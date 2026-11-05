module main

import better_auth
import json
import x.json2

fn serve_bridge(init Command) {
	mut state := &State{
		now:           init.now
		now_millis:    init.now_millis
		fail_delivery: init.options.fail_delivery
	}
	opts := init.options
	mut hasher := better_auth.PasswordHasher(TestHasher{})
	if opts.real_passwords { hasher = better_auth.ScryptHasher{} }
	fallback_hasher := hasher
	if opts.remote_passwords { hasher = RemoteHasher{
			fallback: fallback_hasher
		} }
	user_fields := field_schema(opts.user_fields_json, 'user', opts.field_callbacks) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	session_fields := field_schema(opts.session_fields_json, 'session', opts.field_callbacks) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	account_fields := json.decode(map[string]string, opts.account_fields_json) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	mut storage := open_bridge_storage(opts, account_fields) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	plugins := bridge_plugins(opts) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	mut secondary := better_auth.SecondaryStorage(better_auth.NoSecondaryStorage{})
	if opts.secondary_storage { secondary = RemoteSecondaryStorage{} }
	if tcp := opts.redis_tcp { secondary = better_auth.redis_storage(better_auth.RedisTCPClient{
			options: tcp
		}, better_auth.RedisStorageOptions{
			key_prefix: opts.redis_key_prefix
		}) }
	mut secrets := ?[]better_auth.SecretEntry(none)
	if opts.secrets_json != '' {
		secrets = better_auth.parse_secret_entries(opts.secrets_json) or {
			emit(Reply{ id: init.id, error: err.msg() })
			return
		}
	}
	mut logout_providers := []better_auth.OAuthLogoutProvider{}
	for provider in opts.logout_providers {
		logout_providers << better_auth.OAuthLogoutProvider(provider)
	}
	defaults := better_auth.Config{}
	mut providers := []better_auth.OAuthProvider{}
	if google := opts.google_provider {
		providers << better_auth.GoogleProvider{
			...google
			map_profile:  if opts.google_profile_callback {
				fn (profile string) !string {
					return callback_rpc('google.map', profile)
				}
			} else {
				google.map_profile
			}
			transport:    RemoteOAuthTransport{}
			clock_millis: fn [state] () i64 {
				return state.now_millis
			}
		}
	}
	mut generic := []better_auth.GenericOAuthConfig{}
	for input in opts.generic_oauth {
		provider_id := input.provider_id
		methods := opts.generic_callbacks[provider_id] or { []string{} }
		mut settings := better_auth.GenericOAuthConfig{
			...input
			transport:    RemoteOAuthTransport{}
			clock_millis: fn [state] () i64 {
				return state.now_millis
			}
		}
		if 'token' in methods { settings = better_auth.GenericOAuthConfig{
				...settings
				get_token: fn [provider_id] (code string, verifier string, redirect_uri string) !better_auth.OAuthTokens {
					encoded := callback_rpc('generic.token.' + provider_id, json.encode({
						'code':         code
						'codeVerifier': verifier
						'redirectURI':  redirect_uri
					}))!return json.decode(better_auth.OAuthTokens, encoded)}
			} }
		if 'map' in methods { settings = better_auth.GenericOAuthConfig{
				...settings
				map_profile: fn [provider_id] (profile string) !string {
					return callback_rpc('generic.map.' + provider_id, profile)}
			} }
		generic << settings
	}
	mut adapter_models := map[string]better_auth.AdapterModel{}
	for model, encoded in opts.adapter_model_fields_json {
		adapter_models[model] = better_auth.AdapterModel{
			name:   opts.adapter_model_names[model] or { model }
			fields: field_schema(encoded, model, opts.field_callbacks) or {
				emit(Reply{ id: init.id, error: err.msg() })
				return
			}
		}
	}
	mut auth := better_auth.new(better_auth.Config{
		adapter_models:               adapter_models
		app_name:                     opts.app_name
		id_strategy:                  opts.id_strategy
		generate_id:                  if opts.custom_id_generator {
			fn (model string) !string {
				return json2.decode[string](callback_rpc('id.generate', json.encode({
					'model': model
				}))!)
			}
		} else {
			defaults.generate_id
		}
		generic_oauth:                generic
		account_linking_enabled:      opts.account_linking_enabled
		update_user_info_on_link:     opts.update_user_info_on_link
		require_local_email_verified: opts.require_local_email_verified
		disable_implicit_linking:     opts.disable_implicit_linking
		trusted_linking_providers:    opts.trusted_linking_providers
		disable_email_sign_up:        opts.disable_email_sign_up

		verification:                      better_auth.VerificationOptions{
			...opts.verification_options
			hash_identifier: fn [opts] (identifier string) !string {
				if !opts.verification_hash_callback {
					return error('verification identifier hash callback is not configured')
				}
				return json2.decode[string](callback_rpc('verification.hash',
					json.encode(identifier))!)
			}
		}
		stateless_sessions:                opts.stateless_sessions
		cookie_cache:                      better_auth.CookieCacheConfig{
			...opts.cookie_cache
			version_for: fn [opts] (session better_auth.Session, user better_auth.User) !string {
				if 'cache.version' !in opts.callback_methods { return opts.cookie_cache.version }
				encoded := callback_rpc('cache.version',
					'{"session":${better_auth.encode_session(session)},"user":${better_auth.encode_user(user)}}')!
				return json2.decode[json2.Any](encoded)!.str()
			}
		}
		secondary_storage:                 secondary
		store_session_in_database:         opts.store_session_in_database
		preserve_session_in_database:      opts.preserve_session_in_database
		database_hooks:                    [
			better_auth.DatabaseHook(RemoteDatabaseHook{
				methods: opts.callback_methods
			}),
		]
		internal_interceptor:              fn (mut context better_auth.EndpointContext, operation better_auth.InternalOperation) !better_auth.Interception {
			value := callback_with_context('internal.' + operation.name, operation.arguments_json, mut
				context)!
			return better_auth.Interception{
				handled:    true
				value_json: value
			}
		}
		before_commit:                     fn (mut context better_auth.EndpointContext) ! {
			callback_with_context('transaction.beforeCommit', '{}', mut context)!
		}
		logout_providers:                  logout_providers
		social_providers:                  providers
		store_account_cookie:              opts.store_account_cookie
		account_cookie_bind_user:          opts.account_cookie_bind_user
		encrypt_oauth_tokens:              opts.encrypt_oauth_tokens
		base_url:                          opts.base_url
		base_path:                         opts.base_path
		secret:                            opts.secret
		secrets:                           secrets
		disable_csrf_check:                opts.disable_csrf_check
		disable_origin_check:              opts.disable_origin_check
		skip_origin_check_paths:           opts.skip_origin_check_paths
		cookie_names:                      opts.cookie_names
		default_cookie_attributes:         json2.decode[map[string]json2.Any](opts.default_cookie_attributes_json) or {
			panic(err)
		}
		cookie_attributes:                 bridge_cookie_attributes(opts.cookie_attributes_json) or {
			panic(err)
		}
		cookie_prefix:                     opts.cookie_prefix
		secure_cookies:                    opts.secure_cookies
		cross_subdomain_cookies:           opts.cross_subdomain_cookies
		cookie_domain:                     opts.cookie_domain
		trusted_origins:                   opts.trusted_origins
		trusted_origins_for:               fn [opts] (_ better_auth.RequestContext) ![]string {
			if 'trustedOrigins' !in opts.callback_methods { return []string{} }
			return better_auth.parse_trusted_origins(callback_rpc('trustedOrigins', '{}')!)
		}
		verification_delivery_enabled:     opts.verification_delivery_enabled
		auto_sign_in_after_verification:   opts.auto_sign_in_after_verification
		delete_user_enabled:               opts.delete_user_enabled
		delete_token_expires_in:           opts.delete_token_expires_in
		send_delete_verification:          if 'email.delete-account' in opts.callback_methods {
			fn (message better_auth.EmailMessage) ! {
				callback_rpc('email.delete-account', better_auth.encode_email(message))!
			}
		} else {
			defaults.send_delete_verification
		}
		before_delete:                     fn [opts] (user better_auth.User, _ better_auth.RequestContext) ! {
			if 'user.delete.before' in opts.callback_methods {
				callback_rpc('user.delete.before', better_auth.encode_user(user))!
			}
		}
		after_delete:                      fn [opts] (user better_auth.User, _ better_auth.RequestContext) ! {
			if 'user.delete.after' in opts.callback_methods {
				callback_rpc('user.delete.after', better_auth.encode_user(user))!
			}
		}
		change_email_enabled:              opts.change_email_enabled
		update_email_without_verification: opts.update_email_without_verification
		send_change_email_confirmation:    if 'email.change-confirmation' in opts.callback_methods {
			fn (message better_auth.EmailMessage) ! {
				callback_rpc('email.change-confirmation', better_auth.encode_email(message))!
			}
		} else {
			defaults.send_change_email_confirmation
		}
		before_email_verification:         fn [opts] (user better_auth.User, _ better_auth.RequestContext) ! {
			if 'email.verify.before' in opts.callback_methods {
				callback_rpc('email.verify.before', better_auth.encode_user(user))!
			}
		}
		after_email_verification:          fn [opts] (user better_auth.User, _ better_auth.RequestContext) ! {
			if 'email.verify.after' in opts.callback_methods {
				callback_rpc('email.verify.after', better_auth.encode_user(user))!
			}
		}
		require_email_verification:        opts.require_email_verification
		send_verification_on_sign_up:      opts.send_verification_on_sign_up
		send_verification_on_sign_in:      opts.send_verification_on_sign_in
		auto_sign_in:                      opts.auto_sign_in
		email_and_password:                opts.email_and_password
		min_password_length:               opts.min_password_length
		max_password_length:               opts.max_password_length
		session_expires_in:                opts.session_expires_in
		session_update_age:                opts.session_update_age
		session_fresh_age:                 opts.session_fresh_age
		defer_session_refresh:             opts.defer_session_refresh
		disable_session_refresh:           opts.disable_session_refresh
		verification_expires_in:           opts.verification_expires_in
		rate_limit_max:                    opts.rate_limit_max
		rate_limit_window:                 opts.rate_limit_window
		rate_limit_storage:                opts.rate_limit_storage
		rate_limit_rules:                  opts.rate_limit_rules
		max_body_bytes:                    opts.max_body_bytes
		password_hasher:                   hasher
		password_reset_expires_in:         opts.password_reset_expires_in
		revoke_sessions_on_password_reset: opts.revoke_sessions_on_password_reset
		on_password_reset:                 fn [opts] (user better_auth.User) ! {
			if 'password.reset' in opts.callback_methods {
				callback_rpc('password.reset', '{"user":' + better_auth.encode_user(user) + '}')!
			}
		}
		trust_proxy_ip_headers:            true
		trust_proxy_origin_headers:        opts.trust_proxy_origin_headers
		plugins:                           plugins
		validate_user_info:                fn [opts] (user better_auth.User, source better_auth.UserInfoSource) !better_auth.ValidationDecision {
			if 'user.validate' !in opts.callback_methods { return better_auth.ValidationDecision{} }
			encoded := callback_rpc('user.validate', '{"user":' + better_auth.encode_user(user) +
				',"source":' + better_auth.encode_user_source(source) + '}')!
			if encoded == 'null' { return better_auth.ValidationDecision{} }
			return json.decode(better_auth.ValidationDecision, encoded)
		}
		on_existing_user_sign_up:          fn [opts] (user better_auth.User) ! {
			if 'user.existing' in opts.callback_methods {
				callback_rpc('user.existing', '{"user":' + better_auth.encode_user(user) + '}')!
			}
		}
		custom_synthetic_user:             fn [opts] (input better_auth.SyntheticUserInput) !better_auth.User {
			if 'user.synthetic' !in opts.callback_methods {
				return better_auth.User{
					...input.core_fields
					id:                input.id
					additional_fields: input.additional_fields
				}
			}
			encoded := callback_rpc('user.synthetic',
				'{"coreFields":${better_auth.encode_user(input.core_fields)},"additionalFields":${json2.Any(input.additional_fields).json_str()},"id":${json.encode(input.id)}}')!
			return better_auth.decode_user(encoded)
		}
		user_fields:                       user_fields
		session_fields:                    session_fields
		log:                               fn [mut state] (level string, message string) {
			state.logs << better_auth.LogEvent{
				level:   level
				message: message
			}
		}
		clock_millis:                      fn [state] () i64 {
			return state.now_millis
		}
		clock:                             fn [state] () i64 {
			return state.now
		}
		send_email:                        fn [mut state, opts] (message better_auth.EmailMessage) ! {
			if state.fail_delivery { return error('delivery failed') }
			method := 'email.' + message.kind
			if method in opts.callback_methods {
				callback_rpc(method, better_auth.encode_email(message))!
			}
			state.emails << message
		}
	}, storage) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	defer { auth.close() or {} }
	if opts.storage in ['postgres', 'sqlite', 'mongo'] && !opts.defer_migrations {
		auth.migrate_storage() or {
			emit(Reply{ id: init.id, error: err.msg() })
			return
		}
	}
	emit(Reply{ id: init.id })
	serve_commands(mut auth, mut state, mut storage, fallback_hasher)
}
