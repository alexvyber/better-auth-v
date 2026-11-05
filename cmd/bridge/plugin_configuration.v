module main

import better_auth
import json
import x.json2

fn bridge_plugins(opts Options) ![]better_auth.Plugin {
	mut plugins := [better_auth.Plugin(better_auth.BearerPlugin{})]
	if given := opts.two_factor {
		mut settings := given
		mut otp := given.otp_options
		mut backup := given.backup_code_options
		if 'send' in opts.two_factor_callbacks { otp = better_auth.TwoFactorOTPOptions{
				...otp
				send: fn (mut context better_auth.EndpointContext, user better_auth.User, code string) ! {
					otp_callback('twoFactor.send', '{"user":' + better_auth.encode_user(user) + ',"otp":' + json.encode(code) + '}', mut context)!}
			} }
		if 'hash' in opts.two_factor_callbacks { otp = better_auth.TwoFactorOTPOptions{
				...otp
				hash: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('twoFactor.hash', json.encode(value), mut context)!)}
			} }
		if 'encrypt' in opts.two_factor_callbacks { otp = better_auth.TwoFactorOTPOptions{
				...otp
				encrypt: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('twoFactor.encrypt', json.encode(value), mut context)!)}
			} }
		if 'decrypt' in opts.two_factor_callbacks { otp = better_auth.TwoFactorOTPOptions{
				...otp
				decrypt: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('twoFactor.decrypt', json.encode(value), mut context)!)}
			} }
		if 'backupEncrypt' in opts.two_factor_callbacks { backup = better_auth.BackupCodeOptions{
				...backup
				encrypt: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('twoFactor.backupEncrypt', json.encode(value), mut context)!)}
			} }
		if 'backupDecrypt' in opts.two_factor_callbacks { backup = better_auth.BackupCodeOptions{
				...backup
				decrypt: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('twoFactor.backupDecrypt', json.encode(value), mut context)!)}
			} }
		if 'backupGenerate' in opts.two_factor_callbacks { backup = better_auth.BackupCodeOptions{
				...backup
				generate: fn (mut context better_auth.EndpointContext) ![]string {
					return json.decode([]string, otp_callback('twoFactor.backupGenerate', 'null', mut context)!)}
			} }
		settings = better_auth.TwoFactorOptions{
			...settings
			otp_options:         otp
			backup_code_options: backup
		}
		plugins << better_auth.TwoFactorPlugin{
			options: settings
		}
	}

	if given := opts.admin {
		mut settings := given
		if opts.admin_banned_callback { settings = better_auth.AdminOptions{
				...settings
				banned_message: fn (mut context better_auth.EndpointContext, user better_auth.User) !string {
					return json2.decode[string](otp_callback('admin.bannedMessage', better_auth.encode_user(user), mut context)!)!}
			} }
		plugins << better_auth.AdminPlugin{
			options: settings
		}
	} else if opts.admin_schema {
		plugins << better_auth.AdminSchemaPlugin{
			default_role: opts.admin_default_role
		}
	}
	if given := opts.open_api { plugins << better_auth.OpenAPIPlugin{
			options: given
		} }
	if given := opts.organization {
		mut fields := map[string]map[string]better_auth.AdditionalField{}
		for model, encoded in opts.organization_fields_json {
			fields[model] = field_schema(encoded, model, opts.field_callbacks) or { return err }
		}
		mut settings := better_auth.OrganizationOptions{
			...given
			additional_fields: fields
		}
		if opts.organization_hooks.len > 0 {
			names := opts.organization_hooks.clone()
			settings = better_auth.OrganizationOptions{
				...settings
				hook: fn [names] (mut context better_auth.EndpointContext, name string, data string) !better_auth.Lookup[string] {
					if name !in names { return better_auth.Lookup[string]{} }
					result := json2.decode[json2.Any](otp_callback('organization.' + name, data, mut
						context)!)!
					if result is map[string]json2.Any {
						if value := result['data'] { return better_auth.Lookup[string]{
								value: value.json_str()
							} }
					}
					return better_auth.Lookup[string]{}
				}
			}
		}
		if opts.organization_invitation_limit {
			settings = better_auth.OrganizationOptions{
				...settings
				invitation_limit_callback: fn (mut context better_auth.EndpointContext, data string) !int {
					return json2.decode[int](otp_callback('organization.invitationLimit', data, mut
						context)!)!
				}
			}
		}
		if opts.organization_invitation_email {
			settings = better_auth.OrganizationOptions{
				...settings
				send_invitation_email: fn (mut context better_auth.EndpointContext, data string) ! {
					otp_callback('organization.sendInvitationEmail', data, mut context)!
				}
			}
		}
		if opts.organization_creation_callback { settings = better_auth.OrganizationOptions{
				...settings
				allow_creation: fn (mut context better_auth.EndpointContext, user better_auth.User) !bool {
					return json2.decode[bool](otp_callback('organization.allowCreate', better_auth.encode_user(user), mut context)!)!}
			} }
		plugins << better_auth.OrganizationPlugin{
			options: settings
		}
	} else if opts.organization_schema {
		plugins << better_auth.OrganizationSchemaPlugin{
			teams_enabled: opts.organization_teams
		}
	}
	for plugin in opts.endpoint_plugins {
		plugins << better_auth.Plugin(plugin)
	}
	if opts.jwt_plugin {
		mut key_store := better_auth.JWKStore(better_auth.NoJWKStore{})
		if opts.custom_jwk_store { key_store = RemoteJWKStore{
				methods: opts.callback_methods
			} }
		mut jwt_options := opts.jwt_options
		if opts.jwt_expiration_json != '' {
			value := json2.decode[json2.Any](opts.jwt_expiration_json) or { return err }
			expiration := if value is string {
				better_auth.JWTExpiration(value)
			} else {
				better_auth.JWTExpiration(value.f64())
			}
			jwt_options = better_auth.JWTOptions{
				...jwt_options
				expiration_time: expiration
			}
		}
		if 'jwt.definePayload' in opts.callback_methods {
			jwt_options = better_auth.JWTOptions{
				...jwt_options
				define_payload: fn (current better_auth.SessionResult) !string {
					return callback_rpc('jwt.definePayload', '{"user":' +
						better_auth.encode_user(current.user) + ',"session":' +
						better_auth.encode_session(current.session) + '}')
				}
			}
		}
		if 'jwt.getSubject' in opts.callback_methods {
			jwt_options = better_auth.JWTOptions{
				...jwt_options
				get_subject: fn (current better_auth.SessionResult) !better_auth.Lookup[string] {
					encoded := callback_rpc('jwt.getSubject', '{"user":' +
						better_auth.encode_user(current.user) + ',"session":' +
						better_auth.encode_session(current.session) + '}')!
					if encoded == 'null' { return better_auth.Lookup[string]{} }
					return better_auth.Lookup[string]{
						value: json2.decode[string](encoded)!
					}
				}
			}
		}
		if 'jwt.sign' in opts.callback_methods {
			jwt_options = better_auth.JWTOptions{
				...jwt_options
				sign_with: fn (payload string, header string, signing better_auth.JWTSigningConfig) !string {
					return json2.decode[string](callback_rpc('jwt.sign', '{"payload":' + payload +
						',"header":' + header + ',"config":' + json.encode(signing) + '}')!)
				}
			}
		}
		plugins << better_auth.JWTPlugin{
			options: better_auth.JWTOptions{
				...jwt_options
				key_store: key_store
			}
		}
	}
	if given := opts.anonymous {
		mut settings := given
		if 'name' in opts.anonymous_callbacks { settings = better_auth.AnonymousOptions{
				...settings
				generate_name: fn (mut context better_auth.EndpointContext) !string {
					return json2.decode[string](otp_callback('anonymous.name', 'null', mut context)!)}
			} }
		if 'email' in opts.anonymous_callbacks { settings = better_auth.AnonymousOptions{
				...settings
				generate_email: fn () !string {
					return json2.decode[string](callback_rpc('anonymous.email', 'null')!)}
			} }
		if 'link' in opts.anonymous_callbacks { settings = better_auth.AnonymousOptions{
				...settings
				on_link_account: fn (mut context better_auth.EndpointContext, previous better_auth.SessionResult, next better_auth.SessionResult) ! {
					data := '{"anonymousUser":{"user":${better_auth.encode_user(previous.user)},"session":${better_auth.encode_session(previous.session)}},"newUser":{"user":${better_auth.encode_user(next.user)},"session":${better_auth.encode_session(next.session)}}}'otp_callback('anonymous.link', data, mut context)!}
			} }
		plugins << better_auth.AnonymousPlugin{
			options: settings
		}
	}
	if given := opts.email_otp {
		mut settings := given
		if 'generate' in opts.email_otp_callbacks {
			settings = better_auth.EmailOTPOptions{
				...settings
				generate_otp: fn (mut context better_auth.EndpointContext, data better_auth.EmailOTPMessage) !string {
					encoded := otp_callback('otp.generate',
						'{"email":${json.encode(data.email)},"type":${json.encode(data.kind)}}', mut
						context)!
					result := json2.decode[json2.Any](encoded)!
					return if result is json2.Null { '' } else { result.str() }
				}
			}
		}
		if 'send' in opts.email_otp_callbacks { settings = better_auth.EmailOTPOptions{
				...settings
				send_otp: fn (mut context better_auth.EndpointContext, data better_auth.EmailOTPMessage) ! {
					otp_callback('otp.send', json.encode(data), mut context)!}
			} }
		if 'hash' in opts.email_otp_callbacks { settings = better_auth.EmailOTPOptions{
				...settings
				hash_otp: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('otp.hash', json.encode(value), mut context)!)}
			} }
		if 'encrypt' in opts.email_otp_callbacks { settings = better_auth.EmailOTPOptions{
				...settings
				encrypt_otp: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('otp.encrypt', json.encode(value), mut context)!)}
			} }
		if 'decrypt' in opts.email_otp_callbacks { settings = better_auth.EmailOTPOptions{
				...settings
				decrypt_otp: fn (mut context better_auth.EndpointContext, value string) !string {
					return json2.decode[string](otp_callback('otp.decrypt', json.encode(value), mut context)!)}
			} }
		plugins << better_auth.EmailOTPPlugin{
			options: settings
		}
	}
	if given := opts.one_time_token {
		mut settings := given
		if opts.ott_generate_callback {
			settings = better_auth.OneTimeTokenOptions{
				...settings
				generate_token: fn (mut context better_auth.EndpointContext, session better_auth.SessionResult) !string {
					return json2.decode[string](callback_with_context('ott.generate',
						'{"session":${better_auth.encode_session(session.session)},"user":${better_auth.encode_user(session.user)}}', mut
						context)!)
				}
			}
		}
		if opts.ott_hash_callback {
			settings = better_auth.OneTimeTokenOptions{
				...settings
				hash_token: fn (token string) !string {
					return json2.decode[string](callback_rpc('ott.hash', json.encode(token))!)
				}
			}
		}
		plugins << better_auth.OneTimeTokenPlugin{
			options: settings
		}
	}
	if opts.magic_link { plugins << better_auth.MagicLinkPlugin{} }
	return plugins
}
