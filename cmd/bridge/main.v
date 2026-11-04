// Test-only JSON-lines process. It is never part of the HTTP server.
module main

import better_auth
import better_auth.normalization
import crypto.sha256
import crypto.rand
import encoding.hex
import json
import os
import time
import x.json2

struct Options {
	custom_jwk_store                  bool
	admin_schema                      bool
	admin_default_role                string = 'user'
	organization_schema               bool
	organization_teams                bool
	endpoint_plugins                  []RemoteEndpointPlugin
	jwt_plugin                        bool
	jwt_expiration_json               string
	jwt_options                       better_auth.JWTOptions
	defer_migrations                  bool
	storage                           string = 'sqlite'
	stateless_sessions                bool
	cookie_cache                      better_auth.CookieCacheConfig
	base_url                          string = 'http://localhost:3000'
	base_path                         string = '/api/auth'
	secrets_json                      string
	secret                            string = 'better-auth-test-secret-at-least-32-bytes'
	trusted_origins                   []string
	verification_delivery_enabled     bool
	auto_sign_in_after_verification   bool
	delete_user_enabled               bool
	delete_token_expires_in           i64 = 86400
	change_email_enabled              bool
	update_email_without_verification bool
	require_email_verification        bool
	send_verification_on_sign_up      ?bool
	send_verification_on_sign_in      bool
	auto_sign_in                      bool = true
	email_and_password                bool = true
	min_password_length               int  = 8
	max_password_length               int  = 128
	session_expires_in                i64  = 604800
	session_update_age                i64  = 86400
	session_fresh_age                 i64  = 86400
	defer_session_refresh             bool
	disable_session_refresh           bool
	verification_expires_in           i64 = 3600
	rate_limit_max                    int
	rate_limit_window                 i64 = 60
	max_body_bytes                    int = 65536
	password_reset_expires_in         i64 = 3600
	revoke_sessions_on_password_reset bool
	real_passwords                    bool
	fail_delivery                     bool
	magic_link                        bool
	trust_proxy_origin_headers        bool
	user_fields_json                  string = '{}'
	session_fields_json               string = '{}'
	callback_methods                  []string
	account_fields_json               string = '{}'
	remote_passwords                  bool
	secondary_storage                 bool
	store_session_in_database         bool
	preserve_session_in_database      bool
}

struct RemoteJWKStore {
	methods []string
}

fn (mut store RemoteJWKStore) get_keys(mut context better_auth.EndpointContext) ![]better_auth.Jwk {
	if 'jwt.getJwks' !in store.methods { return context.stored_jwks() }
	encoded := callback_with_context('jwt.getJwks', '{}', mut context)!
	if encoded == 'null' { return []better_auth.Jwk{} }
	return json.decode([]better_auth.Jwk, encoded)
}

fn (mut store RemoteJWKStore) create_key(key better_auth.Jwk, mut context better_auth.EndpointContext) !better_auth.Jwk {
	if 'jwt.createJwk' !in store.methods { return context.store_jwk(key) }
	mut fields := json2.decode[map[string]json2.Any](json.encode(key))!
	fields.delete('id')
	encoded := callback_with_context('jwt.createJwk', json2.Any(fields).json_str(), mut context)!
	return json.decode(better_auth.Jwk, encoded)
}

struct RemoteEndpoint {
	name            string
	path            string
	method          string
	require_session bool
	fresh_session   bool
}

@[heap]
struct RemoteEndpointPlugin {
	name   string
	routes []RemoteEndpoint
}

fn (p RemoteEndpointPlugin) id() string {
	return p.name
}

fn (p RemoteEndpointPlugin) endpoints() []better_auth.Endpoint {
	mut endpoints := []better_auth.Endpoint{}
	for route in p.routes {
		callback_name := 'plugin.' + p.name + '.' + route.name
		endpoints << better_auth.Endpoint{
			path:            route.path
			method:          route.method
			require_session: route.require_session
			fresh_session:   route.fresh_session
			handler:         fn [callback_name] (mut context better_auth.EndpointContext, req better_auth.Request) !better_auth.Response {
				session_json := if current := context.session {
					'{"session":${better_auth.encode_session(current.session)},"user":${better_auth.encode_user(current.user)}}'
				} else {
					'null'
				}
				encoded := callback_with_context(callback_name,
					'{"request":${json.encode(req)},"session":${session_json}}', mut context)!
				return json.decode(better_auth.Response, encoded)
			}
		}
	}
	return endpoints
}

struct Command {
	id             int
	op             string
	now_millis     i64
	now            i64
	options        Options
	request        better_auth.Request
	transactions   bool = true
	direct         bool
	where_json     string = '[]'
	model          string
	password       string
	hash           string
	method         string
	arguments_json string = '[]'
}

struct Reply {
	id           int
	error        ?string
	error_status int
	error_code   string
	response     ?better_auth.Response
	emails       []better_auth.EmailMessage @[skip]
	logs         []better_auth.LogEvent
	records_json string = '[]'
	value_json   string = 'null'
}

struct State {
mut:
	now_millis    i64
	now           i64
	emails        []better_auth.EmailMessage
	fail_delivery bool
	logs          []better_auth.LogEvent
}

// Mirrors upstream's fast test hasher for ASCII fixtures. Never exported by the
// library and never selected by the standalone HTTP example.
struct TestHasher {}

fn (_ TestHasher) hash(password string) !string {
	return '$test$sha256$' + hex.encode(sha256.sum(normalization.nfkc(password).bytes()))
}

fn (h TestHasher) verify(password string, encoded string) !bool {
	expected := h.hash(password) or { return false }
	return expected == encoded
}

fn emit(reply Reply) {
	base := json.encode(reply)
	encoded := reply.emails.map(better_auth.encode_email(it)).join(',')
	println(base[..base.len - 1] + ',"emails":[' + encoded + ']}')
	flush_stdout()
}

struct CallbackReply {
	op           string
	value_json   string
	error        ?string
	callback_id  string
	error_status int
	error_code   string
}

fn callback_error(reply CallbackReply) IError {
	message := reply.error or { 'callback failed' }
	if reply.error_status >= 400 && reply.error_status < 500 { return better_auth.APIError{
			status:  reply.error_status
			code:    reply.error_code
			message: message
		} }
	return error(message)
}

// Synchronous inside V; the TS peer awaits the supplied callback before replying.
// Only one top-level command is in flight, so callback replies cannot be confused
// with another request. This channel is available only to this test executable.
fn callback_rpc(method string, payload string) !string {
	callback_id := hex.encode(rand.bytes(8)!)
	println('{"callback":${json.encode(method)},"callback_id":${json.encode(callback_id)},"payload":${payload}}')
	flush_stdout()
	line := os.get_raw_line()
	if line == '' { return error('callback peer disconnected') }
	reply := json.decode(CallbackReply, line)!
	if reply.op != 'callback-result' { return error('unexpected callback protocol frame') }
	if reply.callback_id != callback_id { return error('callback correlation mismatch') }
	if reply.error != none { return callback_error(reply) }
	return reply.value_json
}

fn callback_with_context(method string, payload string, mut context better_auth.EndpointContext) !string {
	callback_id := hex.encode(rand.bytes(8)!)
	println('{"callback":${json.encode(method)},"callback_id":${json.encode(callback_id)},"context":true,"payload":${payload}}')
	flush_stdout()
	for {
		line := os.get_raw_line()
		if line == '' { return error('callback peer disconnected') }
		frame := json.decode(CallbackReply, line)!
		if frame.op == 'callback-result' {
			if frame.callback_id != callback_id { return error('callback correlation mismatch') }
			if frame.error != none { return callback_error(frame) }
			return frame.value_json
		}
		command := json.decode(Command, line)!
		if command.op == 'internal' {
			value := context.invoke_internal(command.method, command.arguments_json) or {
				emit(Reply{ id: command.id, error: err.msg() })
				continue
			}
			emit(Reply{ id: command.id, value_json: value })
		} else if command.op == 'inspect' {
			if command.model == 'user' {
				users := context.users()!
				emit(Reply{
					id:           command.id
					records_json: '[' + users.map(better_auth.encode_user(it)).join(',') + ']'
				})
			} else if command.model == 'account' {
				emit(Reply{ id: command.id, records_json: json.encode(context.accounts('')!) })
			} else {
				emit(Reply{ id: command.id, error: 'unsupported inspection model' })
			}
		} else {
			emit(Reply{ id: command.id, error: 'unsupported nested operation' })
		}
	}
	return error('callback peer disconnected')
}

struct RemoteSecondaryStorage {}

fn (mut _ RemoteSecondaryStorage) get(key string) !better_auth.Lookup[string] {
	encoded := callback_rpc('secondary.get', json.encode({
		'key': key
	}))!
	if encoded == 'null' { return better_auth.Lookup[string]{} }
	value := json2.decode[json2.Any](encoded)!
	return better_auth.Lookup[string]{
		value: if value is string { value } else { value.json_str() }
	}
}

fn (mut _ RemoteSecondaryStorage) get_and_delete(key string) !better_auth.Lookup[string] {
	encoded := callback_rpc('secondary.getAndDelete', json.encode({
		'key': key
	}))!
	if encoded == 'null' { return better_auth.Lookup[string]{} }
	value := json2.decode[json2.Any](encoded)!
	return better_auth.Lookup[string]{
		value: if value is string { value } else { value.json_str() }
	}
}

fn (mut _ RemoteSecondaryStorage) set(key string, value string, ttl i64) ! {
	callback_rpc('secondary.set',
		'{"key":${json.encode(key)},"value":${json.encode(value)},"ttl":${ttl}}')!
}

fn (mut _ RemoteSecondaryStorage) delete(key string) ! {
	callback_rpc('secondary.delete', json.encode({
		'key': key
	}))!
}

fn (mut _ RemoteSecondaryStorage) increment(key string, ttl i64) !i64 {
	return json2.decode[i64](callback_rpc('secondary.increment',
		'{"key":${json.encode(key)},"ttl":${ttl}}')!)
}

struct RemoteDatabaseHook {
	methods []string
}

fn (h RemoteDatabaseHook) run(mut context better_auth.EndpointContext, event better_auth.DatabaseEvent) !better_auth.HookResult {
	method := 'db.' + event.model + '.' + event.operation + '.' + event.phase
	if method !in h.methods { return better_auth.HookResult{} }
	encoded := callback_with_context(method, event.data_json, mut context)!
	if encoded == 'false' { return better_auth.HookResult{
			cancel: true
		} }
	if encoded == 'null' { return better_auth.HookResult{} }
	value := json2.decode[map[string]json2.Any](encoded)!
	if data := value['data'] { return better_auth.HookResult{
			data_json: data.json_str()
		} }
	return better_auth.HookResult{}
}

struct RemoteHasher {
	fallback better_auth.PasswordHasher
}

fn (h RemoteHasher) hash(password string) !string {
	encoded := callback_rpc('password.hash', json.encode(password))!
	if encoded == 'null' { return h.fallback.hash(password) }
	return json2.decode[string](encoded)
}

fn (h RemoteHasher) verify(password string, hash string) !bool {
	encoded := callback_rpc('password.verify', json.encode({
		'password': password
		'hash':     hash
	}))!
	if encoded == 'null' { return h.fallback.verify(password, hash) }
	return json2.decode[bool](encoded)
}

fn expiration_command() ! {
	fields := json2.decode[map[string]json2.Any](os.get_raw_line())!
	value := fields['value'] or { return error('missing expiration') }
	kind := fields['kind'] or { return error('missing expiration type') }
	iat := (fields['iat'] or { return error('missing issue time') }).i64()
	expiration := if kind.str() == 'date' {
		better_auth.JWTExpiration(time.unix_milli(value.i64()))
	} else if value is string {
		better_auth.JWTExpiration(value)
	} else {
		better_auth.JWTExpiration(value.f64())
	}
	println(json.encode(better_auth.jwt_expiration(expiration, iat)!))
}

fn main() {
	if os.args.len == 2 && os.args[1] == '--crypto' {
		crypto_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--jwt-expiration' {
		expiration_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	first := os.get_raw_line()
	if first == '' { return }
	init := json.decode(Command, first) or {
		emit(Reply{ error: 'invalid initialization' })
		return
	}
	if init.op != 'init' {
		emit(Reply{ id: init.id, error: 'first command must be init' })
		return
	}
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
	user_fields := json2.decode[map[string]better_auth.AdditionalField](opts.user_fields_json) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	session_fields := json2.decode[map[string]better_auth.AdditionalField](opts.session_fields_json) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	account_fields := json.decode(map[string]string, opts.account_fields_json) or {
		emit(Reply{ id: init.id, error: err.msg() })
		return
	}
	mut storage := better_auth.Storage(better_auth.open_memory())
	if opts.storage == 'sqlite' {
		mut sqlite_storage := better_auth.open_sqlite_with_options(':memory:', better_auth.SQLiteOptions{
			account_fields: account_fields
		}) or {
			emit(Reply{ id: init.id, error: err.msg() })
			return
		}
		if !opts.defer_migrations {
			sqlite_storage.migrate() or {
				emit(Reply{ id: init.id, error: err.msg() })
				return
			}
		}
		storage = sqlite_storage
	} else if opts.storage != 'memory' {
		emit(Reply{ id: init.id, error: 'unsupported storage' })
		return
	}
	mut plugins := [better_auth.Plugin(better_auth.BearerPlugin{})]
	if opts.admin_schema { plugins << better_auth.AdminSchemaPlugin{
			default_role: opts.admin_default_role
		} }
	if opts.organization_schema { plugins << better_auth.OrganizationSchemaPlugin{
			teams_enabled: opts.organization_teams
		} }
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
			value := json2.decode[json2.Any](opts.jwt_expiration_json) or {
				emit(Reply{ id: init.id, error: err.msg() })
				return
			}
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
	if opts.magic_link { plugins << better_auth.MagicLinkPlugin{} }
	mut secondary := better_auth.SecondaryStorage(better_auth.NoSecondaryStorage{})
	if opts.secondary_storage { secondary = RemoteSecondaryStorage{} }
	mut secrets := ?[]better_auth.SecretEntry(none)
	if opts.secrets_json != '' {
		secrets = better_auth.parse_secret_entries(opts.secrets_json) or {
			emit(Reply{ id: init.id, error: err.msg() })
			return
		}
	}
	defaults := better_auth.Config{}
	mut auth := better_auth.new(better_auth.Config{
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
		base_url:                          opts.base_url
		base_path:                         opts.base_path
		secret:                            opts.secret
		secrets:                           secrets
		trusted_origins:                   opts.trusted_origins
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
	emit(Reply{ id: init.id })
	for {
		line := os.get_raw_line()
		if line == '' { break
		 }
		command := json.decode(Command, line) or {
			emit(Reply{ error: 'invalid command' })
			continue
		}
		auth.set_adapter_transactions(command.transactions) or {
			emit(Reply{ id: command.id, error: err.msg() })
			continue
		}
		state.now = command.now
		state.now_millis = command.now_millis
		match command.op {
			'migrate' {
				if mut storage is better_auth.SQLiteStorage {
					storage.migrate() or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
				} else {
					emit(Reply{ id: command.id, error: 'explicit migrations require native SQLite' })
					continue
				}
				emit(Reply{ id: command.id })
			}
			'transaction' {
				value := auth.with_internal(fn [command] (mut context better_auth.EndpointContext) !string {
					return callback_with_context(command.method, '{}', mut context)
				}) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, value_json: value })
			}
			'internal' {
				log_start := state.logs.len
				value := auth.with_internal(fn [command] (mut context better_auth.EndpointContext) !string {
					return context.invoke_internal(command.method, command.arguments_json)
				}) or {
					emit(Reply{
						id:           command.id
						error:        err.msg()
						error_status: if err is better_auth.APIError { err.status } else { 500 }
						error_code:   if err is better_auth.APIError {
							err.code
						} else {
							'INTERNAL_SERVER_ERROR'
						}
					})
					continue
				}
				emit(Reply{ id: command.id, value_json: value, logs: state.logs[log_start..].clone() })
			}
			'configured-password-hash' {
				value := fallback_hasher.hash(command.password) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'configured-password-verify' {
				value := fallback_hasher.verify(command.password, command.hash) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'password-hash' {
				value := better_auth.ScryptHasher{}.hash(command.password) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'password-verify' {
				value := better_auth.ScryptHasher{}.verify(command.password, command.hash) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'request' {
				start := state.emails.len
				log_start := state.logs.len
				response := if command.direct {
					auth.call(command.request)
				} else {
					auth.handle(command.request)
				}
				emit(Reply{
					id:       command.id
					response: response
					emails:   state.emails[start..].clone()
					logs:     state.logs[log_start..].clone()
				})
			}
			'inspect' {
				if command.model == 'verification' {
					records := storage.verifications() or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					encoded := filter_inspection(json.encode(records), command.where_json) or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					emit(Reply{ id: command.id, records_json: encoded })
					continue
				}
				if command.model == 'account' {
					records := storage.accounts('') or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					encoded := filter_inspection(json.encode(records), command.where_json) or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					emit(Reply{ id: command.id, records_json: encoded })
					continue
				} else if command.model != 'user' {
					emit(Reply{ id: command.id, error: 'unsupported inspection model' })
					continue
				}
				records := storage.users() or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				encoded := filter_inspection('[' +
					records.map(better_auth.encode_user(it)).join(',') + ']', command.where_json) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, records_json: encoded })
			}
			'close' {
				emit(Reply{ id: command.id })
				break
			}
			else {
				emit(Reply{ id: command.id, error: 'unsupported command' })
			}
		}
	}
}

fn filter_inspection(encoded string, where string) !string {
	conditions := json2.decode[[]json2.Any](where)!
	records := json2.decode[[]json2.Any](encoded)!
	mut selected := []json2.Any{}
	for record in records {
		mut matches := true
		for condition in conditions {
			filter := condition.as_map()
			for key, _ in filter {
				if key !in ['field', 'value', 'operator'] {
					return error('unsupported inspection predicate')
				}
			}
			if (filter['operator'] or { json2.Any('eq') }).str() != 'eq' {
				return error('only equality inspection predicates are implemented')
			}
			field := (filter['field'] or { return error('missing predicate field') }).str()
			actual := record.as_map()[field] or { json2.Any(json2.Null{}) }
			expected := filter['value'] or { return error('missing predicate value') }
			if actual.json_str() != expected.json_str() {
				matches = false
				break
			}
		}
		if matches { selected << record }
	}
	return json2.Any(selected).json_str()
}
