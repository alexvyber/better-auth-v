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
	postgres                          ?better_auth.PostgresOptions
	mongo                             ?better_auth.MongoOptions
	id_strategy                       string = 'random'
	custom_id_generator               bool
	redis_tcp                         ?better_auth.RedisTCPOptions
	redis_key_prefix                  string = 'better-auth:'
	generic_oauth                     []better_auth.GenericOAuthConfig
	generic_callbacks                 map[string][]string
	account_linking_enabled           bool
	update_user_info_on_link          bool
	require_local_email_verified      bool = true
	disable_implicit_linking          bool
	trusted_linking_providers         []string
	disable_email_sign_up             bool
	app_name                          string = 'Better Auth'
	two_factor_callbacks              []string
	two_factor                        ?better_auth.TwoFactorOptions
	anonymous                         ?better_auth.AnonymousOptions
	anonymous_callbacks               []string
	email_otp                         ?better_auth.EmailOTPOptions
	email_otp_callbacks               []string
	verification_options              better_auth.VerificationOptions
	verification_hash_callback        bool
	one_time_token                    ?better_auth.OneTimeTokenOptions
	ott_generate_callback             bool
	ott_hash_callback                 bool
	custom_jwk_store                  bool
	admin_schema                      bool
	admin                             ?better_auth.AdminOptions
	admin_banned_callback             bool
	admin_default_role                string = 'user'
	organization_schema               bool
	organization_teams                bool
	logout_providers                  []better_auth.GenericOAuthLogoutProvider
	google_profile_callback           bool
	google_provider                   ?better_auth.GoogleProvider
	store_account_cookie              bool
	account_cookie_bind_user          ?bool
	encrypt_oauth_tokens              bool
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
	disable_csrf_check                ?bool
	disable_origin_check              bool
	skip_origin_check_paths           []string
	cookie_names                      map[string]string
	default_cookie_attributes_json    string = '{}'
	cookie_attributes_json            string = '{}'
	cookie_prefix                     string = 'better-auth'
	secure_cookies                    ?bool
	cross_subdomain_cookies           bool
	cookie_domain                     string
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
	rate_limit_window                 i64    = 60
	rate_limit_storage                string = 'memory'
	rate_limit_rules                  map[string]better_auth.RateLimitRule
	max_body_bytes                    int
	password_reset_expires_in         i64 = 3600
	revoke_sessions_on_password_reset bool
	real_passwords                    bool
	fail_delivery                     bool
	magic_link                        bool
	trust_proxy_origin_headers        bool
	field_callbacks                   []string
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
	prefix  string = 'jwt'
	methods []string
}

fn (mut store RemoteJWKStore) get_keys(mut context better_auth.EndpointContext) ![]better_auth.Jwk {
	if store.prefix + '.getJwks' !in store.methods { return context.stored_jwks() }
	encoded := callback_with_context(store.prefix + '.getJwks', '{}', mut context)!
	if encoded == 'null' { return []better_auth.Jwk{} }
	return json.decode([]better_auth.Jwk, encoded)
}

fn (mut store RemoteJWKStore) create_key(key better_auth.Jwk, mut context better_auth.EndpointContext) !better_auth.Jwk {
	if store.prefix + '.createJwk' !in store.methods { return context.store_jwk(key) }
	mut fields := json2.decode[map[string]json2.Any](json.encode(key))!
	fields.delete('id')
	encoded := callback_with_context(store.prefix + '.createJwk', json2.Any(fields).json_str(), mut
		context)!
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
	id                   int
	op                   string
	now_millis           i64
	now                  i64
	options              Options
	jwt_options_json     string
	jwt_expiration_json  string
	jwt_callback_prefix  string
	jwt_callback_methods []string
	prepared_json        string
	hook_request         ?better_auth.Request
	hook_response        ?better_auth.Response
	request              better_auth.Request
	transactions         bool = true
	direct               bool
	where_json           string = '[]'
	model                string
	password             string
	hash                 string
	method               string
	arguments_json       string = '[]'
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

fn invoke_bridge_internal(mut context better_auth.EndpointContext, command Command) !string {
	if command.jwt_options_json == ''
		|| command.method !in ['signJWTWith', 'verifyJWTWithOptions', 'jwkLookupWithOptions'] {
		return context.invoke_internal(command.method, command.arguments_json)
	}
	mut options := json.decode(better_auth.JWTOptions, command.jwt_options_json)!
	if command.jwt_expiration_json != '' {
		value := json2.decode[json2.Any](command.jwt_expiration_json)!
		expiration := if value is string {
			better_auth.JWTExpiration(value)
		} else if value is map[string]json2.Any {
			millis := value['$jwtDateMillis'] or { return error('invalid JWT expiration Date') }
			if millis !is i64 && millis !is int && millis !is f64 {
				return error('invalid JWT expiration Date')
			}
			better_auth.JWTExpiration(time.unix_milli(millis.i64()))
		} else {
			if value !is i64 && value !is int && value !is f64 {
				return error('invalid JWT expiration')
			}
			better_auth.JWTExpiration(value.f64())
		}
		options = better_auth.JWTOptions{
			...options
			expiration_time: expiration
		}
	}
	if command.jwt_callback_prefix + '.getJwks' in command.jwt_callback_methods
		|| command.jwt_callback_prefix + '.createJwk' in command.jwt_callback_methods {
		options = better_auth.JWTOptions{
			...options
			key_store: RemoteJWKStore{
				prefix:  command.jwt_callback_prefix
				methods: command.jwt_callback_methods
			}
		}
	}
	method := command.jwt_callback_prefix + '.sign'
	if method in command.jwt_callback_methods {
		options = better_auth.JWTOptions{
			...options
			sign_with: fn [method] (payload string, header string, config better_auth.JWTSigningConfig) !string {
				return json2.decode[string](callback_rpc(method, '{"payload":' + payload +
					',"header":' + header + ',"config":' + json.encode(config) + '}')!)
			}
		}
	}
	args := json2.decode[[]json2.Any](command.arguments_json)!
	if command.method == 'jwkLookupWithOptions' {
		if args.len != 2 { return error('jwkLookupWithOptions requires method and value') }
		return context.jwk_lookup_with_options(args[0].str(), args[1].str(), options)
	}
	if command.method == 'verifyJWTWithOptions' {
		if args.len != 1 { return error('verifyJWTWithOptions requires a token') }
		return (context.verify_jwt_with_options(args[0].str(), options)!).value or { 'null' }
	}
	if args.len != 2 { return error('signJWTWith requires payload and signing config') }
	config := better_auth.jwt_signing_config_from_json(args[1].json_str())!
	return json.encode(context.sign_jwt_with(args[0].json_str(), better_auth.JWTSigningConfig{
		...config
		options: options
	})!)
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
			value := invoke_bridge_internal(mut context, command) or {
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
	iat := (fields['iat'] or { return error('missing issue time') }).f64()
	expiration := if kind.str() == 'date' {
		better_auth.JWTExpiration(time.unix_milli(value.i64()))
	} else if value is string {
		better_auth.JWTExpiration(value)
	} else {
		better_auth.JWTExpiration(value.f64())
	}
	println(json.encode(better_auth.jwt_expiration_at(expiration, iat)!))
}

fn main() {
	if os.args.len == 2 && os.args[1] == '--id-field' {
		id_field_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--redis' {
		redis_bridge() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--oauth-token' {
		oauth_token_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--oauth-assertion' {
		oauth_assertion_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}

	if os.args.len == 2 && os.args[1] == '--oauth-helpers' {
		oauth_helper_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}

	if os.args.len == 2 && os.args[1] == '--provider-id-token' {
		provider_id_token_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--google' {
		google_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--cookies' {
		cookie_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
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
	if os.args.len == 2 && os.args[1] == '--trusted-origins' {
		input := json2.decode[map[string]json2.Any](os.get_raw_line()) or {
			eprintln(err.msg())
			exit(1)
		}
		origins := better_auth.get_trusted_origins((input['options'] or {
			json2.Any(map[string]json2.Any{})
		}).json_str(), (input['request_url'] or { json2.Any('') }).str(),
			os.getenv('BETTER_AUTH_TRUSTED_ORIGINS')) or {
			eprintln(err.msg())
			exit(1)
		}
		println(json.encode(origins))
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
	} else if opts.storage == 'postgres' {
		options := opts.postgres or {
			emit(Reply{ id: init.id, error: 'PostgreSQL options are required' })
			return
		}

		storage = better_auth.open_postgres(options) or {
			emit(Reply{ id: init.id, error: err.msg() })
			return
		}
	} else if opts.storage == 'mongo' {
		options := opts.mongo or {
			emit(Reply{ id: init.id, error: 'MongoDB options are required' })
			return
		}

		storage = better_auth.open_mongo(options) or {
			emit(Reply{ id: init.id, error: err.msg() })
			return
		}
	} else if opts.storage != 'memory' {
		emit(Reply{ id: init.id, error: 'unsupported storage' })
		return
	}
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
	mut auth := better_auth.new(better_auth.Config{
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
				auth.migrate_storage() or {
					emit(Reply{ id: command.id, error: err.msg() })
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
					return invoke_bridge_internal(mut context, command)
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
			'prepare-request' {
				prepared := auth.prepare_request(command.request, command.direct) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(prepared) })
			}
			'complete-request' {
				prepared := json.decode(better_auth.PreparedRequest, command.prepared_json) or {
					emit(Reply{ id: command.id, error: err.msg() })
					continue
				}
				actual := better_auth.PreparedRequest{
					...prepared
					request:  command.hook_request or { prepared.request }
					response: command.hook_response
				}
				email_start := state.emails.len
				log_start := state.logs.len
				response := auth.handle_prepared(actual)
				emit(Reply{
					id:       command.id
					response: response
					emails:   state.emails[email_start..].clone()
					logs:     state.logs[log_start..].clone()
				})
			}
			'request' {
				start := state.emails.len
				log_start := state.logs.len
				mut response := better_auth.Response{}
				if command.direct {
					response = auth.call_result(command.request) or {
						message := 'Internal server error'
						emit(Reply{
							id:           command.id
							error:        message
							error_status: 500
							error_code:   'INTERNAL_SERVER_ERROR'
						})
						continue
					}
				} else {
					response = auth.handle(command.request)
				}

				emit(Reply{
					id:       command.id
					response: response
					emails:   state.emails[start..].clone()
					logs:     state.logs[log_start..].clone()
				})
			}
			'inspect' {
				if command.model == 'session' {
					mut records := []better_auth.Session{}
					users := storage.users() or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					for user in users {
						records << storage.sessions(user.id) or { []better_auth.Session{} }
					}
					encoded := filter_inspection('[' +
						records.map(better_auth.encode_session(it)).join(',') + ']',
						command.where_json) or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					emit(Reply{ id: command.id, records_json: encoded })
					continue
				}
				if command.model == 'twoFactor' {
					if mut storage is better_auth.TwoFactorStorage {
						records := storage.two_factors('') or {
							emit(Reply{ id: command.id, error: err.msg() })
							continue
						}
						encoded := filter_inspection('[' +
							records.map(better_auth.encode_two_factor(it)).join(',') + ']',
							command.where_json) or {
							emit(Reply{ id: command.id, error: err.msg() })
							continue
						}
						emit(Reply{ id: command.id, records_json: encoded })
						continue
					}
				}
				if command.model == 'verification' {
					records := storage.verifications() or {
						emit(Reply{ id: command.id, error: err.msg() })
						continue
					}
					encoded := filter_inspection('[' +
						records.map(better_auth.encode_verification(it)).join(',') + ']',
						command.where_json) or {
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

fn otp_callback(method string, data string, mut context better_auth.EndpointContext) !string {
	request := context.request_context()
	encoded_request := if value := request.request { json.encode(value) } else { 'null' }
	session := if value := context.session {
		'{"session":${better_auth.encode_session(value.session)},"user":${better_auth.encode_user(value.user)}}'
	} else {
		'null'
	}
	return callback_with_context(method,
		'{"data":${data},"request":${encoded_request},"headers":${json.encode(request.headers)},"session":${session}}', mut
		context)
}

fn field_schema(encoded string, model string, callbacks []string) !map[string]better_auth.AdditionalField {
	mut fields := json2.decode[map[string]better_auth.AdditionalField](encoded)!
	for name, field in fields.clone() {
		mut configured := field
		validation := 'field.' + model + '.' + name + '.validate'
		transformation := 'field.' + model + '.' + name + '.transform'
		if validation in callbacks { configured = better_auth.AdditionalField{
				...configured
				validate_input: fn [validation] (value json2.Any) !better_auth.FieldInputResult {
					return json2.decode[better_auth.FieldInputResult](callback_rpc(validation, value.json_str())!)}
			} }
		if transformation in callbacks { configured = better_auth.AdditionalField{
				...configured
				transform_input: fn [transformation] (value json2.Any) !better_auth.FieldInputResult {
					return json2.decode[better_auth.FieldInputResult](callback_rpc(transformation, value.json_str())!)}
			} }
		fields[name] = configured
	}
	return fields
}
