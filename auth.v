module better_auth

import json
import os
import net.urllib
import sync
import time
import x.json2

pub struct Auth {
pub:
	config Config
mut:
	production_cookie_default bool
	warned_origin_csrf        bool
	initial_trusted_origins   []string
	storage                   Storage
	secret_config             SymmetricSecret
	mutex                     &sync.Mutex = sync.new_mutex()
	limits                    map[string]RateBucket
	closed                    bool
	secondary                 SecondaryStorage
	transaction_active        bool
	transactions_enabled      bool
	pending_tasks             []AfterCommitTask
	secondary_created         []Session
	intercepting              map[string]bool
	request_context           RequestContext
	new_session               ?SessionResult
	anonymous_link_session    ?SessionResult
	oauth_nonce_requirements  map[string]bool
	user_defined_fields       []string
}

struct RateBucket {
	window_millis i64
	start         i64
	count         int
}

pub fn new(input_config Config, storage Storage) !&Auth {
	mut config :=
		resolve_cache_defaults(resolve_plugin_fields(resolve_generic_oauth_config(input_config)!))
	if environment := os.getenv_opt('BETTER_AUTH_TRUSTED_ORIGINS') {
		mut origins := config.trusted_origins.clone()
		origins << environment.split(',').filter(it != '')
		config = Config{
			...config
			trusted_origins: origins
		}
	}
	initial_trusted_origins := config.trusted_origins_for(RequestContext{})!
	mut secret_config := SymmetricSecret(config.secret)
	if entries := config.secrets {
		secret_config = SymmetricSecret(build_secret_config(entries, config.secret)!)
		for warning in secret_config_warnings(entries) {
			config.log('warn', warning)
		}
		config = Config{
			...config
			secret: entries[0].value
		}
	}
	if config.password_reset_expires_in == 0 { config = Config{
			...config
			password_reset_expires_in: 3600
		} }
	validate_cookie_config(config)!
	url := urllib.parse(config.base_url)!
	if config.base_url != ''
		&& (url.scheme !in ['http', 'https'] || url.host == '' || config.base_url.contains('@')
		|| url.raw_query != '' || url.fragment != '' || url.path !in ['', '/']) {
		return error('base_url must be an HTTP(S) origin')
	}
	if config.secret == '' { return error('secret is required') }
	if config.secret.len < 32 && config.secrets == none {
		config.log('warn',
			'[better-auth] Warning: your secret should be at least 32 characters long for adequate security.')
	}
	if config.cookie_cache.strategy !in ['compact', 'jwt', 'jwe'] || config.cookie_cache.max_age <= 0 || (config.cookie_cache.update_age or {
		0
	}) < 0 {
		return error('unsupported cookie cache strategy or invalid max age')
	}
	if !config.base_path.starts_with('/') || config.base_path.ends_with('/')
		|| config.base_path.contains_any('?#\\ \t\r\n\x00') || config.base_path.starts_with('//') {
		return error('base_path must begin with / and must not end with /')
	}
	if config.session_expires_in <= 0 || config.verification_expires_in <= 0
		|| config.session_update_age < 0 || config.session_fresh_age < 0
		|| config.password_reset_expires_in <= 0 || config.rate_limit_window <= 0
		|| config.rate_limit_max < 0 || config.max_body_bytes < 0 || config.min_password_length < 1
		|| config.max_password_length < config.min_password_length {
		return error('invalid auth limits')
	}
	if config.id_strategy !in ['random', 'uuid'] {
		return error('unsupported persisted ID strategy')
	}
	if config.rate_limit_storage !in ['memory', 'database'] {
		return error('unsupported rate limit storage')
	}
	for name, field in config.user_fields {
		if name in core_user_fields
			|| name in ['additional_fields', '__proto__', 'constructor', 'prototype'] {
			return error('additional user field collides with a reserved name')
		}
		if field.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
			'number[]'] {
			return error('unsupported additional field type')
		}
		if value := field.default_value { validate_field(field, value)! }
	}
	for name, field in config.session_fields {
		if name in core_session_fields
			|| name in ['additional_fields', '__proto__', 'constructor', 'prototype'] {
			return error('additional session field collides with a reserved name')
		}
		if field.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
			'number[]'] {
			return error('unsupported additional field type')
		}
		if value := field.default_value { validate_field(field, value)! }
	}
	mut ids := map[string]bool{}
	mut provider_ids := map[string]bool{}
	for provider in config.social_providers {
		id := provider.id()
		if id == '' || id.len > 64 || id in provider_ids {
			return error('duplicate or invalid OAuth provider id')
		}
		for c in id.bytes() {
			if !((c >= `a` && c <= `z`) || (c >= `0` && c <= `9`) || c in [`-`, `_`]) {
				return error('invalid OAuth provider id')
			}
		}
		provider_ids[id] = true
	}
	mut routes := map[string]bool{}
	for path, methods in core_routes() {
		for method in methods {
			routes[method + ' ' + path] = true
		}
	}
	for plugin in config.plugins {
		if plugin is JWTPlugin {
			options := normalized_jwt_options(plugin.options)
			if options.custom_signer() && options.remote_url == '' {
				return error('options.jwks.remoteUrl must be set when using options.jwt.sign')
			}
			if options.remote_url != '' && plugin.options.algorithm == '' {
				return error('options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata')
			}
			if options.session_cookie_cache && options.custom_signer() {
				return error('JWT session cookie cache requires locally managed keys and does not support jwt.sign')
			}
			if options.algorithm !in jwt_algorithms
				|| (options.curve != '' && options.curve != jwt_curve(options.algorithm)) {
				return error('unsupported JWT algorithm or curve')
			}
			for extra in options.key_pair_configs {
				if extra.algorithm !in jwt_algorithms
					|| (extra.curve != '' && extra.curve != jwt_curve(extra.algorithm))
					|| extra.modulus_length < 2048 || extra.modulus_length > 8192 {
					return error('unsupported extra JWT key configuration')
				}
			}
			if options.modulus_length < 2048 || options.modulus_length > 8192 {
				return error('invalid RSA modulus length')
			}
			if options.rotation_interval < 0 || options.grace_period < 0 || options.expires_in <= 0 {
				return error('invalid JWT timing options')
			}
			if options.jwks_path == '' || !options.jwks_path.starts_with('/')
				|| options.jwks_path.contains('..') {
				return error('invalid JWKS path')
			}
			if options.session_cookie_cache && config.cookie_cache.strategy != 'jwt' {
				return error('JWT session cookie cache requires the jwt cache strategy')
			}
		}
		if plugin.id() == '' || plugin.id() in ids { return error('duplicate or empty plugin id') }
		ids[plugin.id()] = true
		for endpoint in plugin.endpoints() {
			key := endpoint.method + ' ' + endpoint.path
			if !endpoint.path.starts_with('/') || endpoint.path.starts_with('/callback/')
				|| endpoint.path.starts_with('/reset-password/') || key in routes {
				return error('duplicate or invalid plugin endpoint')
			}
			if endpoint.handler == empty_endpoint {
				return error('plugin endpoint handler is required')
			}
			routes[key] = true
		}
	}
	return &Auth{
		production_cookie_default: os.getenv('NODE_ENV') == 'production'
		initial_trusted_origins:   initial_trusted_origins
		user_defined_fields:       input_config.user_fields.keys()
		config:                    config
		secret_config:             secret_config
		transactions_enabled:      config.database_transactions
		storage:                   storage
		secondary:                 config.secondary_storage
	}
}

pub fn (mut a Auth) close() ! {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed { return }
	a.storage.close()!
	a.closed = true
}

fn (a &Auth) clock_millis() i64 {
	if a.config.clock_millis != no_millisecond_clock { return a.config.clock_millis() }
	if a.config.clock == time.unix_now { return time.now().unix_milli() }
	return a.config.clock() * 1000
}

fn stamp(epoch i64) string {
	return time.unix(epoch).format_rfc3339()
}

fn epoch(value string) !i64 {
	return time.parse_rfc3339(value)!.unix()
}

fn stamp_millis(value i64) string {
	return time.unix_milli(value).format_rfc3339()
}

fn epoch_millis(value string) !i64 {
	return time.parse_rfc3339(value)!.unix_milli()
}

fn verification_expiry_millis(value Verification) i64 {
	return value.expires_at_millis or { value.expires_at * 1000 }
}

fn normalize_email(value string) !string {
	email := value.trim_space().to_lower()
	parts := email.split('@')
	if email.len > 254 || parts.len != 2 || parts[0] == '' || parts[1] == ''
		|| !parts[1].contains('.') || email.contains_any(' \t\r\n\x00') {
		return fail(400, 'INVALID_EMAIL', 'Invalid email')
	}
	return email
}

fn (a &Auth) check_password(password string) ! {
	if utf16_length(password) < a.config.min_password_length {
		a.config.log('warn', 'Password is too short')
		return fail(400, 'PASSWORD_TOO_SHORT', 'Password too short')
	}
	a.check_password_max(password)!
}

fn utf16_length(value string) int {
	mut length := 0
	for codepoint in value.runes() {
		length += if u32(codepoint) > 0xffff { 2 } else { 1 }
	}
	return length
}

fn (a &Auth) check_password_max(password string) ! {
	if utf16_length(password) > a.config.max_password_length {
		a.config.log('warn', 'Password is too long')
		return fail(400, 'PASSWORD_TOO_LONG', 'Password too long')
	}
}

fn (mut a Auth) make_session(user_id string, ctx RequestContext, remember bool) !Session {
	if encoded := (a.intercept_internal('createSession', '[${json.encode(user_id)},${!remember}]')!).value {
		return decode_session(encoded)!
	}

	now := a.clock_millis()
	token := random_token()!
	lifetime := if remember { a.config.session_expires_in } else { i64(86400) }
	session := Session{
		additional_fields: parse_fields(a.config.session_fields, map[string]json2.Any{},
			map[string]json2.Any{}, true)!
		persistent:        remember
		id:                a.new_id('session')!
		user_id:           user_id
		token:             token
		expires_at:        stamp_millis(now + lifetime * 1000)
		created_at:        stamp_millis(now)
		updated_at:        stamp_millis(now)
		// Forwarded headers require explicit opt-in behind a trusted ingress.
		ip_address: if a.config.trust_proxy_ip_headers {
			ctx.headers['x-forwarded-for'].all_before(',').trim_space()
		} else {
			''
		}
		user_agent: ctx.headers['user-agent']
	}
	return a.persist_session(session)
}

fn (mut a Auth) sign_up(input SignUpInput, ctx RequestContext) !AuthResult {
	if !a.config.email_and_password || a.config.disable_email_sign_up {
		return fail(400, 'EMAIL_PASSWORD_SIGN_UP_DISABLED',
			'Email and password sign up is not enabled')
	}
	email := normalize_email(input.email)!
	a.check_password(input.password)!
	additional := a.parse_user_fields(input.additional_fields, map[string]json2.Any{}, true)!
	now := stamp_millis(a.clock_millis())
	mut user := User{
		additional_fields: additional
		id:                a.new_id('user')!
		name:              input.name
		email:             email
		image:             input.image
		created_at:        now
		updated_at:        now
	}
	generic_duplicate := a.config.require_email_verification || !a.config.auto_sign_in
	if existing := (a.storage.user_by_email(email)!).value {
		if generic_duplicate {
			a.config.password_hasher.hash(input.password)!
			a.config.on_existing_user_sign_up(existing)!
			return AuthResult{
				user: a.synthetic_user(user)!
			}
		}
		return fail(422, 'USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL',
			'User already exists. Use another email.')
	}
	hash := a.config.password_hasher.hash(input.password)!
	decision := a.config.validate_user_info(user, UserInfoSource{ method: 'email-password' })!
	if decision.error != '' {
		if generic_duplicate { return AuthResult{
				user: a.synthetic_user(user)!
			} }
		return fail(403, decision.error, if decision.error_description != '' {
			decision.error_description
		} else {
			decision.error
		})
	}
	user = a.persist_user(user)!
	a.persist_account(Account{
		id:          a.new_id('account')!
		user_id:     user.id
		provider_id: 'credential'
		account_id:  user.id
		password:    hash
	})!
	if (a.config.send_verification_on_sign_up or { a.config.require_email_verification })
		&& a.can_send_verification() {
		a.issue_email('verify-email', user, '')!
	}
	if !a.config.auto_sign_in || a.config.require_email_verification { return AuthResult{
			user: user
		} }
	session := a.make_session(user.id, ctx, true)!
	return AuthResult{
		user:    user
		token:   session.token
		session: session
	}
}

fn (mut a Auth) sign_in(input SignInInput, ctx RequestContext) !AuthResult {
	if !a.config.email_and_password {
		return fail(400, 'EMAIL_PASSWORD_DISABLED', 'Email and password sign in is not enabled')
	}
	email := normalize_email(input.email)!
	a.check_password_max(input.password)!
	if input.password.len > 4096 {
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}
	user := (a.find_user_by_email(email)!).value or {
		a.config.log('warn', 'User not found')
		a.config.password_hasher.hash(input.password)!
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}

	account := (a.storage.account(user.id, 'credential')!).value or {
		a.config.password_hasher.hash(input.password)!
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}

	if account.password == '' {
		a.config.password_hasher.hash(input.password)!
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}
	if !a.config.password_hasher.verify(input.password, account.password)! {
		a.config.log('warn', 'Invalid password')
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}
	if a.config.require_email_verification && !user.email_verified {
		if a.config.send_verification_on_sign_in && a.can_send_verification() {
			a.issue_email('verify-email', user, '')!
		}
		return fail(403, 'EMAIL_NOT_VERIFIED', 'Email not verified')
	}
	session := a.make_session(user.id, ctx, input.remember_me)!
	return AuthResult{
		user:    user
		token:   session.token
		session: session
	}
}

fn (mut a Auth) current_session(ctx RequestContext) !Lookup[SessionResult] {
	return a.lookup_session(ctx, true)
}

fn (mut a Auth) lookup_session(ctx RequestContext, delete_expired bool) !Lookup[SessionResult] {
	token := a.context_token(ctx) or { return Lookup[SessionResult]{} }
	found := a.find_session_record(token) or {
		a.config.log('error', 'Failed to get session: ${err.msg()}')
		return fail(500, 'FAILED_TO_GET_SESSION', 'Failed to get session')
	}
	result := found.value or { return Lookup[SessionResult]{} }
	if epoch_millis(result.session.expires_at)! < a.clock_millis() {
		if delete_expired { a.remove_session(token)! }
		return Lookup[SessionResult]{}
	}
	return Lookup[SessionResult]{
		value: result
	}
}

fn (mut a Auth) require_session(ctx RequestContext, fresh bool) !SessionResult {
	mut found := Lookup[SessionResult]{}
	if a.config.stateless_sessions && !a.has_secondary() {
		if cached := (a.cached_session(ctx)!).value { found = Lookup[SessionResult]{
				value: cached.result
			} }
	}
	if found.value == none { found = a.current_session(ctx)! }
	result := found.value or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }

	if fresh && a.config.session_fresh_age > 0
		&& a.clock_millis() - epoch_millis(result.session.created_at)! >= a.config.session_fresh_age * 1000 {
		return fail(403, 'SESSION_NOT_FRESH', 'Session is not fresh')
	}
	return result
}

fn (a &Auth) context_token(ctx RequestContext) ?string {
	for plugin in a.config.plugins {
		if plugin.id() == 'bearer' && ctx.headers['authorization'].starts_with('Bearer ') {
			token := ctx.headers['authorization'][7..]
			if token.len == 64 { return token }
			return a.verify_cookie(token)
		}
	}

	for item in ctx.headers['cookie'].split(';') {
		name, raw := item.trim_space().split_once('=') or { continue }
		if name == a.cookie_name() {
			value := urllib.path_unescape(raw) or { return none }
			return a.verify_cookie(value)
		}
	}
	return none
}

fn (mut a Auth) issue_email(kind string, user User, callback string) ! {
	if kind == 'verify-email' {
		if a.email_otp_verification_override() {
			a.send_email_otp_verification(user)!
			return
		}
		if !a.can_send_verification() { return }
		a.config.send_email(a.verification_message(user, callback, '', '')!)!
		return
	}
	token := random_token()!
	a.persist_verification(Verification{
		id:                digest(token)
		identifier:        kind
		value:             user.id
		expires_at:        a.config.clock() +
			if kind == 'reset-password' { a.config.password_reset_expires_in } else { a.config.verification_expires_in }
		expires_at_millis: a.clock_millis() +
			1000 * if kind == 'reset-password' { a.config.password_reset_expires_in } else { a.config.verification_expires_in }
	})!
	path := if kind == 'reset-password' {
		'/reset-password/' + token
	} else {
		'/verify-email?token=' + token
	}
	mut url := a.base_url().trim_right('/') + a.config.base_path + path
	if callback != '' {
		a.check_redirect(callback, 'callbackURL')!
		url += if url.contains('?') { '&' } else { '?' }
		url += 'callbackURL=' + urllib.query_escape(callback)
	}
	a.config.send_email(EmailMessage{
		kind:    kind
		user:    user
		token:   token
		url:     url
		request: a.request_context.request
	})!
}

fn (mut a Auth) token_user(token string, kind string) !User {
	if token.len != 64 { return fail(400, 'INVALID_TOKEN', 'Invalid token') }
	id := digest(token)
	record := (a.storage.verification(id)!).value or {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}

	if record.identifier != kind || verification_expiry_millis(record) < a.clock_millis() {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}
	user := (a.storage.user(record.value)!).value or {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}

	return user
}

fn (mut a Auth) consume_token(token string, kind string) !User {
	user := a.token_user(token, kind)!
	a.remove_verification(digest(token))!
	return user
}

// An omitted base URL is resolved only for the current request. Direct server
// calls without a request keep it unresolved, as in the pinned upstream API.
fn (a &Auth) base_url() string {
	return if a.config.base_url != '' { a.config.base_url } else { a.request_context.origin }
}

fn (a &Auth) trusted(origin string) bool {
	return origin != '' && a.is_trusted_origin(origin, false)
}

fn (a &Auth) check_redirect(value string, input_field string) ! {
	field := if input_field == 'redirectTo' { 'redirectURL' } else { input_field }
	if value == '' { return }
	if value.contains_any('\r\n\x00') {
		return fail(403, 'INVALID_CALLBACK_URL', 'Invalid ${field}')
	}
	if a.skip_origin_check() { return }
	if value.contains('\\') || value.starts_with('//') {
		return fail(403, 'INVALID_CALLBACK_URL', 'Invalid ${field}')
	}
	// Trusted server calls have no HTTP origin policy; keep structural header checks.
	if a.request_context.request == none { return }
	if !a.is_trusted_origin(value, true) {
		return fail(403, 'INVALID_CALLBACK_URL', 'Invalid ${field}')
	}
}

fn (a &Auth) secret_candidates() []string {
	mut candidates := [a.config.secret]
	config := a.secret_config
	if config is SecretConfig {
		for _, value in config.keys {
			if value != '' && value !in candidates { candidates << value }
		}
		if config.legacy_secret != '' && config.legacy_secret !in candidates {
			candidates << config.legacy_secret
		}
	}
	return candidates
}

// Adapter capabilities are application-owned, never request-controlled HTTP data.
pub fn (mut a Auth) set_adapter_transactions(enabled bool) ! {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.transaction_active {
		return error('cannot change adapter transactions during an operation')
	}
	a.transactions_enabled = enabled
}
