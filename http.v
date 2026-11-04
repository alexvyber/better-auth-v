module better_auth

import json
import x.json2
import net.urllib
import net.http

struct Payload {
	state                 string
	provider              string
	disable_redirect      bool @[json: 'disableRedirect']
	email                 string
	password              string
	name                  string
	image                 ?string
	remember_me           bool = true   @[json: 'rememberMe']
	callback_url          string @[json: 'callbackURL']
	redirect_to           string @[json: 'redirectTo']
	error_callback_url    string @[json: 'errorCallbackURL']
	new_user_callback_url string @[json: 'newUserCallbackURL']
	token                 string
	current_password      string @[json: 'currentPassword']
	new_email             string @[json: newEmail]
	new_password          string @[json: 'newPassword']
	revoke_other_sessions bool   @[json: 'revokeOtherSessions']
}

fn core_routes() map[string][]string {
	return {
		'/error':                   ['GET']
		'/ok':                      ['GET']
		'/sign-up/email':           ['POST']
		'/sign-in/email':           ['POST']
		'/sign-in/social':          ['POST']
		'/get-session':             ['GET', 'POST']
		'/sign-out':                ['POST']
		'/list-sessions':           ['GET']
		'/revoke-session':          ['POST']
		'/revoke-sessions':         ['POST']
		'/revoke-other-sessions':   ['POST']
		'/update-session':          ['POST']
		'/change-email':            ['POST']
		'/update-user':             ['POST']
		'/verify-password':         ['POST']
		'/change-password':         ['POST']
		'/delete-user':             ['POST']
		'/delete-user/callback':    ['GET']
		'/request-password-reset':  ['POST']
		'/reset-password':          ['POST']
		'/send-verification-email': ['POST']
		'/verify-email':            ['GET']
	}
}

fn json_response[T](value T) Response {
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    json.encode(value)
	}
}

fn with_header(r Response, name string, value string) Response {
	mut headers := r.headers.clone()
	headers << Header{name, value}
	return Response{
		...r
		headers: headers
	}
}

fn (a &Auth) cookie_name() string {
	return a.cookie_name_for('session_token')
}

fn (a &Auth) set_cookie(r Response, token string, remember bool) Response {
	bounded_age := if a.config.session_expires_in > 34560000 {
		i64(34560000)
	} else {
		a.config.session_expires_in
	}
	max_age := if remember { ?i64(bounded_age) } else { none }
	value := a.cookie_header(a.cookie_name(), urllib.query_escape(a.sign_cookie(token)), '/',
		max_age)
	mut result := with_header(r, 'set-cookie', value)
	for plugin in a.config.plugins {
		if plugin is BearerPlugin { result = with_header(result, 'set-auth-token', token) }
	}
	marker := a.cookie_name_for('dont_remember')
	if !remember {
		result = with_header(result, 'set-cookie', a.cache_cookie_header(marker,
			urllib.query_escape(a.sign_cookie('true')), none))
	} else if marker in cookie_values(a.request_context) {
		result = with_header(result, 'set-cookie', a.cache_cookie_header(marker, '', i64(0)))
	}
	return result
}

fn (a &Auth) clear_cookie(r Response) Response {
	value := a.cookie_header(a.cookie_name(), '', '/', i64(0))
	mut result := a.clear_cache_cookie(with_header(r, 'set-cookie', value))
	marker := a.cookie_name_for('dont_remember')
	if marker in cookie_values(a.request_context) {
		result = with_header(result, 'set-cookie', a.cache_cookie_header(marker, '', i64(0)))
	}
	return result
}

// handle is the public transport-independent HTTP entry point. Each Auth instance
// serializes calls to its storage connection, including complete transactions.
pub fn (mut a Auth) handle(req Request) Response {
	return a.process(req, false)
}

// call is for trusted server-side calls. It bypasses HTTP content-type and CSRF
// checks, but retains validation, authorization, and transaction semantics.
// Never expose a caller-controlled choice between call() and handle().
pub fn (mut a Auth) call(req Request) Response {
	return a.process(req, true)
}

fn (mut a Auth) process(req Request, direct bool) Response {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed {
		return error_response(fail(503, 'SERVICE_UNAVAILABLE', 'Auth instance is closed'))
	}
	mut headers := map[string]string{}
	for name, value in req.headers {
		headers[name.to_lower()] = value
	}
	normalized := Request{
		...req
		method:  req.method.to_upper()
		headers: headers
	}
	previous_context := a.request_context
	defer { a.request_context = previous_context }
	parsed_origin := urllib.parse(normalized.url) or { urllib.URL{} }
	origin_url := if parsed_origin.scheme in ['http', 'https'] && parsed_origin.host != ''
		&& !normalized.url.all_after('://').all_before('/').all_before('?').all_before('#').contains('@') {
		parsed_origin.scheme + '://' + parsed_origin.host
	} else {
		''
	}
	a.request_context = RequestContext{
		headers: headers
		origin:  origin_url
		request: if direct { none } else { ?Request(normalized) }
	}
	r := a.process_checked(normalized, direct) or { error_response(err) }
	mut result := r
	parsed_url := urllib.parse(normalized.url) or { urllib.URL{} }
	mut plugin_endpoint := false
	for plugin in a.config.plugins {
		for endpoint in plugin.endpoints() {
			if parsed_url.path == a.config.base_path + endpoint.path
				&& normalized.method == endpoint.method {
				plugin_endpoint = true
			}
		}
	}
	if !plugin_endpoint { result = with_header(result, 'cache-control', 'no-store') }
	result = with_header(result, 'x-content-type-options', 'nosniff')
	origin := headers['origin']
	if origin != '' && a.trusted(origin) {
		result = with_header(result, 'access-control-allow-origin', origin)
		result = with_header(result, 'access-control-allow-credentials', 'true')
		result = with_header(result, 'vary', 'Origin')
	}
	return result
}

fn (mut a Auth) process_checked(req Request, direct bool) !Response {
	if req.body.len > a.config.max_body_bytes {
		return fail(413, 'BODY_TOO_LARGE', 'Request body too large')
	}
	u := urllib.parse(req.url) or { return fail(400, 'INVALID_URL', 'Invalid URL') }
	if (!direct || u.scheme != '' || u.host != '') && (u.scheme !in ['http', 'https']
		|| u.host == ''
		|| req.url.all_after('://').all_before('/').all_before('?').all_before('#').contains('@')) {
		return fail(400, 'INVALID_URL', 'Invalid URL')
	}
	path := if u.path.starts_with(a.config.base_path + '/') {
		u.path[a.config.base_path.len..]
	} else {
		return fail(404, 'NOT_FOUND', 'Not found')
	}
	if req.method == 'OPTIONS' {
		if !a.trusted(req.headers['origin']) { return fail(403, 'INVALID_ORIGIN', 'Invalid origin') }
		return Response{
			status:  204
			headers: [Header{'access-control-allow-methods', 'GET, POST, OPTIONS'},
				Header{'access-control-allow-headers', 'Content-Type'},
				Header{'access-control-max-age', '600'}]
		}
	}
	mut methods := core_routes()[path]
	for plugin in a.config.plugins {
		for endpoint in plugin.endpoints() {
			if endpoint.path == path { methods << endpoint.method }
		}
	}
	if path.starts_with('/reset-password/') { methods = ['GET'] }
	if path.starts_with('/callback/') { methods = ['GET'] }
	if methods.len == 0 { return fail(404, 'NOT_FOUND', 'Not found') }
	if req.method !in methods { return fail(405, 'METHOD_NOT_ALLOWED', 'Method not allowed') }
	if !direct {
		a.check_csrf(req, path)!
		a.rate_limit(path)!
	}
	mut body := req.body
	if req.method == 'POST' {
		content_type := req.headers['content-type'].all_before(';').trim_space().to_lower()
		if content_type == 'application/x-www-form-urlencoded'
			&& path in ['/sign-up/email', '/sign-in/email'] {
			values := urllib.parse_query(body) or {
				return fail(400, 'INVALID_BODY', 'Invalid body')
			}
			mut fields := map[string]string{}
			for key, _ in values.to_map() {
				fields[key] = values.get(key) or { '' }
			}
			body = json.encode(fields)
		} else if !direct && content_type != 'application/json' {
			return fail(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json')
		}
		if body == '' { body = '{}' }
		json2.decode[map[string]json2.Any](body) or {
			return fail(400, 'BODY_MUST_BE_AN_OBJECT', 'Body must be an object')
		}
	}
	payload := if req.method == 'POST' { json.decode(Payload, body) or {
			return fail(400, 'VALIDATION_ERROR', 'Validation Error')} } else { Payload{} }
	for field, value in {
		'callbackURL':        payload.callback_url
		'redirectTo':         payload.redirect_to
		'errorCallbackURL':   payload.error_callback_url
		'newUserCallbackURL': payload.new_user_callback_url
	} {
		a.check_redirect(value, field)!
	}
	for field in ['callbackURL', 'redirectTo'] {
		a.check_redirect((u.query().get(field) or { '' }), field)!
	}
	a.begin_transaction(path == '/get-session' && req.method == 'GET'
		&& a.config.defer_session_refresh)!
	defer { a.rollback_transaction() }
	mut result := a.dispatch(Request{ ...req, body: body }, path, payload)!
	if path == '/get-session' && result.body != 'null' {
		if options := a.jwt_options() {
			if !options.disable_setting_jwt_header {
				current := decode_session_result(result.body)!
				result = with_header(result, 'set-auth-jwt', a.session_jwt(current)!)
				result = with_header(result, 'access-control-expose-headers', 'set-auth-jwt')
			}
		}
	}
	if a.transaction_active { a.commit_transaction()! }
	return result
}

fn (a &Auth) check_csrf(req Request, path string) ! {
	if req.method in ['GET', 'HEAD'] { return }
	origin := req.headers['origin']
	if req.headers['cookie'] == '' && path in ['/sign-in/email', '/sign-up/email']
		&& req.headers['sec-fetch-site'] == 'cross-site'
		&& req.headers['sec-fetch-mode'] == 'navigate' {
		return fail(403, 'CROSS_SITE_NAVIGATION_LOGIN_BLOCKED',
			'Cross-site navigation login blocked. This request appears to be a CSRF attack.')
	}
	if origin != '' {
		if origin == 'null' && req.headers['sec-fetch-site'] == 'same-origin' {
			u := urllib.parse(req.url)!
			target := if a.config.trust_proxy_origin_headers
				&& req.headers['x-forwarded-host'] != ''
				&& req.headers['x-forwarded-proto'] in ['https', 'http'] {
				req.headers['x-forwarded-proto'] + '://' + req.headers['x-forwarded-host']
			} else {
				u.scheme + '://' + u.host
			}
			if !a.trusted(target) { return fail(403, 'INVALID_ORIGIN', 'Invalid origin') }
		} else if origin == 'null' {
			return fail(403, 'MISSING_OR_NULL_ORIGIN', 'Missing or null Origin')
		} else if !a.trusted(origin) {
			return fail(403, 'INVALID_ORIGIN', 'Invalid origin')
		}
	} else if req.headers['referer'] != '' {
		u := urllib.parse(req.headers['referer']) or {
			return fail(403, 'INVALID_ORIGIN', 'Invalid origin')
		}
		if !a.trusted(u.scheme + '://' + u.host) {
			return fail(403, 'INVALID_ORIGIN', 'Invalid origin')
		}
	} else if req.headers['sec-fetch-site'] == 'cross-site' {
		return fail(403, 'INVALID_ORIGIN', 'Invalid origin')
	} else if req.headers['cookie'] != '' {
		return fail(403, 'MISSING_OR_NULL_ORIGIN', 'Missing or null Origin')
	}
}

fn (mut a Auth) rate_limit(path string) ! {
	if a.config.rate_limit_max == 0 { return }
	now := a.config.clock()
	// Bounded, per-instance limiter. Applications needing per-IP/distributed
	// limits should enforce those at their trusted HTTP ingress as well.
	for key, bucket in a.limits {
		if now - bucket.start >= a.config.rate_limit_window { a.limits.delete(key) }
	}
	key := if path.starts_with('/callback/') {
		'/callback/:provider'
	} else if path.starts_with('/reset-password/') {
		'/reset-password/:token'
	} else {
		path
	}
	previous := a.limits[key] or {
		RateBucket{
			start: now
		}
	}
	if previous.count >= a.config.rate_limit_max {
		return fail(429, 'TOO_MANY_REQUESTS', 'Too many requests')
	}
	a.limits[key] = RateBucket{
		start: previous.start
		count: previous.count + 1
	}
}

fn (mut a Auth) dispatch(req Request, path string, p Payload) !Response {
	ctx := RequestContext{
		headers: req.headers
	}
	u := urllib.parse(req.url)!
	match path {
		'/sign-in/social' {
			return a.start_oauth(p)
		}
		'/ok' {
			return json_response({
				'ok': true
			})
		}
		'/sign-up/email' {
			fields := json2.decode[map[string]json2.Any](req.body)!
			if 'name' !in fields { return fail(400, 'MISSING_FIELD', 'Name is required') }
			mut additional_input := map[string]json2.Any{}
			for key, value in fields {
				if key !in sign_up_reserved_fields { additional_input[key] = value }
			}
			result := a.sign_up(SignUpInput{
				additional_fields: additional_input
				email:             p.email
				password:          p.password
				name:              p.name
				image:             p.image
			}, ctx)!
			token_json := if token := result.token { json.encode(token) } else { 'null' }
			r := Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"token":${token_json},"user":${a.user_json(result.user)}}'
			}
			if session := result.session { return a.set_session_cookies(r, SessionResult{
					session: session
					user:    result.user
				}) }
			return r
		}
		'/sign-in/email' {
			result := a.sign_in(SignInInput{
				email:       p.email
				password:    p.password
				remember_me: p.remember_me
			}, ctx) or {
				if err is APIError {
					// A verification email deliberately survives a rejected sign-in.
					if err.code == 'EMAIL_NOT_VERIFIED' { return error_response(err) }
				}
				return err
			}
			token := result.token or { return error('missing session token') }
			session := result.session or { return error('missing created session') }
			r := Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"redirect":${p.callback_url != ''},"token":${json.encode(token)},"user":${a.user_json(result.user)}}'
			}
			if p.callback_url != '' {
				return a.set_session_cookies(with_header(r, 'location', p.callback_url), SessionResult{
					session: session
					user:    result.user
				})
			}
			return a.set_session_cookies(r, SessionResult{ session: session, user: result.user })
		}
		'/get-session' {
			if req.method == 'POST' && !a.config.defer_session_refresh {
				return fail(405, 'METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED',
					'POST method requires deferSessionRefresh to be enabled in session config')
			}
			if (u.query().get('disableCookieCache') or { '' }) !in ['true', '1'] {
				if cached := (a.cached_session(ctx)!).value {
					if a.config.stateless_sessions && !a.has_secondary() && (a.config.cookie_cache.refresh_cache or {
						false
					}) && !a.config.disable_session_refresh && (u.query().get('disableRefresh') or {
						''
					}) !in ['true', '1'] && cached.expires_at - a.config.clock() * 1000 < (a.config.cookie_cache.update_age or {
						0
					}) * 1000 {
						return a.set_session_cookies(a.session_response(cached.result),
							cached.result)
					}
					return a.session_response(cached.result)
				}
			}
			result := (a.lookup_session(ctx,
				!a.config.defer_session_refresh || req.method == 'POST')!).value or {
				return a.clear_cookie(Response{
					headers: [
						Header{'content-type', 'application/json'},
						Header{'pragma', 'no-cache'},
					]
					body:    'null'
				})
			}

			if !result.session.persistent || (u.query().get('disableRefresh') or { '' }) != '' {
				return a.set_cache_cookie(a.session_response(result), result)
			}
			due := epoch(result.session.expires_at)! - a.config.session_expires_in +
				a.config.session_update_age
			needs_refresh := a.config.clock() >= due && !a.config.disable_session_refresh
			if a.config.defer_session_refresh && req.method == 'GET' {
				return a.session_response(SessionResult{ ...result, needs_refresh: needs_refresh })
			}
			if needs_refresh {
				updated := Session{
					...result.session
					updated_at: stamp(a.config.clock())
					expires_at: stamp(a.config.clock() + a.config.session_expires_in)
				}
				a.update_session_record(updated)!
				return a.set_session_cookies(a.session_response(SessionResult{
					user:    result.user
					session: updated
				}), SessionResult{ user: result.user, session: updated })
			}
			return a.set_cache_cookie(a.session_response(result), result)
		}
		'/sign-out' {
			return a.sign_out_request(p, ctx)!
		}
		'/error' {
			return error_page(req.url)!
		}
		'/list-sessions' {
			current := a.require_session(ctx, true)!
			sessions := a.user_sessions(current.user.id)!
			encoded := sessions.map(a.session_json(it)).join(',')
			return Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '[' + encoded + ']'
			}
		}
		'/revoke-session', '/revoke-sessions', '/revoke-other-sessions' {
			current := a.require_session(ctx, true)!
			if path == '/revoke-session' {
				for session in a.user_sessions(current.user.id)! {
					if session.token == p.token || session.id == p.token {
						a.remove_session_row(session)!
					}
				}
			} else {
				a.remove_user_sessions(current.user.id, if path == '/revoke-other-sessions' {
					current.session.id
				} else {
					''
				})!
			}
			return json_response({
				'status': true
			})
		}
		'/update-session' {
			current := a.require_session(ctx, false)!
			input := json2.decode[map[string]json2.Any](req.body)!
			mut allowed := map[string]json2.Any{}
			for key, value in input {
				if key in a.config.session_fields { allowed[key] = value }
			}
			if allowed.len == 0 { return fail(400, 'NO_FIELDS_TO_UPDATE', 'No fields to update') }
			updated_fields := parse_fields(a.config.session_fields, allowed,
				current.session.additional_fields, false)!
			mut updated := Session{
				...current.session
				additional_fields: updated_fields
				updated_at:        stamp(a.config.clock())
			}
			updated = a.update_session_record(updated)!
			return a.set_session_cookies(Response{
				headers: [
					Header{'content-type', 'application/json'},
				]
				body:    '{"session":${a.session_json(updated)}}'
			}, SessionResult{
				session: updated
				user:    current.user
			})
		}
		'/update-user' {
			current := a.require_session(ctx, false)!
			fields := json2.decode[map[string]json2.Any](req.body)!
			for field, _ in fields {
				if field !in ['name', 'image'] && field !in a.config.user_fields {
					return fail(400, 'FIELD_NOT_ALLOWED', 'Field not allowed to be set')
				}
			}

			additional := a.parse_user_fields(fields, current.user.additional_fields, false)!
			updated := User{
				...current.user
				additional_fields: additional
				name:              if 'name' in fields { p.name } else { current.user.name }
				image:             if 'image' in fields { p.image } else { current.user.image }
				updated_at:        stamp(a.config.clock())
			}
			a.update_user_record(updated)!
			return json_response({
				'status': true
			})
		}
		'/verify-password' {
			current := a.require_session(ctx, false)!
			a.check_password_max(p.password)!
			account := (a.storage.account(current.user.id, 'credential')!).value or {
				return fail(400, 'INVALID_PASSWORD', 'Invalid password')
			}

			if !a.config.password_hasher.verify(p.password, account.password)! {
				return fail(400, 'INVALID_PASSWORD', 'Invalid password')
			}
			return json_response({
				'status': true
			})
		}
		'/change-password' {
			current := a.require_session(ctx, false)!
			a.check_password(p.new_password)!
			a.check_password_max(p.current_password)!
			account := (a.storage.account(current.user.id, 'credential')!).value or {
				return fail(400, 'CREDENTIAL_ACCOUNT_NOT_FOUND', 'Credential account not found')
			}

			if account.password == '' {
				return fail(400, 'CREDENTIAL_ACCOUNT_NOT_FOUND', 'Credential account not found')
			}
			hash := a.config.password_hasher.hash(p.new_password)!
			if !a.config.password_hasher.verify(p.current_password, account.password)! {
				return fail(400, 'INVALID_PASSWORD', 'Invalid password')
			}
			if p.revoke_other_sessions { a.remove_user_sessions(current.user.id, '')! }
			a.update_account_record(account, '{"password":${json.encode(hash)}}')!
			if p.revoke_other_sessions {
				session := a.make_session(current.user.id, ctx, true)!
				return a.set_session_cookies(Response{
					headers: [Header{'content-type', 'application/json'}]
					body:    '{"token":${json.encode(session.token)},"user":${a.user_json(current.user)}}'
				}, SessionResult{
					session: session
					user:    current.user
				})
			}
			return Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"token":null,"user":${a.user_json(current.user)}}'
			}
		}
		'/delete-user' {
			return a.delete_user_request(p, ctx)!
		}
		'/delete-user/callback' {
			return a.delete_user_callback(Payload{
				token:        u.query().get('token') or { '' }
				callback_url: u.query().get('callbackURL') or { '' }
			}, ctx)!
		}
		'/request-password-reset' {
			email := normalize_email(p.email)!
			if user := (a.storage.user_by_email(email)!).value {
				a.issue_email('reset-password', user, p.redirect_to) or {
					a.config.log('error', 'Failed to send reset password email')
				}
			} else {
				a.config.log('warn', 'Reset Password: User not found')
			}
			return Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"status":true,"message":"If this email exists in our system, check your email for the reset link"}'
			}
		}
		'/reset-password' {
			a.check_password(p.new_password)!
			token := if p.token != '' { p.token } else { (u.query().get('token') or { '' }) }
			user := a.token_user(token, 'reset-password')!
			hash := a.config.password_hasher.hash(p.new_password)!
			a.consume_token(token, 'reset-password')!
			if a.config.revoke_sessions_on_password_reset { a.remove_user_sessions(user.id, '')! }
			if (a.storage.account(user.id, 'credential')!).value == none {
				a.persist_account(Account{
					user_id:     user.id
					provider_id: 'credential'
					account_id:  user.id
					id:          random_token()!
					password:    hash
				})!
			} else {
				a.update_password(user.id, hash)!
			}
			a.queue_task(AfterCommitTask{ kind: 'password-reset', user: user })!
			return json_response({
				'status': true
			})
		}
		'/send-verification-email' {
			return a.send_verification(p, ctx)
		}
		'/verify-email' {
			return a.verify_email_request(req, ctx)
		}
		'/change-email' {
			return a.change_email_request(p, ctx)
		}
		else {
			if path.starts_with('/callback/') {
				return a.finish_oauth(req, path.all_after('/callback/'))
			}
			if path.starts_with('/reset-password/') {
				token := path.all_after('/reset-password/')
				record := (a.storage.verification(digest(token))!).value or {
					return fail(400, 'INVALID_TOKEN', 'Invalid token')
				}

				if record.identifier != 'reset-password' || record.expires_at <= a.config.clock() {
					return fail(400, 'INVALID_TOKEN', 'Invalid token')
				}
				callback := (u.query().get('callbackURL') or { '' })
				if callback == '' {
					return fail(400, 'CALLBACK_URL_REQUIRED', 'callbackURL is required')
				}
				separator := if callback.contains('?') { '&' } else { '?' }
				return Response{
					status:  302
					headers: [
						Header{'location', callback + separator + 'token=' +
							urllib.query_escape(token)},
					]
				}
			}
			for plugin in a.config.plugins {
				for endpoint in plugin.endpoints() {
					if endpoint.path == path && endpoint.method == req.method {
						current := if endpoint.require_session || endpoint.fresh_session {
							?SessionResult(a.require_session(ctx, endpoint.fresh_session)!)
						} else {
							none
						}
						mut context := EndpointContext{
							auth:    a
							session: current
						}
						return endpoint.handler(mut context, req)
					}
				}
			}
			return fail(404, 'NOT_FOUND', 'Not found')
		}
	}
}

fn error_response(err IError) Response {
	if err is APIError {
		return Response{
			status:      err.status
			status_text: http.status_from_int(err.status).str().to_upper().replace(' ', '_')
			headers:     [Header{'content-type', 'application/json'}]
			body:        json.encode({
				'code':    err.code
				'message': err.message
			})
		}
	}
	return Response{
		status:      500
		status_text: 'INTERNAL_SERVER_ERROR'
		headers:     [Header{'content-type', 'application/json'}]
		body:        '{"code":"INTERNAL_SERVER_ERROR","message":"Internal server error"}'
	}
}
