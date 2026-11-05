module better_auth

import crypto.rand
import crypto.sha256
import x.json2

pub struct OneTimeTokenOptions {
pub:
	expires_in                    f64 = 3    @[json: expiresIn]
	disable_client_request        bool   @[json: disableClientRequest]
	disable_set_session_cookie    bool   @[json: disableSetSessionCookie]
	set_ott_header_on_new_session bool   @[json: setOttHeaderOnNewSession]
	store_token                   string = 'plain' @[json: storeToken]
	generate_token                fn (mut EndpointContext, SessionResult) !string = default_one_time_token @[skip]
	hash_token                    fn (string) !string = default_one_time_token_hasher @[skip]
}

pub fn default_one_time_token_hasher(token string) !string {
	return base64url(sha256.sum(token.bytes()))
}

fn default_one_time_token(mut _ EndpointContext, _ SessionResult) !string {
	alphabet := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
	mut result := []u8{}
	for result.len < 32 {
		for byte in rand.bytes(48)! {
			// Rejection sampling avoids bias in the alphabet indices.
			if byte < 248 { result << alphabet[int(byte) % alphabet.len] }
			if result.len == 32 { break
			 }
		}
	}
	return result.bytestr()
}

pub struct OneTimeTokenPlugin {
pub:
	options OneTimeTokenOptions
}

pub fn (_ OneTimeTokenPlugin) id() string {
	return 'one-time-token'
}

pub fn (_ OneTimeTokenPlugin) endpoints() []Endpoint {
	return [
		Endpoint{
			path:            '/one-time-token/generate'
			method:          'GET'
			require_session: true
			handler:         generate_one_time_token_endpoint
		},
		Endpoint{
			path:    '/one-time-token/verify'
			method:  'POST'
			handler: verify_one_time_token_endpoint
		},
	]
}

fn (a &Auth) one_time_token_options() !OneTimeTokenOptions {
	for plugin in a.config.plugins {
		if plugin is OneTimeTokenPlugin { return plugin.options }
	}
	return error('one-time-token plugin is not configured')
}

fn one_time_token_key(options OneTimeTokenOptions, token string) !string {
	stored := if options.store_token == 'hashed' {
		default_one_time_token_hasher(token)!
	} else if options.store_token == 'custom-hasher' {
		options.hash_token(token)!
	} else {
		token
	}
	return 'one-time-token:' + stored
}

fn (mut context EndpointContext) generate_one_time_token(session SessionResult) !string {
	options := context.auth.one_time_token_options()!
	token := options.generate_token(mut context, session)!
	expires := i64(f64(context.auth.clock_millis()) + options.expires_in * 60000)
	context.create_verification_value(Verification{
		identifier:        one_time_token_key(options, token)!
		value:             session.session.token
		expires_at:        expires / 1000
		expires_at_millis: expires
	})!
	return token
}

fn generate_one_time_token_endpoint(mut context EndpointContext, _ Request) !Response {
	options := context.auth.one_time_token_options()!
	if options.disable_client_request && context.auth.operation.request.request != none {
		return fail(400, 'BAD_REQUEST', 'Client requests are disabled')
	}
	session := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	return json_response({
		'token': context.generate_one_time_token(session)!
	})
}

fn verify_one_time_token_endpoint(mut context EndpointContext, request Request) !Response {
	fields := json2.decode[map[string]json2.Any](request.body) or {
		return fail(400, 'VALIDATION_ERROR', 'Invalid body')
	}
	token := fields['token'] or { return fail(400, 'VALIDATION_ERROR', 'token is required') }
	if token !is string { return fail(400, 'VALIDATION_ERROR', 'token must be a string') }
	options := context.auth.one_time_token_options()!
	value := context.consume_verification_value(one_time_token_key(options, token.str())!)!
	// Consumption precedes session lookup in upstream and remains burned when
	// the session is missing, revoked or expired, or a later operation fails.
	context.auth.commit_transaction()!
	context.auth.begin_transaction(false)!
	record := value.value or { return fail(400, 'BAD_REQUEST', 'Invalid token') }
	session := (context.auth.find_session_record(record.value)!).value or {
		return fail(400, 'BAD_REQUEST', 'Session not found')
	}

	if epoch_millis(session.session.expires_at)! < context.auth.clock_millis() {
		return fail(400, 'BAD_REQUEST', 'Session expired')
	}
	response := context.auth.session_response(session)
	if options.disable_set_session_cookie { return response }
	return context.auth.set_session_cookies(response, session)
}

fn (mut a Auth) one_time_token_new_session(response Response) !Response {
	session := a.operation.attempt.new_session or { return response }
	options := a.one_time_token_options() or { return response }
	if !options.set_ott_header_on_new_session { return response }
	mut context := EndpointContext{
		auth:    a
		session: session
	}
	token := context.generate_one_time_token(session)!
	mut exposed := []string{}
	mut headers := []Header{}
	for header in response.headers {
		if header.name.to_lower() == 'access-control-expose-headers' {
			for name in header.value.split(',') {
				if name.trim_space() != '' && name.trim_space() !in exposed {
					exposed << name.trim_space()
				}
			}
		} else {
			headers << header
		}
	}
	if 'set-ott' !in exposed { exposed << 'set-ott' }
	headers << [Header{'set-ott', token}, Header{'access-control-expose-headers', exposed.join(', ')}]
	return Response{
		...response
		headers: headers
	}
}
