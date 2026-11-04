module better_auth

import math
import x.json2

pub fn encrypt_oauth_token(token string, secret SymmetricSecret, enabled bool) !string {
	if !enabled || token == '' { return token }
	return symmetric_encrypt(secret, token)
}

pub fn decrypt_oauth_token(token string, secret SymmetricSecret, enabled bool) !string {
	if !enabled || token == '' { return token }
	likely_encrypted := token.starts_with('$ba$')
		|| (token.len % 2 == 0 && token.bytes().all(it.is_hex_digit()))
	if !likely_encrypted { return token }
	return symmetric_decrypt(secret, token)
}

fn (a &Auth) account_cookie_name() string {
	return a.cookie_name_for('account_data')
}

fn pending_auth_cookie(response Response, base string) bool {
	return response.headers.any(it.name.to_lower() == 'set-cookie'
		&& (it.value.starts_with(base + '=') || it.value.starts_with(base + '.')))
}

fn with_unique_cookie(response Response, name string, value string) Response {
	return with_header(Response{
		...response
		headers: response.headers.filter(it.name.to_lower() != 'set-cookie'
			|| !it.value.starts_with(name + '='))
	}, 'set-cookie', value)
}

fn (a &Auth) clear_account_cookies(response Response) Response {
	base := a.account_cookie_name()
	mut result := Response{
		...response
		headers: response.headers.filter(it.name.to_lower() != 'set-cookie'
			|| (!it.value.starts_with(base + '=') && !it.value.starts_with(base + '.')))
	}
	result = with_unique_cookie(result, base, a.cache_cookie_header(base, '', i64(0)))
	for name, _ in cookie_values(a.request_context) {
		if cache_chunk_index(name, base) != none {
			result = with_unique_cookie(result, name, a.cache_cookie_header(name, '', i64(0)))
		}
	}
	return result
}

pub fn (a &Auth) get_account_cookie(context RequestContext) Lookup[string] {
	base := a.account_cookie_name()
	direct := cookie_values(context)[base] or { '' }
	value := get_chunked_cookie(context.headers['cookie'], base, direct) or {
		return Lookup[string]{}
	}
	decoded := symmetric_decode_jwt_rotating(value, a.secret_config, 'better-auth-account',
		a.config.clock()) or { return Lookup[string]{} }
	fields := json2.decode[json2.Any](decoded) or { return Lookup[string]{} }
	if fields !is map[string]json2.Any { return Lookup[string]{} }
	return Lookup[string]{
		value: decoded
	}
}

pub fn (a &Auth) set_account_cookie(response Response, payload_json string) !Response {
	fields := json2.decode[json2.Any](payload_json)!
	if fields !is map[string]json2.Any { return error('account cookie payload must be an object') }
	attributes := a.auth_cookie_factory().get_cookies()['accountData'].attributes
	configured_age := attributes['maxAge'] or { json2.Any(300) }
	lifetime := if configured_age is json2.Null { f64(0) } else { configured_age.f64() }
	data := symmetric_encode_jwt_rotating_with_lifetime(payload_json, a.secret_config,
		'better-auth-account', lifetime, a.config.clock())!
	age := if configured_age is json2.Null { ?i64(none) } else { ?i64(i64(math.floor(lifetime))) }
	base := a.account_cookie_name()
	mut result := a.clear_account_cookies(response)
	if base !in cookie_values(a.request_context) {
		result = Response{
			...result
			headers: result.headers.filter(it.name.to_lower() != 'set-cookie'
				|| !it.value.starts_with(base + '='))
		}
	}
	size := 4050 - a.cache_cookie_header(base + '.99', '', age).len
	if size <= 0 || data.len > size * 100 {
		a.config.log('warn',
			'Account cookie is too large to store even after chunking, so the cookie cache was skipped. Reduce the cached data size or avoid storing this data in cookies.')
		return result
	}
	// An initial write has no base expiry; cleanup only expires a base that was
	// present in the request or displaced by a chunked representation.
	if data.len <= size {
		return with_unique_cookie(result, base, a.cache_cookie_header(base, data, age))
	}
	for offset := 0; offset < data.len; offset += size {
		end := if offset + size < data.len { offset + size } else { data.len }
		name := '${base}.${offset / size}'
		result = with_unique_cookie(result, name,
			a.cache_cookie_header(name, data[offset..end], age))
	}
	return result
}

fn (a &Auth) sync_account_cookie(response Response, session SessionResult) !Response {
	if !a.config.store_account_cookie || pending_auth_cookie(response, a.account_cookie_name()) {
		return response
	}
	data := a.get_account_cookie(a.request_context).value or { return response }
	fields := json2.decode[map[string]json2.Any](data)!
	bind := a.config.account_cookie_bind_user or { !a.config.stateless_sessions }
	if bind && (fields['userId'] or { json2.Any(json2.Null{}) }) != json2.Any(session.user.id) {
		return a.clear_account_cookies(response)
	}
	return a.set_account_cookie(response, data)
}

fn (a &Auth) oauth_account_patch(tokens OAuthTokens, stored_scope string) !map[string]json2.Any {
	mut patch := map[string]json2.Any{}
	if token := tokens.access_token {
		patch['accessToken'] = encrypt_oauth_token(token, a.secret_config,
			a.config.encrypt_oauth_tokens)!
	}
	if token := tokens.refresh_token {
		patch['refreshToken'] = encrypt_oauth_token(token, a.secret_config,
			a.config.encrypt_oauth_tokens)!
	}
	if tokens.id_token != '' { patch['idToken'] = tokens.id_token }
	if date := tokens.access_token_expires_at { patch['accessTokenExpiresAt'] = date }
	if date := tokens.refresh_token_expires_at { patch['refreshTokenExpiresAt'] = date }
	if scope := tokens.scope { patch['scope'] = merge_oauth_scopes(stored_scope, scope.split(',')) }
	return patch
}
