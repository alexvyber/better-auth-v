module better_auth

import x.json2

pub fn (provider GoogleProvider) supports_id_token() bool {
	return !provider.disable_id_token_sign_in
}

pub fn google_id_token_key_request(token string) !Request {
	header := id_token_header(token)!
	if (header['alg'] or { json2.Any('') }) != json2.Any('RS256') {
		return error('Google ID tokens require RS256')
	}
	return Request{
		method: 'GET'
		url:    'https://www.googleapis.com/oauth2/v3/certs'
	}
}

fn google_id_token_keys(token string, jwks_json string) ![]string {
	header := id_token_header(token)!
	google_id_token_key_request(token)!
	jwks := json2.decode[map[string]json2.Any](jwks_json)!
	keys := jwks['keys'] or { return error('Keys not found') }
	if keys !is []json2.Any { return error('Invalid Google key set') }
	kid := header['kid'] or { json2.Any(json2.Null{}) }
	mut candidates := []string{}
	for key in keys.as_array() {
		if key !is map[string]json2.Any { return error('Invalid Google key') }
		if js_truthy(kid) && (key.as_map()['kid'] or { json2.Any(json2.Null{}) }) != kid { continue
		 }
		// Google imports every matching candidate before attempting signatures.
		// The trusted RS256 algorithm overrides optional JWK alg/use metadata.
		validate_id_token_jwk(key.json_str(), 'RS256')!
		candidates << key.json_str()
	}
	if candidates.len == 0 { return error('Google JWK not found') }
	return candidates
}

pub fn verify_google_id_token_jwks(token string, audiences []string, nonce string, jwks_json string, now i64, first_key_only bool) Lookup[string] {
	keys := google_id_token_keys(token, jwks_json) or { return Lookup[string]{} }
	config := IDTokenVerifyConfig{
		issuers:       ['https://accounts.google.com', 'accounts.google.com']
		audiences:     audiences
		algorithms:    ['RS256']
		max_token_age: f64(3600)
		nonce:         nonce
	}
	for index, key in keys {
		if first_key_only && index > 0 { break
		 }
		if payload := verify_id_token_with_jwk(token, key, config, now) {
			return Lookup[string]{
				value: payload
			}
		}
	}
	return Lookup[string]{}
}

pub fn verify_google_id_token(token string, audiences []string, nonce string, transport OAuthTransport, now i64) Lookup[string] {
	request := google_id_token_key_request(token) or { return Lookup[string]{} }
	response := transport.request(request) or { return Lookup[string]{} }
	if response.status < 200 || response.status >= 300 { return Lookup[string]{} }
	return verify_google_id_token_jwks(token, audiences, nonce, response.body, now, false)
}

pub fn (provider GoogleProvider) verify_id_token(token string, nonce string) Lookup[string] {
	if provider.disable_id_token_sign_in || !provider.audiences().any(it != '') {
		return Lookup[string]{}
	}
	request := google_id_token_key_request(token) or { return Lookup[string]{} }
	response := provider.transport.request(request) or { return Lookup[string]{} }
	if response.status < 200 || response.status >= 300 { return Lookup[string]{} }
	verified := verify_google_id_token_jwks(token, provider.audiences(), nonce, response.body,
		provider.clock_millis() / 1000, true)
	payload := verified.value or { return Lookup[string]{} }
	claims := json2.decode[map[string]json2.Any](payload) or { return Lookup[string]{} }
	if !google_hosted_domain_allowed(provider.hd, claims['hd'] or { json2.Any(json2.Null{}) }) {
		return Lookup[string]{}
	}
	return verified
}

pub fn (provider GoogleProvider) user_info(tokens OAuthTokens) !Lookup[OAuthIdentity] {
	if tokens.id_token == '' { return Lookup[OAuthIdentity]{} }
	parts := tokens.id_token.split('.')
	if parts.len != 3 { return error('Invalid Google profile token') }
	profile := json2.decode[map[string]json2.Any](decode_base64url(parts[1])!.bytestr())!
	if !google_hosted_domain_allowed(provider.hd, profile['hd'] or { json2.Any(json2.Null{}) }) {
		return Lookup[OAuthIdentity]{}
	}
	return Lookup[OAuthIdentity]{
		value: provider.mapped_identity(profile, tokens)!
	}
}

fn google_profile_identity(profile map[string]json2.Any, tokens OAuthTokens) OAuthIdentity {
	return OAuthIdentity{
		id:             if sub := profile['sub'] {
			if sub is string { sub } else { '' }
		} else {
			''
		}
		email:          (profile['email'] or { json2.Any('') }).str()
		email_verified: (profile['email_verified'] or { json2.Any(false) }) == json2.Any(true)
		name:           (profile['name'] or { json2.Any('') }).str()
		image:          if value := profile['picture'] {
			if value is string { ?string(value) } else { none }
		} else {
			none
		}
		profile:        profile
		tokens:         tokens
	}
}
