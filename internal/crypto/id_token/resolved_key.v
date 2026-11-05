module better_auth

import x.json2

// Platform facades serialize the key's actual type and algorithm together with
// its bytes. Re-importing only the bytes would lose CryptoKey hash/usage binding.
pub fn decode_id_token_resolved_key(encoded string, algorithm string) !string {
	fields := json2.decode[map[string]json2.Any](encoded)!
	key := fields['jwk'] or { return error('missing resolved ID token key') }
	if key !is map[string]json2.Any { return error('invalid resolved ID token key') }
	jwk := key.as_map()
	kind := (fields['kind'] or { json2.Any('') }).str()
	symmetric := algorithm in ['HS256', 'HS384', 'HS512']
	if kind in ['crypto', 'object'] {
		expected_type := if symmetric { 'secret' } else { 'public' }
		if (fields['type'] or { json2.Any('') }).str() != expected_type {
			return error('resolved ID token key has the wrong type')
		}
	}
	if kind == 'crypto' {
		metadata := (fields['algorithm'] or { return error('missing key algorithm') }).as_map()
		name := (metadata['name'] or { json2.Any('') }).str()
		expected_name := if symmetric {
			'HMAC'
		} else if algorithm.starts_with('RS') {
			'RSASSA-PKCS1-v1_5'
		} else if algorithm.starts_with('PS') {
			'RSA-PSS'
		} else if algorithm.starts_with('ES') {
			'ECDSA'
		} else {
			'Ed25519'
		}
		if name != expected_name { return error('resolved ID token key algorithm mismatch') }
		usages := fields['usages'] or { return error('missing key usages') }
		if usages !is []json2.Any || !usages.as_array().any(it == json2.Any('verify')) {
			return error('resolved ID token key does not permit verification')
		}
		if symmetric || algorithm.starts_with('RS') || algorithm.starts_with('PS') {
			hash := (metadata['hash'] or { return error('missing key hash') }).as_map()
			if (hash['name'] or { json2.Any('') }).str() != 'SHA-' + algorithm[2..] {
				return error('resolved ID token key hash mismatch')
			}
		}
		if algorithm.starts_with('ES') {
			if (metadata['namedCurve'] or { json2.Any('') }).str() != jwt_curve(algorithm) {
				return error('resolved ID token key curve mismatch')
			}
		}
	} else if kind == 'jwk' {
		if usage := jwk['use'] {
			if usage != json2.Any('sig') { return error('resolved JWK use is not sig') }
		}
		if alg := jwk['alg'] {
			if alg != json2.Any(algorithm) { return error('resolved JWK algorithm mismatch') }
		}
		if ops := jwk['key_ops'] {
			if ops !is []json2.Any || !ops.as_array().any(it == json2.Any('verify')) {
				return error('resolved JWK does not permit verification')
			}
		}
	} else if kind != 'object' && kind != 'bytes' {
		return error('invalid resolved ID token key kind')
	}
	if kind == 'bytes' && !symmetric { return error('byte key requires an HMAC algorithm') }
	return key.json_str()
}
