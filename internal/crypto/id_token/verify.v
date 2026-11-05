module better_auth

import crypto.ed25519
import crypto.hmac
import crypto.sha256
import encoding.hex
import x.json2

pub struct IDTokenVerifyConfig {
pub:
	issuers            []string
	issuer_required    bool
	audiences          []string
	algorithms         []string
	required_claims    []string = ['iss', 'sub', 'aud', 'exp', 'iat']
	clock_tolerance    f64      = 30
	max_token_age      ?f64
	max_token_age_text ?string
	nonce              string
	nonce_comparison   string = 'exact'
}

fn id_token_header(token string) !map[string]json2.Any {
	parts := token.split('.')
	if parts.len != 3 { return error('invalid compact ID token') }
	return json2.decode[map[string]json2.Any](decode_base64url(parts[0])!.bytestr())
}

fn validate_id_token_jwk(encoded string, algorithm string) ! {
	key := json2.decode[map[string]json2.Any](encoded)!
	if ext := key['ext'] {
		if ext !is bool { return error('invalid JWK extractability') }
	}
	kind := (key['kty'] or { json2.Any('') }).str()
	if operations := key['key_ops'] {
		if operations !is []json2.Any { return error('invalid JWK operations') }
		mut seen := []string{}
		for operation in operations.as_array() {
			if operation !is string || operation.str() in seen {
				return error('invalid JWK operations')
			}
			seen << operation.str()
		}
		if kind != 'oct' && seen != ['verify'] { return error('JWK does not permit verification') }
	}
	if kind == 'oct' {
		if algorithm !in ['HS256', 'HS384', 'HS512'] {
			return error('invalid symmetric ID-token key algorithm')
		}
		decode_base64url((key['k'] or { return error('missing symmetric key') }).str())!
		return
	}
	if 'd' in key { return error('ID-token verification requires a public key') }
	validate_jwk_shape(algorithm, encoded)!
	fields := if kind == 'RSA' {
		['n', 'e']
	} else if kind == 'EC' {
		['x', 'y']
	} else {
		['x']
	}
	for field in fields {
		value := key[field] or { return error('missing public key field') }
		if value !is string { return error('invalid public key field') }
		if decode_base64url(value.str())!.len == 0 { return error('empty public key field') }
	}
}

fn validate_id_token_header(header map[string]json2.Any, config IDTokenVerifyConfig) !string {
	algorithm := header['alg'] or { return error('missing ID-token algorithm') }
	if algorithm !is string || algorithm.str() !in config.algorithms {
		return error('ID-token algorithm not allowed')
	}
	if crit := header['crit'] {
		if crit !is []json2.Any { return error('invalid critical header') }
		items := crit.as_array()
		if items.len != 1 || items[0] != json2.Any('b64')
			|| (header['b64'] or { json2.Any(false) }) != json2.Any(true) {
			return error('unsupported critical ID-token header')
		}
	}
	return algorithm.str()
}

pub fn verify_id_token_with_jwk(token string, key_json string, config IDTokenVerifyConfig, now i64) !string {
	if !config.audiences.any(it != '') { return error('ID token audience is not configured') }
	header := id_token_header(token)!
	algorithm := validate_id_token_header(header, config)!
	validate_id_token_jwk(key_json, algorithm)!
	parts := token.split('.')
	signature := decode_base64url(parts[2])!
	message := (parts[0] + '.' + parts[1]).bytes()
	key := json2.decode[map[string]json2.Any](key_json)!
	if algorithm.starts_with('RS') || algorithm.starts_with('PS') {
		modulus := decode_base64url((key['n'] or { return error('missing RSA modulus') }).str())!
		mut start := 0
		for start < modulus.len && modulus[start] == 0 {
			start++
		}
		mut bits := (modulus.len - start) * 8
		if start < modulus.len {
			mut first := modulus[start]
			for first < 128 {
				bits--
				first <<= 1
			}
		}
		if bits < 2048 { return error('ID token RSA key must have at least 2048 bits') }
	}
	mut valid := false
	if (key['kty'] or { json2.Any('') }).str() == 'oct' {
		bytes := decode_base64url((key['k'] or { return error('missing symmetric key') }).str())!
		valid = hmac.equal(cookie_reader_hmac(algorithm, bytes, message)!, signature)
	} else if algorithm == 'EdDSA' {
		bytes := decode_base64url((key['x'] or { return error('missing public key') }).str())!
		if bytes.len != ed25519.public_key_size { return error('invalid Ed25519 key') }
		valid = ed25519.verify(ed25519.PublicKey(bytes), message, signature)!
	} else {
		valid = openssl_verify(algorithm, key_json, message, signature)!
	}
	if !valid { return error('invalid ID-token signature') }
	claims := json2.decode[map[string]json2.Any](decode_base64url(parts[1])!.bytestr())!
	for required in config.required_claims {
		if required !in claims { return error('missing required ID-token claim ${required}') }
	}
	if config.issuer_required || config.issuers.len > 0 {
		issuer := claims['iss'] or { return error('missing ID-token issuer') }
		if issuer !is string || issuer.str() !in config.issuers {
			return error('ID-token issuer mismatch')
		}
	}
	if !audience_matches(claims['aud'] or { json2.Any(json2.Null{}) }, config.audiences) {
		return error('ID-token audience mismatch')
	}
	if 'exp' in claims && numeric_date_field(claims, 'exp')! <= f64(now) - config.clock_tolerance {
		return error('expired ID token')
	}
	if 'nbf' in claims && numeric_date_field(claims, 'nbf')! > f64(now) + config.clock_tolerance {
		return error('ID token not yet valid')
	}
	if 'iat' in claims { numeric_date_field(claims, 'iat')! }
	maximum := if text := config.max_token_age_text {
		?f64(id_token_duration_seconds(text)!)
	} else {
		config.max_token_age
	}
	if age := maximum {
		issued := numeric_date_field(claims, 'iat')!
		elapsed := f64(now) - issued
		if elapsed - config.clock_tolerance > age { return error('ID token is too old') }
		if elapsed < -config.clock_tolerance { return error('ID-token iat is in the future') }
	}
	if config.nonce != '' {
		nonce := claims['nonce'] or { return error('missing ID-token nonce') }
		if nonce !is string { return error('invalid ID-token nonce') }
		hashed := hex.encode(sha256.sum(config.nonce.bytes()))
		if nonce.str() != config.nonce && !(config.nonce_comparison == 'exact-or-sha256'
			&& nonce.str() == hashed) {
			return error('ID-token nonce mismatch')
		}
	}
	return json2.Any(claims).json_str()
}
