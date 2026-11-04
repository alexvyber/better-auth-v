module better_auth

import crypto.ed25519
import crypto.hmac
import crypto.sha256
import crypto.sha512
import encoding.base64
import os
import time
import x.json2

pub struct CookieCacheReadConfig {
pub:
	cookie_prefix string = 'better-auth'
	cookie_name   string = 'session_data'
	is_secure     ?bool
	secret        string
	strategy      string = 'compact'
	jwt_jwks_json ?string
	jwt_issuer    ?string
	jwt_audience  string = 'better-auth:session-cache'
	version       ?string
	version_for   fn (string) !string = no_cookie_reader_version @[skip]
	clock_millis  fn () i64           = cookie_reader_clock           @[skip]
	log           fn (string, string) = discard_log @[skip]
}

fn no_cookie_reader_version(_ string) !string {
	return error('cookie cache version callback is not configured')
}

fn cookie_reader_clock() i64 {
	return time.now().unix_milli()
}

// A verified and schema-checked snapshot. A staged reader allows application
// version callbacks to run before final expiry checks, just like a direct read.
pub struct CookieCacheSnapshot {
pub:
	payload_json       string
	compact_expires_at ?f64
}

struct CookieReaderChunk {
	index    f64
	position int
	value    string
}

fn cookie_reader_value(header string, config CookieCacheReadConfig) ?string {
	secure := config.is_secure or { os.getenv('NODE_ENV') == 'production' }
	name := (if secure { secure_cookie_prefix } else { '' }) + config.cookie_prefix + '.' +
		config.cookie_name
	cookies := parse_cookies(header)
	if value := cookies[name] {
		if value != '' { return value }
	}
	mut chunks := []CookieReaderChunk{}
	for key, value in cookies {
		if !key.starts_with(name + '.') { continue
		 }
		suffix := key.all_after_last('.')
		if index := cookie_max_age(if suffix == '' { '0' } else { suffix }) {
			chunks << CookieReaderChunk{index, chunks.len, value}
		}
	}
	if chunks.len == 0 { return none }
	chunks.sort_with_compare(fn (a &CookieReaderChunk, b &CookieReaderChunk) int {
		if a.index < b.index { return -1 }
		if a.index > b.index { return 1 }
		return a.position - b.position
	})
	value := chunks.map(it.value).join('')
	return if value == '' { none } else { ?string(value) }
}

fn cookie_reader_date(input json2.Any) !i64 {
	if input !is string { return error('invalid cached date') }
	value := input.str()
	// safeJSONParse revives only this UTC ISO shape; z.date rejects all other
	// strings and numeric timestamps rather than coercing them into dates.
	if value.len < 20 || value[4] != `-` || value[7] != `-` || value[10] != `T` || value[13] != `:`
		|| value[16] != `:` || !value.ends_with('Z') {
		return error('invalid cached ISO date')
	}
	for i, ch in value.bytes() {
		if i in [4, 7, 10, 13, 16, value.len - 1] { continue
		 }
		if i == 19 && ch == `.` && value.len > 21 { continue
		 }
		if !ch.is_digit() { return error('invalid cached ISO date') }
	}
	return epoch_millis(value)
}

fn cookie_reader_string(value json2.Any) string {
	return match value {
		json2.Null { 'null' }
		map[string]json2.Any { '[object Object]' }
		[]json2.Any { value.map(if it is json2.Null { '' } else { cookie_reader_string(it) }).join(',') }
		string { value }
		else { js_json(value) }
	}
}

fn parse_cookie_reader_payload(input json2.Any, now_millis i64) !map[string]json2.Any {
	if input !is map[string]json2.Any { return error('invalid cache payload') }
	mut payload := input.as_map().clone()
	numeric_date_field(payload, 'updatedAt')!
	if version := payload['version'] {
		if version !is string { return error('invalid cache version') }
		if _ := cookie_reader_date(version) { return error('cached version revived to a Date') }
	}
	for kind in ['session', 'user'] {
		item := payload[kind] or { return error('missing cache identity') }
		if item !is map[string]json2.Any { return error('invalid cache identity') }
		mut fields := item.as_map().clone()
		required_strings := if kind == 'user' {
			['id', 'email', 'name']
		} else {
			['id', 'token']
		}
		for key in required_strings {
			value := fields[key] or { return error('missing cache field') }
			if value !is string { return error('invalid cache string') }
			if _ := cookie_reader_date(value) { return error('cached string revived to a Date') }
		}
		for key in ['createdAt', 'updatedAt'] {
			if value := fields[key] {
				cookie_reader_date(value)!
			} else {
				fields[key] = stamp_millis(now_millis)
			}
		}
		optional_strings := if kind == 'user' {
			['image']
		} else {
			['ipAddress', 'userAgent']
		}
		for key in optional_strings {
			if value := fields[key] {
				if value !is string && value !is json2.Null {
					return error('invalid optional cache string')
				}
				if _ := cookie_reader_date(value) {
					return error('cached optional string revived to a Date')
				}
			}
		}
		if kind == 'user' {
			fields['email'] = (fields['email'] or { json2.Any('') }).str().to_lower()
			if verified := fields['emailVerified'] {
				if verified !is bool { return error('invalid cache emailVerified') }
			} else {
				fields['emailVerified'] = false
			}
		} else {
			fields['userId'] = if id := fields['userId'] {
				cookie_reader_string(id)
			} else {
				'undefined'
			}
			cookie_reader_date(fields['expiresAt'] or { return error('missing cache expiry') })!
		}
		payload[kind] = fields
	}
	return payload
}

fn cookie_reader_hmac(algorithm string, key []u8, input []u8) ![]u8 {
	return match algorithm {
		'HS256' { hmac.new(key, input, sha256.sum, sha256.block_size) }
		'HS384' { hmac.new(key, input, sha512.sum384, sha512.block_size) }
		'HS512' { hmac.new(key, input, sha512.sum512, sha512.block_size) }
		else { return error('unsupported HMAC JWT algorithm') }
	}
}

fn cookie_reader_jwt(token string, secret string, config CookieCacheReadConfig, now_millis i64) !map[string]json2.Any {
	parts := token.split('.')
	if parts.len != 3 { return error('invalid cache JWT') }
	header := json2.decode[map[string]json2.Any](decode_base64url(parts[0])!.bytestr())!
	if 'crit' in header { return error('unsupported critical JWT header') }
	alg := (header['alg'] or { return error('missing cache JWT algorithm') }).str()
	signature := decode_base64url(parts[2])!
	message := (parts[0] + '.' + parts[1]).bytes()
	mut tolerance := i64(0)
	if jwks_json := config.jwt_jwks_json {
		tolerance = 15
		if (header['typ'] or { json2.Any('') }).str() != 'better-auth.session-cache+jwt' {
			return error('invalid cache JWT type')
		}
		kid := header['kid'] or { return error('missing cache JWT kid') }
		if kid !is string || kid.str() == '' { return error('invalid cache JWT kid') }
		jwks := json2.decode[map[string]json2.Any](jwks_json)!
		keys := (jwks['keys'] or { return error('missing JWKS keys') }).as_array()
		mut selected := ?map[string]json2.Any(none)
		for entry in keys {
			if entry is map[string]json2.Any {
				if (entry['kid'] or { json2.Any(json2.Null{}) }) == kid {
					selected = entry.clone()
					break
				}
			}
		}
		key := selected or { return error('unknown cache JWT kid') }.clone()
		key_alg := if candidate := key['alg'] {
			if candidate is json2.Null { alg } else { candidate.str() }
		} else {
			alg
		}
		if key_alg != alg { return error('cache JWT algorithm mismatch') }
		kind := (key['kty'] or { json2.Any('') }).str()
		if ext := key['ext'] {
			if ext !is bool { return error('invalid JWK extractability') }
		}
		if operations := key['key_ops'] {
			if operations !is []json2.Any { return error('invalid JWK operations') }
			mut seen := []string{}
			for operation in operations.as_array() {
				if operation !is string || operation.str() in seen {
					return error('invalid JWK operations')
				}
				seen << operation.str()
			}
			if kind != 'oct' && seen != ['verify'] {
				return error('JWK does not permit verification')
			}
		}
		if kind == 'oct' {
			key_bytes :=
				decode_base64url((key['k'] or { return error('missing symmetric JWK') }).str())!
			if !hmac.equal(cookie_reader_hmac(alg, key_bytes, message)!, signature) {
				return error('invalid cache JWT signature')
			}
		} else {
			if 'd' in key { return error('private JWK cannot verify JWTs') }
			validate_jwk_shape(alg, json2.Any(key).json_str())!
			if alg == 'EdDSA' {
				x := decode_base64url((key['x'] or { return error('missing public key') }).str())!
				if x.len != ed25519.public_key_size { return error('invalid Ed25519 public key') }
				if !ed25519.verify(ed25519.PublicKey(x), message, signature)! {
					return error('invalid cache JWT signature')
				}
			} else {
				if !openssl_verify(alg, json2.Any(key).json_str(), message, signature)! {
					return error('invalid cache JWT signature')
				}
			}
		}
	} else {
		if !hmac.equal(cookie_reader_hmac(alg, secret.bytes(), message)!, signature) {
			return error('invalid cache JWT signature')
		}
	}
	claims := json2.decode[map[string]json2.Any](decode_base64url(parts[1])!.bytestr())!
	now := f64(now_millis / 1000)
	if 'exp' in claims && numeric_date_field(claims, 'exp')! <= now - tolerance {
		return error('expired cache JWT')
	}
	if 'nbf' in claims && numeric_date_field(claims, 'nbf')! > now + tolerance {
		return error('cache JWT not yet valid')
	}
	if 'iat' in claims { numeric_date_field(claims, 'iat')! }
	if config.jwt_jwks_json != none {
		if issuer := config.jwt_issuer {
			if issuer != '' && (claims['iss'] or { json2.Any(json2.Null{}) }) != json2.Any(issuer) {
				return error('cache JWT issuer mismatch')
			}
		}
		iss := claims['iss'] or { return error('missing cache JWT issuer') }
		if iss !is string || iss.str() == '' { return error('invalid cache JWT issuer') }
		if !audience_matches(claims['aud'] or { json2.Any(json2.Null{}) }, [
			config.jwt_audience,
		]) {
			return error('cache JWT audience mismatch')
		}
	}
	return claims
}

// Missing credentials are configuration errors; malformed/untrusted snapshots
// are ordinary cache misses. No database or session-token cookie is required.
pub fn open_cookie_cache(header string, config CookieCacheReadConfig, now_millis i64) !Lookup[CookieCacheSnapshot] {
	value := cookie_reader_value(header, config) or { return Lookup[CookieCacheSnapshot]{} }
	secret := if config.secret != '' { config.secret } else { os.getenv('BETTER_AUTH_SECRET') }
	if secret == '' && !(config.strategy == 'jwt' && config.jwt_jwks_json != none) {
		return error('getCookieCache requires a secret to be provided. Either pass it as an option or set the BETTER_AUTH_SECRET environment variable')
	}
	decoded := decode_cookie_reader(value, secret, config, now_millis) or {
		return Lookup[CookieCacheSnapshot]{}
	}
	return Lookup[CookieCacheSnapshot]{
		value: decoded
	}
}

fn decode_cookie_reader(value string, secret string, config CookieCacheReadConfig, now_millis i64) !CookieCacheSnapshot {
	mut expiry := ?f64(none)
	mut raw := json2.Any(json2.Null{})
	if config.strategy == 'jwt' {
		raw = cookie_reader_jwt(value, secret, config, now_millis)!
	} else if config.strategy == 'jwe' {
		raw = json2.decode[json2.Any](symmetric_decode_jwt(value, secret, 'better-auth-session',
			now_millis / 1000)!)!
	} else {
		outer := json2.decode[map[string]json2.Any](base64.url_decode(value).bytestr())!
		expires := numeric_date_field(outer, 'expiresAt')!
		raw = outer['session'] or { return error('missing compact payload') }
		if raw !is map[string]json2.Any { return error('invalid compact payload') }
		mut signed := raw.as_map().clone()
		signed['expiresAt'] = expires
		signature := outer['signature'] or { return error('missing compact signature') }
		if signature !is string { return error('invalid compact signature') }
		expected := base64url(cookie_reader_hmac('HS256', secret.bytes(),
			js_json(json2.Any(signed)).bytes())!)
		if !hmac.equal(expected.bytes(), signature.str().bytes()) {
			return error('invalid compact signature')
		}
		expiry = expires
	}
	payload := parse_cookie_reader_payload(raw, now_millis) or {
		config.log('warn', 'Cookie cache payload failed schema validation')
		return err
	}
	if config.strategy == 'jwt' && config.jwt_jwks_json != none {
		user := (payload['user'] or { json2.Any(map[string]json2.Any{}) }).as_map()
		session := (payload['session'] or { json2.Any(map[string]json2.Any{}) }).as_map()
		if (payload['sub'] or { json2.Any(json2.Null{}) }) != (user['id'] or { json2.Any('') }) || (payload['sid'] or {
			json2.Any(json2.Null{})
		}) != (session['token'] or { json2.Any('') }) {
			return error('cache JWT identity mismatch')
		}
	}
	return CookieCacheSnapshot{
		payload_json:       json2.Any(payload).json_str()
		compact_expires_at: expiry
	}
}

pub fn finish_cookie_cache(snapshot CookieCacheSnapshot, expected_version ?string, now_millis i64) !Lookup[string] {
	payload := json2.decode[map[string]json2.Any](snapshot.payload_json)!
	if expected := expected_version {
		version := (payload['version'] or { json2.Any('1') }).str()
		if (if version == '' {
			'1'
		} else {
			version
		}) != expected {
			return Lookup[string]{}
		}
	}
	if expires := snapshot.compact_expires_at {
		if expires < now_millis { return Lookup[string]{} }
	}
	session := (payload['session'] or { return error('missing cached session') }).as_map()
	if cookie_reader_date(session['expiresAt'] or { return error('missing cached expiry') })! < now_millis {
		return Lookup[string]{}
	}
	return Lookup[string]{
		value: snapshot.payload_json
	}
}

pub fn get_cookie_cache(header string, config CookieCacheReadConfig) !Lookup[string] {
	opened := open_cookie_cache(header, config, config.clock_millis())!
	snapshot := opened.value or { return Lookup[string]{} }
	expected := if config.version_for != no_cookie_reader_version {
		?string(config.version_for(snapshot.payload_json)!)
	} else if version := config.version {
		if version == '' { none } else { ?string(version) }
	} else {
		none
	}
	return finish_cookie_cache(snapshot, expected, config.clock_millis())
}
