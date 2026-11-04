module better_auth

import crypto.hmac
import crypto.sha256
import encoding.base64
import json
import net.urllib
import strconv
import x.json2

struct CachedSession {
	result     SessionResult
	expires_at i64
	version    string
}

fn resolve_cache_defaults(config Config) Config {
	cache := config.cookie_cache
	stateless := config.stateless_sessions && config.secondary_storage is NoSecondaryStorage
	max_age := if cache.max_age != 0 {
		cache.max_age
	} else if stateless {
		config.session_expires_in
	} else {
		i64(300)
	}
	refresh := cache.refresh_cache or { stateless }
	if refresh && !stateless {
		config.log('warn',
			'Cookie cache refresh is disabled when a server-side session store is configured')
	}
	return Config{
		...config
		cookie_cache: CookieCacheConfig{
			...cache
			enabled:       cache.enabled or { stateless }
			strategy:      if cache.strategy != '' {
				cache.strategy
			} else if stateless {
				'jwe'
			} else {
				'compact'
			}
			max_age:       max_age
			refresh_cache: refresh && stateless
			update_age:    cache.update_age or { max_age / 5 }
		}
	}
}

fn base64url(data []u8) string {
	return base64.url_encode(data).trim_right('=')
}

fn decode_base64url(value string) ![]u8 {
	for ch in value.bytes() {
		if !(ch >= `A` && ch <= `Z`) && !(ch >= `a` && ch <= `z`) && !(ch >= `0` && ch <= `9`)
			&& ch !in [`-`, `_`] {
			return error('invalid base64url character')
		}
	}
	decoded := base64.url_decode(value)
	if base64url(decoded) != value { return error('noncanonical base64url') }
	return decoded
}

fn (a &Auth) cache_mac(data string) string {
	return base64url(hmac.new(a.config.secret.bytes(), data.bytes(), sha256.sum, sha256.block_size))
}

fn (a &Auth) cache_version(result SessionResult) !string {
	if a.config.cookie_cache.version_for != default_cache_version {
		return a.config.cookie_cache.version_for(result.session, result.user)
	}
	return a.config.cookie_cache.version
}

fn (mut a Auth) encode_cookie_cache(result SessionResult) !string {
	version := a.cache_version(result)!
	now := a.config.clock()
	lifetime := if result.session.persistent { a.config.cookie_cache.max_age } else { i64(60) }
	payload :=
		js_json(json2.decode[json2.Any]('{"session":${a.session_json(result.session)},"user":${a.user_json(result.user)},"updatedAt":${a.clock_millis()},"version":${json.encode(version)}}')!)
	if a.config.cookie_cache.strategy == 'jwe' {
		return symmetric_encode_jwt_rotating(payload, a.secret_config, 'better-auth-session',
			a.config.cookie_cache.max_age, now)
	}
	if a.config.cookie_cache.strategy == 'jwt' {
		if a.jwks_cache_enabled() {
			return a.sign_jwks_payload(json2.decode[map[string]json2.Any](payload)!,
				'better-auth.session-cache+jwt', true)
		}
		header := base64url('{"alg":"HS256"}'.bytes())
		claims := payload[..payload.len - 1] + ',"iat":${now},"exp":${now +
			a.config.cookie_cache.max_age}}'
		input := header + '.' + base64url(claims.bytes())
		return input + '.' + a.cache_mac(input)
	}
	expires := a.clock_millis() + lifetime * 1000
	signed := payload[..payload.len - 1] + ',"expiresAt":${expires}}'
	return base64url('{"session":${payload},"expiresAt":${expires},"signature":${json.encode(a.cache_mac(signed))}}'.bytes())
}

fn numeric_date_field(fields map[string]json2.Any, name string) !f64 {
	value := fields[name] or { return error('missing numeric claim') }
	if value !is i64 && value !is int && value !is f64 { return error('invalid numeric claim') }
	return value.f64()
}

fn numeric_field(fields map[string]json2.Any, name string) !i64 {
	value := fields[name] or { return error('missing numeric claim') }
	if value !is i64 && value !is int && value !is f64 { return error('invalid numeric claim') }
	return value.i64()
}

fn (mut a Auth) decode_cookie_cache(value string) !CachedSession {
	mut payload := map[string]json2.Any{}
	mut expires := i64(0)
	if a.config.cookie_cache.strategy == 'jwe' {
		payload = json2.decode[map[string]json2.Any](symmetric_decode_jwt_rotating(value,
			a.secret_config, 'better-auth-session', a.config.clock())!)!
		expires = numeric_field(payload, 'exp')! * 1000
	} else if a.config.cookie_cache.strategy == 'jwt' {
		if a.jwks_cache_enabled() {
			payload = a.verify_jwks_payload(value, true, '')!
			expires = numeric_field(payload, 'exp')! * 1000
		} else {
			parts := value.split('.')
			if parts.len != 3 { return error('invalid JWT') }
			header := json2.decode[map[string]json2.Any](base64.url_decode(parts[0]).bytestr())!
			if (header['alg'] or { json2.Any('') }).str() != 'HS256' || 'crit' in header {
				return error('unsupported JWT header')
			}
			if !hmac.equal(a.cache_mac(parts[0] + '.' + parts[1]).bytes(), parts[2].bytes()) {
				return error('invalid JWT signature')
			}
			payload = json2.decode[map[string]json2.Any](base64.url_decode(parts[1]).bytestr())!
			expires = numeric_field(payload, 'exp')! * 1000
			if expires <= a.config.clock() * 1000 { return error('expired JWT') }
			if 'nbf' in payload && numeric_field(payload, 'nbf')! > a.config.clock() {
				return error('JWT not yet valid')
			}
		}
	} else {
		outer := json2.decode[map[string]json2.Any](base64.url_decode(value).bytestr())!
		payload = (outer['session'] or { return error('missing payload') }).as_map()
		expires = numeric_field(outer, 'expiresAt')!
		encoded := js_json(json2.Any(payload))
		signed := encoded[..encoded.len - 1] + ',"expiresAt":${expires}}'
		signature := (outer['signature'] or { return error('missing signature') }).str()
		if !hmac.equal(a.cache_mac(signed).bytes(), signature.bytes()) {
			return error('invalid cache signature')
		}
	}
	result := decode_session_result(json2.Any(payload).json_str())!
	if result.session.id == '' || result.user.id == '' || result.session.user_id != result.user.id
		|| result.session.token == '' {
		return error('malformed session cache')
	}
	epoch(result.session.created_at)!
	epoch(result.session.updated_at)!
	epoch(result.user.created_at)!
	epoch(result.user.updated_at)!
	epoch(result.session.expires_at)!
	version := if item := payload['version'] { item.str() } else { '1' }
	return CachedSession{
		result:     result
		expires_at: expires
		version:    version
	}
}

fn (a &Auth) cache_cookie_name() string {
	return a.cookie_name_for('session_data')
}

fn cookie_values(ctx RequestContext) map[string]string {
	mut values := map[string]string{}
	for item in ctx.headers['cookie'].split(';') {
		name, value := item.trim_space().split_once('=') or { continue }
		if name !in values { values[name] = urllib.path_unescape(value) or { continue } }
	}
	return values
}

fn cache_chunk_index(name string, base string) ?int {
	if !name.starts_with(base + '.') { return none }
	suffix := name[base.len + 1..]
	index := strconv.atoi(suffix) or { return none }
	if index < 0 || index.str() != suffix { return none }
	return index
}

fn (a &Auth) cache_cookie(ctx RequestContext) ?string {
	values := cookie_values(ctx)
	base := a.cache_cookie_name()
	if value := values[base] {
		if value != '' { return value }
	}
	mut indices := []int{}
	for name, _ in values {
		if index := cache_chunk_index(name, base) { indices << index }
	}
	if indices.len == 0 || indices.len > 100 { return none }
	indices.sort()
	mut combined := ''
	for index in indices {
		combined += values['${base}.${index}']
	}
	return combined
}

fn (a &Auth) cache_cookie_header(name string, value string, max_age ?i64) string {
	return a.cookie_header(name, value, '/', max_age)
}

fn (a &Auth) clear_cache_cookie(response Response) Response {
	mut result := response
	base := a.cache_cookie_name()
	for name, _ in cookie_values(a.request_context) {
		if name == base || cache_chunk_index(name, base) != none {
			result = with_header(result, 'set-cookie', a.cache_cookie_header(name, '', i64(0)))
		}
	}
	return result
}

fn (mut a Auth) set_cache_cookie(response Response, current SessionResult) !Response {
	if !(a.config.cookie_cache.enabled or { false }) { return a.clear_cache_cookie(response) }
	data := a.encode_cookie_cache(current)!
	base := a.cache_cookie_name()
	age := if current.session.persistent { ?i64(a.config.cookie_cache.max_age) } else { none }
	chunk_size := 4050 - a.cache_cookie_header(base + '.99', '', age).len
	mut result := a.clear_cache_cookie(response)
	if chunk_size <= 0 || data.len > chunk_size * 100 {
		a.config.log('warn', 'Session cookie is too large; cookie cache skipped')
		return result
	}
	if data.len <= chunk_size {
		return with_header(result, 'set-cookie', a.cache_cookie_header(base, data, age))
	}
	for offset := 0; offset < data.len; offset += chunk_size {
		end := if offset + chunk_size < data.len { offset + chunk_size } else { data.len }
		result = with_header(result, 'set-cookie', a.cache_cookie_header('${base}.${offset / chunk_size}',
			data[offset..end], age))
	}
	return result
}

fn (mut a Auth) set_session_cookies(response Response, current SessionResult) !Response {
	return a.set_cache_cookie(a.set_cookie(response, current.session.token,
		current.session.persistent), current)
}

fn (mut a Auth) cached_session(ctx RequestContext) !Lookup[CachedSession] {
	if !(a.config.cookie_cache.enabled or { false }) { return Lookup[CachedSession]{} }
	token := a.context_token(ctx) or { return Lookup[CachedSession]{} }
	encoded := a.cache_cookie(ctx) or { return Lookup[CachedSession]{} }
	decoded := a.decode_cookie_cache(encoded) or { return Lookup[CachedSession]{} }
	marker := cookie_values(ctx)[a.cookie_name_for('dont_remember')]
	persistent := (a.verify_signed_value(marker) or { '' }) != 'true'
	cached := CachedSession{
		...decoded
		result: SessionResult{
			...decoded.result
			session: Session{
				...decoded.result.session
				persistent: persistent
			}
		}
	}
	if cached.result.session.token != token || cached.expires_at < a.clock_millis()
		|| epoch_millis(cached.result.session.expires_at)! < a.clock_millis()
		|| cached.version != a.cache_version(cached.result)! {
		return Lookup[CachedSession]{}
	}
	return Lookup[CachedSession]{
		value: cached
	}
}
