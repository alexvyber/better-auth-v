module better_auth

import math
import time
import x.json2

fn valid_cookie_name(name string) bool {
	if name == '' { return false }
	for value in name.bytes() {
		if value <= 32 || value >= 127
			|| value in [`(`, `)`, `<`, `>`, `@`, `,`, `;`, `:`, `\\`, `"`, `/`, `[`, `]`, `?`, `=`, `{`, `}`] {
			return false
		}
	}
	return true
}

fn validate_cookie_config(config Config) ! {
	validate_cookie_attributes(config.default_cookie_attributes)!
	for _, attributes in config.cookie_attributes {
		validate_cookie_attributes(attributes)!
	}
	if config.cookie_prefix != '' && !valid_cookie_name(config.cookie_prefix) {
		return error('invalid cookie prefix')
	}
	for _, name in config.cookie_names {
		if name != '' && !valid_cookie_name(name) { return error('invalid cookie name') }
	}
	if config.cross_subdomain_cookies {
		if config.cookie_domain == '' && config.base_url == '' {
			return error('baseURL is required when crossSubdomainCookies are enabled.')
		}
		if config.cookie_domain != '' {
			domain := config.cookie_domain.trim_left('.')
			if domain == '' || !domain.bytes().all(it.is_alnum() || it in [`-`, `.`, `:`]) {
				return error('invalid cookie domain')
			}
		}
	}
}

fn validate_cookie_attributes(attributes map[string]json2.Any) ! {
	for key, value in attributes {
		if value is json2.Null { continue
		 }
		if key in ['secure', 'httpOnly', 'partitioned'] && value !is bool {
			return error('invalid cookie attribute ${key}')
		}
		if key in ['domain', 'path', 'sameSite', 'prefix', 'expires'] {
			if value !is string { return error('invalid cookie attribute ${key}') }
			if value.str().bytes().any(it < 32 || it == 127) {
				return error('invalid cookie attribute ${key}')
			}
			if key == 'expires' { time.parse_rfc3339(value.str()) or {
					return error('invalid cookie expiry')} }
		}
		if key == 'maxAge' {
			if value !is int && value !is i64 && value !is f64 {
				return error('invalid cookie maxAge')
			}
			if math.is_nan(value.f64()) || math.is_inf(value.f64(), 0) || value.f64() > 34560000 {
				return error('Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.')
			}
		}
	}
}

fn (a &Auth) cookie_secure() bool {
	return a.auth_cookie_factory().secure()
}

fn (a &Auth) auth_cookie_factory() CookieFactory {
	return CookieFactory{
		base_url:                if a.config.cross_subdomain_cookies {
			a.base_url()
		} else {
			a.config.base_url
		}
		production:              a.production_cookie_default
		cookie_prefix:           a.config.cookie_prefix
		cookie_names:            a.config.cookie_names
		secure_cookies:          a.config.secure_cookies
		cross_subdomain_cookies: a.config.cross_subdomain_cookies
		cookie_domain:           a.config.cookie_domain
		default_attributes:      a.config.default_cookie_attributes
		cookie_attributes:       a.config.cookie_attributes
		session_max_age:         f64(a.config.session_expires_in)
		cache_max_age:           f64(a.config.cookie_cache.max_age)
	}
}

fn (a &Auth) cookie_name_for(kind string) string {
	return a.auth_cookie_factory().create_cookie(kind, {}).name
}

fn (a &Auth) cookie_header(name string, value string, path string, max_age ?i64) string {
	mut kind := ''
	for candidate in ['session_token', 'session_data', 'account_data', 'dont_remember', 'state',
		'oauth_state', 'admin_session'] {
		base := a.cookie_name_for(candidate)
		if name == base || cache_chunk_index(name, base) != none {
			kind = candidate
			break
		}
	}
	factory := a.auth_cookie_factory()
	mut defaults := map[string]json2.Any{}
	if path != '/' { defaults['path'] = path }
	mut attrs := factory.create_cookie(kind, defaults).attributes.clone()
	// Session-token lifetimes and explicit expiry writes override configured
	// Max-Age. Cache lifetimes are selected by their descriptor before encoding.
	if age := max_age {
		attrs['maxAge'] = age
	} else if kind != 'dont_remember' {
		attrs.delete('maxAge')
	}
	return serialize_auth_cookie(name, value, attrs)
}

fn serialize_auth_cookie(input_name string, encoded_value string, input map[string]json2.Any) string {
	mut name := input_name
	mut attrs := input.clone()
	prefix := (attrs['prefix'] or { json2.Any('') }).str()
	if prefix in ['host', 'secure'] { name =
			(if prefix == 'host' { host_cookie_prefix } else { secure_cookie_prefix }) + name
	 }
	if name.to_lower().starts_with('__host-') {
		attrs['secure'] = true
		attrs['path'] = '/'
		attrs.delete('domain')
	} else if name.to_lower().starts_with('__secure-') {
		attrs['secure'] = true
	}
	if (attrs['partitioned'] or { json2.Any(false) }) == json2.Any(true) || (attrs['sameSite'] or {
		json2.Any('')
	}).str().to_lower() == 'none' {
		attrs['secure'] = true
	}
	mut header := '${name}=${encoded_value}'
	if age := attrs['maxAge'] {
		if age !is json2.Null && age.f64() >= 0 { header += '; Max-Age=${i64(age.f64())}' }
	}
	for key, label in {
		'domain': 'Domain'
		'path':   'Path'
	} {
		if value := attrs[key] {
			if js_truthy(value) { header += '; ${label}=${value.str()}' }
		}
	}
	if expires := attrs['expires'] {
		if expires is string {
			if parsed := time.parse_rfc3339(expires) {
				header += '; Expires=' + parsed.http_header_string()
			}
		}
	}
	if js_truthy(attrs['httpOnly'] or { json2.Any(false) }) { header += '; HttpOnly' }
	if js_truthy(attrs['secure'] or { json2.Any(false) }) { header += '; Secure' }
	if same_site := attrs['sameSite'] {
		text := same_site.str()
		if js_truthy(same_site) && text != '' {
			header += '; SameSite=' + text[..1].to_upper() + text[1..]
		}
	}
	if js_truthy(attrs['partitioned'] or { json2.Any(false) }) { header += '; Partitioned' }
	return header
}
