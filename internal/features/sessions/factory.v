module better_auth

import net.urllib
import x.json2

pub struct AuthCookie {
pub:
	name       string
	attributes map[string]json2.Any
}

// Production is captured when the auth instance/factory is initialized. Dynamic
// URL protocols are explicit settings; auto leaves the production fallback intact.
pub struct CookieFactory {
pub:
	base_url                string
	dynamic_base_url        bool
	dynamic_protocol        string
	production              bool
	cookie_prefix           string = 'better-auth'
	cookie_names            map[string]string
	secure_cookies          ?bool
	cross_subdomain_cookies bool
	cookie_domain           string
	default_attributes      map[string]json2.Any
	cookie_attributes       map[string]map[string]json2.Any
	session_max_age         f64 = 604800
	cache_max_age           f64 = 300
}

pub fn (factory CookieFactory) secure() bool {
	if explicit := factory.secure_cookies { return explicit }
	if factory.dynamic_protocol in ['https', 'http'] { return factory.dynamic_protocol == 'https' }
	if factory.base_url != '' { return factory.base_url.starts_with('https://') }
	return factory.production
}

pub fn (factory CookieFactory) create_cookie(kind string, overrides map[string]json2.Any) AuthCookie {
	prefix := if factory.cookie_prefix == '' { 'better-auth' } else { factory.cookie_prefix }
	configured := factory.cookie_names[kind]
	name := if configured == '' { prefix + '.' + kind } else { configured }
	mut attributes := {
		'secure':   json2.Any(factory.secure())
		'sameSite': json2.Any('lax')
		'path':     json2.Any('/')
		'httpOnly': json2.Any(true)
	}
	if factory.cross_subdomain_cookies {
		domain := if factory.cookie_domain != '' {
			factory.cookie_domain
		} else {
			url := urllib.parse(factory.base_url) or { urllib.URL{} }
			hostname := url.hostname()
			if hostname.contains(':') {
				'[' + hostname + ']'
			} else {
				hostname
			}
		}
		if domain != '' { attributes['domain'] = domain }
	}
	for key, value in factory.default_attributes {
		attributes[key] = value
	}
	for key, value in overrides {
		attributes[key] = value
	}
	for key, value in factory.cookie_attributes[kind] {
		attributes[key] = value
	}
	return AuthCookie{
		name:       (if factory.secure() { secure_cookie_prefix } else { '' }) + name
		attributes: attributes
	}
}

pub fn (factory CookieFactory) get_cookies() map[string]AuthCookie {
	return {
		'sessionToken':      factory.create_cookie('session_token', {
			'maxAge': json2.Any(factory.session_max_age)
		})
		'sessionData':       factory.create_cookie('session_data', {
			'maxAge': json2.Any(factory.cache_max_age)
		})
		'accountData':       factory.create_cookie('account_data', {
			'maxAge': json2.Any(factory.cache_max_age)
		})
		'dontRememberToken': factory.create_cookie('dont_remember', {})
	}
}

// JS-facing options are decoded here so the test facade does not implement
// attribute precedence, cookie names, secure defaults, or domain policy.
pub fn create_cookie_getter(options_json string, production bool) !CookieFactory {
	options := json2.decode[map[string]json2.Any](options_json)!
	advanced := (options['advanced'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	cross := (advanced['crossSubDomainCookies'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	session := (options['session'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	cache := (session['cookieCache'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	base := options['baseURL'] or { json2.Any(json2.Null{}) }
	base_string := if base is string { base } else { '' }
	dynamic := base is map[string]json2.Any
	dynamic_options := base.as_map()
	domain := (cross['domain'] or { json2.Any('') }).str()
	enabled := js_truthy(cross['enabled'] or { json2.Any(false) })
	if enabled && domain == '' && base_string == '' && !dynamic {
		return error('baseURL is required when crossSubdomainCookies are enabled.')
	}
	mut names := map[string]string{}
	mut attributes := map[string]map[string]json2.Any{}
	for kind, item in (advanced['cookies'] or { json2.Any(map[string]json2.Any{}) }).as_map() {
		fields := item.as_map()
		names[kind] = (fields['name'] or { json2.Any('') }).str()
		attributes[kind] =
			(fields['attributes'] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
	}
	return CookieFactory{
		base_url:                base_string
		dynamic_base_url:        dynamic
		dynamic_protocol:        (dynamic_options['protocol'] or { json2.Any('') }).str()
		production:              production
		cookie_prefix:           (advanced['cookiePrefix'] or { json2.Any('better-auth') }).str()
		cookie_names:            names
		secure_cookies:          if value := advanced['useSecureCookies'] {
			if value is bool { ?bool(value) } else { none }
		} else {
			none
		}
		cross_subdomain_cookies: enabled
		cookie_domain:           domain
		default_attributes:      (advanced['defaultCookieAttributes'] or {
			json2.Any(map[string]json2.Any{})
		}).as_map().clone()
		cookie_attributes:       attributes
		session_max_age:         if js_truthy(session['expiresIn'] or { json2.Any(0) }) {
			(session['expiresIn'] or { json2.Any(0) }).f64()
		} else {
			604800
		}
		cache_max_age:           if js_truthy(cache['maxAge'] or { json2.Any(0) }) {
			(cache['maxAge'] or { json2.Any(0) }).f64()
		} else {
			300
		}
	}
}

pub fn get_cookies(options_json string, production bool) !map[string]AuthCookie {
	return create_cookie_getter(options_json, production)!.get_cookies()
}
