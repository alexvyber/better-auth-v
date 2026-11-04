module better_auth

import x.json2

fn test_cookie_factory_security_precedence_and_attribute_isolation() ! {
	factory :=
		create_cookie_getter('{"baseURL":{"protocol":"auto","allowedHosts":["*.example.com"]},"advanced":{"defaultCookieAttributes":{"path":"/global","sameSite":"strict"},"cookies":{"session_data":{"attributes":{"path":"/cache","maxAge":12}}}}', true)!
	assert factory.secure()
	cookie := factory.create_cookie('session_data', {
		'path': json2.Any('/override')
	})
	assert cookie.name == '__Secure-better-auth.session_data'
	assert (cookie.attributes['path'] or { panic('missing path') }).str() == '/cache'
	mut changed := cookie.attributes.clone()
	changed['path'] = '/mutated'
	assert (factory.get_cookies()['sessionData'].attributes['path'] or { panic('missing path') }).str() == '/cache'
	assert (factory.create_cookie('custom', {}).attributes['path'] or { panic('missing path') }).str() == '/global'
	assert !create_cookie_getter('{"baseURL":{"protocol":"http"}}', true)!.secure()
	assert create_cookie_getter('{"baseURL":{"protocol":"https"}}', false)!.secure()
	assert !create_cookie_getter('{"baseURL":"https://example.com","advanced":{"useSecureCookies":false}}',
		true)!.secure()
}

fn test_cookie_header_prefix_invariants_and_attribute_validation() ! {
	attrs := {
		'path':     json2.Any('/custom')
		'domain':   json2.Any('example.com')
		'secure':   json2.Any(false)
		'httpOnly': json2.Any(false)
		'sameSite': json2.Any(json2.Null{})
	}
	header := serialize_auth_cookie('__Host-token', 'value', attrs)
	assert header == '__Host-token=value; Path=/; Secure'
	assert !header.contains('Domain=') && !header.contains('SameSite=')
	partitioned := serialize_auth_cookie('token', 'value', {
		'partitioned': json2.Any(true)
	})
	assert partitioned == 'token=value; Secure; Partitioned'
	mut rejected := false
	validate_cookie_attributes({
		'path': json2.Any('/\r\nInjected: value')
	}) or {
		assert err.msg() == 'invalid cookie attribute path'
		rejected = true
	}
	assert rejected
	validate_cookie_attributes({
		'maxAge': json2.Any(12.5)
		'path':   json2.Any('/custom')
	})!
}
