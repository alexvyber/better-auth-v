module better_auth

import json
import x.json2

fn standalone_cache_fixture(now i64, expires i64) string {
	payload := '{"session":{"id":"","token":"","expiresAt":${json.encode(stamp_millis(now + 60000))}},"user":{"id":"different","name":"Name","email":"CACHE@EXAMPLE.COM"},"updatedAt":${now}}'
	signed := payload[..payload.len - 1] + ',"expiresAt":${expires}}'
	signature := base64url(cookie_reader_hmac('HS256', 'secret'.bytes(), signed.bytes()) or {
		panic(err)
	})
	return 'better-auth.session_data=' +
		base64url('{"session":${payload},"expiresAt":${expires},"signature":${json.encode(signature)}}'.bytes())
}

fn test_standalone_cookie_cache_native_callback_and_schema_defaults() ! {
	now := i64(1893456000123)
	header := standalone_cache_fixture(now, now)
	config := CookieCacheReadConfig{
		secret:       'secret'
		clock_millis: fn () i64 {
			return 1893456000123
		}
		version_for:  fn (payload string) !string {
			fields := json2.decode[map[string]json2.Any](payload)!
			user := (fields['user'] or { panic('missing user') }).as_map()
			session := (fields['session'] or { panic('missing session') }).as_map()
			assert (user['email'] or { panic('missing email') }).str() == 'cache@example.com'
			assert (user['createdAt'] or { panic('missing default date') }).str() == stamp_millis(1893456000123)
			assert (session['userId'] or { panic('missing coerced ID') }).str() == 'undefined'
			return '1'
		}
	}
	assert get_cookie_cache(header, config)!.value != none
	opened := open_cookie_cache(header, config, now)!.value or { panic('missing snapshot') }
	assert finish_cookie_cache(opened, none, now)!.value != none
	assert finish_cookie_cache(opened, none, now + 1)!.value == none
	mut failed := false
	get_cookie_cache(header, CookieCacheReadConfig{
		...config
		version_for: fn (_ string) !string {
			return error('version callback failed')
		}
	}) or {
		assert err.msg() == 'version callback failed'
		failed = true
	}
	assert failed
}

fn test_standalone_cookie_cache_configuration_errors_only_when_snapshot_present() ! {
	assert get_cookie_cache('', CookieCacheReadConfig{})!.value == none
	assert get_cookie_cache('unrelated=value', CookieCacheReadConfig{})!.value == none
	mut failed := false
	open_cookie_cache('better-auth.session_data=invalid', CookieCacheReadConfig{}, 1893456000123) or {
		assert err.msg().starts_with('getCookieCache requires a secret')
		failed = true
	}
	assert failed
	assert open_cookie_cache('better-auth.session_data=invalid', CookieCacheReadConfig{
		secret: 'secret'
	}, 1893456000123)!.value == none
}
