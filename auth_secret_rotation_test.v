module better_auth

import net.urllib
import os

fn test_native_auth_rotation_preserves_persisted_keys_sessions_and_jwe_cache() ! {
	path := os.join_path(os.temp_dir(), 'better-auth-rotation-${random_token()!}.db')
	defer { os.rm(path) or {} }
	old_secret := 'old-secret-that-is-long-enough-for-rotation-tests'
	new_secret := 'new-secret-that-is-long-enough-for-rotation-tests'
	cache := CookieCacheConfig{
		enabled:  true
		strategy: 'jwe'
	}
	mut old_storage := open_sqlite(path)!
	old_storage.migrate()!
	mut first := new(Config{
		secrets:      [SecretEntry{ version: 1, value: old_secret }]
		cookie_cache: cache
		plugins:      [Plugin(JWTPlugin{})]
	}, old_storage)!
	registered := first.sign_up_email(SignUpInput{
		email:    'rotation@example.com'
		name:     'Rotation'
		password: 'password123'
	}, RequestContext{})!
	token := registered.token or { return error('missing session token') }
	old_cookie := first.sign_cookie(token)
	old_headers := RequestContext{
		headers: {
			'cookie': 'better-auth.session_token=' + urllib.query_escape(old_cookie)
		}
	}
	current := (first.get_session(old_headers)!).value or {
		return error('missing initial session')
	}

	cached := first.encode_cookie_cache(current)!
	first.sign_jwt('{"sub":"before-rotation"}')!
	key_id := old_storage.jwks()![0].id
	first.close()!

	mut reopened := open_sqlite(path)!
	reopened.migrate()!
	mut rotated := new(Config{
		secrets:      [SecretEntry{ version: 2, value: new_secret },
			SecretEntry{ version: 1, value: old_secret }]
		cookie_cache: cache
		plugins:      [Plugin(JWTPlugin{})]
	}, reopened)!
	defer { rotated.close() or {} }
	// Upstream signs session-token cookies with the current secret, even when
	// old encryption versions remain configured. Do not silently broaden that.
	assert rotated.verify_cookie(old_cookie) == none
	new_headers := RequestContext{
		headers: {
			'cookie': 'better-auth.session_token=' + urllib.query_escape(rotated.sign_cookie(token))
		}
	}
	loaded := (rotated.get_session(new_headers)!).value or {
		return error('missing rotated session')
	}

	assert loaded.user.id == registered.user.id
	listed := rotated.list_sessions(new_headers)!
	assert listed.len == 1
	assert listed[0].token == token
	assert rotated.decode_cookie_cache(cached)!.result.user.id == registered.user.id
	issued := rotated.sign_jwt('{"sub":"after-rotation"}')!
	assert (rotated.verify_jwt(issued, '')!).value != none
	assert reopened.jwks()!.len == 1
	assert reopened.jwks()![0].id == key_id
}
