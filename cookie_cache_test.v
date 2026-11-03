module better_auth

import x.json2

fn test_jwe_authentication_binds_secret_purpose_ciphertext_and_expiration() ! {
	secret := '12345678901234567890123456789012'
	token := symmetric_encode_jwt('{"subject":"user"}', secret, 'session', 300, 1000000000)!
	decoded := json2.decode[map[string]json2.Any](symmetric_decode_jwt(token, secret, 'session',
		1000000000)!)!
	assert (decoded['subject'] or { return error('missing subject') }).str() == 'user'
	assert (decoded['exp'] or { return error('missing expiration') }).i64() == 1000000300
	mut rejected := 0
	symmetric_decode_jwt(token, 'a different secret of at least 32 bytes', 'session', 1000000000) or {
		rejected++
		''
	}
	symmetric_decode_jwt(token, secret, 'account', 1000000000) or {
		rejected++
		''
	}
	symmetric_decode_jwt(token, secret, 'session', 1000000316) or {
		rejected++
		''
	}
	mut parts := token.split('.')
	mut ciphertext := decode_base64url(parts[3])!
	ciphertext[0] ^= 1
	parts[3] = base64url(ciphertext)
	symmetric_decode_jwt(parts.join('.'), secret, 'session', 1000000000) or {
		rejected++
		''
	}
	assert rejected == 4
}

fn test_stateless_defaults_are_resolved_in_v_and_secondary_storage_disables_refresh() ! {
	mut storage := open_memory()
	mut stateless := new(Config{
		secret:             '12345678901234567890123456789012'
		stateless_sessions: true
		session_expires_in: 3600
	}, storage)!
	defer { stateless.close() or {} }
	assert stateless.config.cookie_cache.enabled or { false }
	assert stateless.config.cookie_cache.strategy == 'jwe'
	assert stateless.config.cookie_cache.max_age == 3600
	assert stateless.config.cookie_cache.refresh_cache or { false }
	assert (stateless.config.cookie_cache.update_age or { 0 }) == 720
	mut cache := memory_secondary_storage(fn () i64 {
		return 1000000000
	})
	mut secondary := new(Config{
		secret:             '12345678901234567890123456789012'
		stateless_sessions: true
		secondary_storage:  cache
		cookie_cache:       CookieCacheConfig{
			enabled:       true
			refresh_cache: true
		}
	}, open_memory())!
	defer { secondary.close() or {} }
	assert !(secondary.config.cookie_cache.refresh_cache or { true })
	assert secondary.config.cookie_cache.max_age == 300
}

fn test_cache_json_matches_ecmascript_numbers_and_integer_property_order() ! {
	for input, expected in {
		'1793710300000':          '1793710300000'
		'0.000001':               '0.000001'
		'0.0000001':              '1e-7'
		'100000000000000000000':  '100000000000000000000'
		'1000000000000000000000': '1e+21'
		'-0':                     '0'
		'1.25':                   '1.25'
		'1e7':                    '10000000'
		'1e-5':                   '0.00001'
	} {
		assert js_json(json2.decode[json2.Any](input)!) == expected
	}
	assert js_json(json2.decode[json2.Any]('{"z":1,"2":2,"0":0,"01":1,"1":1,"a":2}')!) == '{"0":0,"1":1,"2":2,"z":1,"01":1,"a":2}'
}

fn test_compact_cache_signatures_survive_json_round_trip() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:       '12345678901234567890123456789012'
		cookie_cache: CookieCacheConfig{
			enabled: true
		}
		clock:        fn () i64 {
			return 1793710000
		}
	}, storage)!
	defer { auth.close() or {} }
	result := SessionResult{
		user:    User{
			id:         'user'
			email:      'test@example.com'
			name:       'A / B'
			created_at: stamp(1793710000)
			updated_at: stamp(1793710000)
		}
		session: Session{
			id:         'session'
			user_id:    'user'
			token:      'ab'.repeat(32)
			created_at: stamp(1793710000)
			updated_at: stamp(1793710000)
			expires_at: stamp(1793710600)
		}
	}
	encoded := auth.encode_cookie_cache(result)!
	decoded := auth.decode_cookie_cache(encoded)!
	assert decoded.result.user.name == result.user.name
	assert decoded.result.session.token == result.session.token
}
