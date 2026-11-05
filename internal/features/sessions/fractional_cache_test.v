module better_auth

import x.json2

fn test_native_fractional_jwt_lifetime_apis_keep_legacy_integer_callers() ! {
	secret := 'native-fractional-secret-at-least-thirty-two-bytes'
	const_now := i64(1893456000)
	encrypted := symmetric_encode_jwt_with_lifetime('{"value":"precise"}', secret, 'session', 0.5,
		const_now)!
	decoded := json2.decode[map[string]json2.Any](symmetric_decode_jwt(encrypted, secret,
		'session', const_now + 15)!)!
	assert numeric_date_field(decoded, 'exp')! == f64(const_now) + 0.5
	mut expired := false
	symmetric_decode_jwt(encrypted, secret, 'session', const_now + 16) or {
		assert err.msg() == 'expired JWE'
		expired = true
	}
	assert expired
	signed := sign_hmac_jwt_with_lifetime('{"value":"precise"}', secret, 0.5, const_now)!
	claims := json2.decode[map[string]json2.Any](verify_hmac_jwt(signed, secret, const_now)!)!
	assert numeric_date_field(claims, 'exp')! == f64(const_now) + 0.5
	legacy := symmetric_encode_jwt('{}', secret, 'session', i64(2), const_now)!
	legacy_claims := json2.decode[map[string]json2.Any](symmetric_decode_jwt(legacy, secret,
		'session', const_now)!)!
	assert numeric_date_field(legacy_claims, 'exp')! == f64(const_now + 2)
}

fn test_native_fractional_cache_config_and_compact_millisecond_clipping() ! {
	mut auth := new(Config{
		secret:       'native-fractional-secret-at-least-thirty-two-bytes'
		clock:        fn () i64 {
			return 1893456000
		}
		clock_millis: fn () i64 {
			return 1893456000123
		}
		cookie_cache: CookieCacheConfig{
			enabled: true
			max_age: 12.50075
		}
	}, open_memory())!
	defer { auth.close() or {} }
	assert auth.config.cookie_cache.max_age == 12.50075
	assert (auth.config.cookie_cache.update_age or { f64(0) }) == 12.50075 / 5
	result := SessionResult{
		session: Session{
			id:         'session'
			token:      'token'
			user_id:    'user'
			created_at: stamp(1893456000)
			updated_at: stamp(1893456000)
			expires_at: stamp(1893457000)
		}
		user:    User{
			id:         'user'
			email:      'user@example.com'
			name:       'User'
			created_at: stamp(1893456000)
			updated_at: stamp(1893456000)
		}
	}
	encoded := auth.encode_cookie_cache(result)!
	decoded := auth.decode_cookie_cache(encoded)!
	assert decoded.expires_at == f64(1893456012623)
	assert decoded.result.session.token == 'token'
}
