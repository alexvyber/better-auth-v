module better_auth

import json
import os
import x.json2

struct JWTTestClock {
mut:
	now i64 = 1000000000
}

fn test_legacy_private_keys_and_missing_algorithm_metadata_remain_readable() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		plugins: [
			Plugin(JWTPlugin{}),
		]
	}, storage)!
	defer { auth.close() or {} }
	public, private := generate_exported_keypair(JWTOptions{})!
	legacy := Jwk{
		id:          'legacy-id'
		public_key:  public
		private_key: auth.seal_jwk('legacy-id', private)!
		encrypted:   true
		created_at:  stamp(1000000000)
	}
	storage.create_jwk(legacy)!
	token := auth.sign_jwt('{"sub":"legacy-user"}')!
	assert (auth.verify_jwt(token, '')!).value != none
	assert storage.jwks()!.len == 1
	assert json2.decode[map[string]json2.Any](decode_base64url(token.split('.')[0])!.bytestr())!['kid']!.str() == 'legacy-id'
}

fn test_jwks_private_material_is_sealed_persistent_and_never_published() ! {
	path := os.join_path(os.temp_dir(), 'better-auth-jwks-${random_token()!}.db')
	defer { os.rm(path) or {} }
	secret := '12345678901234567890123456789012'
	mut storage := open_sqlite(path)!
	storage.migrate()!
	mut first := new(Config{ secret: secret, plugins: [Plugin(JWTPlugin{})] }, storage)!
	token := first.sign_jwt('{"sub":"test-user"}')!
	keys := storage.jwks()!
	assert keys.len == 1
	assert keys[0].encrypted
	private := first.private_jwk(keys[0])!
	encoded_seed := base64url(private.seed())
	assert !json.encode(keys[0]).contains(encoded_seed)
	public := first.get_jwks()!
	assert !public.contains(encoded_seed)
	assert !public.contains('privateKey')
	assert !public.contains('"d":')
	first.close()!
	mut reopened := open_sqlite(path)!
	defer { reopened.close() or {} }
	reopened.migrate()!
	mut second := new(Config{ secret: secret, plugins: [Plugin(JWTPlugin{})] }, reopened)!
	defer { second.close() or {} }
	verified := (second.verify_jwt(token, '')!).value or {
		return error('persisted JWT failed verification')
	}

	assert json2.decode[map[string]json2.Any](verified)!['sub']!.str() == 'test-user'
	second.sign_jwt('{"sub":"second-user"}')!
	assert reopened.jwks()!.len == 1
	assert second.get_jwks()! == public
}

fn test_native_jwt_token_api_uses_an_authenticated_session() ! {
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		plugins: [Plugin(JWTPlugin{}), BearerPlugin{}]
	}, open_memory())!
	defer { auth.close() or {} }
	token := auth.with_internal(fn (mut context EndpointContext) !string {
		context.create_user(User{
			id:         'user'
			email:      'jwt@example.com'
			name:       'JWT'
			created_at: stamp(1000000000)
			updated_at: stamp(1000000000)
		})!
		session := context.create_session('user', RequestContext{}, true)!
		return session.token
	})!
	jwt := auth.get_token(RequestContext{
		headers: {
			'authorization': 'Bearer ' + token
		}
	})!
	verified := (auth.verify_jwt(jwt, '')!).value or {
		return error('session JWT failed verification')
	}

	assert json2.decode[map[string]json2.Any](verified)!['sub']!.str() == 'user'
	assert auth.call(Request{ method: 'GET', url: auth.config.base_url + '/api/auth/token' }).status == 401
}

fn test_key_creation_rolls_back_with_its_transaction() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:        '12345678901234567890123456789012'
		plugins:       [Plugin(JWTPlugin{})]
		before_commit: fn (mut _ EndpointContext) ! {
			return error('abort key transaction')
		}
	}, storage)!
	defer { auth.close() or {} }
	mut rejected := false
	auth.sign_jwt('{"sub":"test-user"}') or {
		rejected = true
		''
	}
	assert rejected
	assert storage.jwks()!.len == 0
}

fn test_jwks_rotation_retains_public_keys_only_through_grace_period() ! {
	mut clock := &JWTTestClock{}
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		clock:   fn [clock] () i64 {
			return clock.now
		}
		plugins: [
			Plugin(JWTPlugin{
				options: JWTOptions{
					rotation_interval: 1
					grace_period:      1
				}
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	first := auth.sign_jwt('{"sub":"first"}')!
	assert storage.jwks()!.len == 1
	clock.now++
	second := auth.sign_jwt('{"sub":"second"}')!
	assert storage.jwks()!.len == 2
	assert first.split('.')[0] != second.split('.')[0]
	assert (json2.decode[map[string]json2.Any](auth.get_jwks()!)!['keys']!).as_array().len == 2
	clock.now++
	assert (json2.decode[map[string]json2.Any](auth.get_jwks()!)!['keys']!).as_array().len == 1
}

fn test_jwks_signatures_and_claims_fail_closed() ! {
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		clock:   fn () i64 {
			return 1000000000
		}
		plugins: [Plugin(JWTPlugin{})]
	}, open_memory())!
	defer { auth.close() or {} }
	valid := auth.sign_jwt('{"sub":"user"}')!
	auth.verify_jwks_payload(valid, false, '')!
	mut parts := valid.split('.')
	parts[1] =
		base64url('{"sub":"forged-user","iss":"http://localhost:3000","aud":"http://localhost:3000","exp":1000000900}'.bytes())
	mut rejected := 0
	auth.verify_jwks_payload(parts.join('.'), false, '') or {
		rejected++
		map[string]json2.Any{}
	}
	for payload in ['{"sub":"user","iss":"wrong-issuer"}', '{"sub":"user","aud":"wrong-audience"}',
		'{"sub":"user","exp":999999999}', '{"sub":"user","nbf":1000000010}'] {
		token := auth.sign_jwt(payload)!
		auth.verify_jwks_payload(token, false, '') or {
			rejected++
			map[string]json2.Any{}
		}
	}
	assert rejected == 5
}

fn test_remote_jwt_signer_receives_native_claims_without_minting_local_keys() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:   '12345678901234567890123456789012'
		base_url: 'https://auth.example.com'
		plugins:  [
			Plugin(JWTPlugin{
				options: JWTOptions{
					algorithm:  'ES256'
					remote_url: 'https://keys.example.com/jwks'
					sign:       fn (claims string) !string {
						parsed := json2.decode[map[string]json2.Any](claims)!
						assert parsed['sub']!.str() == 'remote-user'
						assert parsed['iss']!.str() == 'https://auth.example.com'
						assert parsed['aud']!.str() == 'https://auth.example.com'
						assert parsed['exp']!.i64() == 1900
						return 'delegated-token'
					}
				}
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	assert auth.sign_jwt('{"sub":"remote-user","iat":1000}')! == 'delegated-token'
	assert storage.jwks()!.len == 0
	auth.get_jwks() or {
		assert err.msg().contains('Not found')
		return
	}
	assert false, 'remote URL must disable local JWKS publication'
}

fn test_remote_jwt_configuration_requires_explicit_algorithm_and_local_cookie_keys() ! {
	for options in [JWTOptions{ remote_url: 'https://keys.example.com' },
		JWTOptions{
			sign: fn (_ string) !string {
				return 'external'
			}
		}, JWTOptions{
			algorithm:            'EdDSA'
			remote_url:           'https://keys.example.com'
			session_cookie_cache: true
			sign:                 fn (_ string) !string {
				return 'external'
			}
		}] {
		mut storage := open_memory()
		new(Config{
			secret:       '12345678901234567890123456789012'
			cookie_cache: CookieCacheConfig{
				strategy: 'jwt'
			}
			plugins:      [Plugin(JWTPlugin{
				options: options
			})]
		}, storage) or {
			storage.close()!
			continue
		}
		assert false, 'invalid remote signing configuration was accepted'
	}
}

fn test_native_signing_pins_use_transaction_context_and_rollback_key_creation() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		plugins: [
			Plugin(JWTPlugin{
				options: JWTOptions{
					key_pair_configs: [JWTKeyPairConfig{ algorithm: 'ES256' }]
				}
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	auth.with_internal(fn (mut context EndpointContext) !string {
		context.sign_jwt_with('{"sub":"rollback"}', JWTSigningConfig{ signing_algorithm: 'ES256' })!
		return error('roll back new signing key')
	}) or { assert err.msg() == 'roll back new signing key' }
	assert storage.jwks()!.len == 0
	token := auth.sign_jwt_with('{"sub":"profile"}', JWTSigningConfig{
		signing_algorithm: 'ES256'
		header_json:       '{"typ":"logout+jwt","alg":"none","kid":"forged"}'
	})!
	fields := json2.decode[map[string]json2.Any](decode_base64url(token.split('.')[0])!.bytestr())!
	assert fields['alg']!.str() == 'ES256'
	assert fields['typ']!.str() == 'logout+jwt'
	assert fields['kid']!.str() == storage.jwks()![0].id
	assert (auth.verify_jwt(token, '')!).value != none
	auth.sign_jwt_with('{"sub":"missing"}', JWTSigningConfig{ signing_key_id: 'absent' }) or {
		assert err.msg().contains('not found')
		assert storage.jwks()!.len == 1
		return
	}
	assert false, 'missing signing key must fail without minting a replacement'
}

struct JWTOriginLog {
mut:
	messages []string
}

fn test_request_resolved_origins_do_not_leak_into_direct_jwt_calls() ! {
	mut storage := open_memory()
	mut audit := &JWTOriginLog{}
	mut auth := new(Config{
		secret:   '12345678901234567890123456789012'
		base_url: ''
		plugins:  [Plugin(JWTPlugin{})]
		log:      fn [mut audit] (_ string, message string) {
			audit.messages << message
		}
	}, storage)!
	defer { auth.close() or {} }
	signup := auth.call(Request{
		method: 'POST'
		url:    'https://one.example/api/auth/sign-up/email'
		body:   '{"email":"origin@example.com","password":"password123","name":"Origin"}'
	})
	assert signup.status == 200, signup.body
	mut cookies := []string{}
	for header in signup.headers {
		if header.name == 'set-cookie' {
			assert header.value.contains('; Secure')
			cookies << header.value.all_before(';')
		}
	}
	assert cookies.len > 0
	for origin in ['https://one.example', 'https://two.example'] {
		response := auth.handle(Request{
			url:     origin + '/api/auth/get-session'
			headers: {
				'cookie': cookies.join('; ')
				'origin': origin
			}
		})
		assert response.status == 200, response.body
		mut token := ''
		for header in response.headers {
			if header.name == 'set-auth-jwt' { token = header.value }
			if header.name == 'access-control-allow-origin' { assert header.value == origin
			 }
		}
		assert token != ''
		claims :=
			json2.decode[map[string]json2.Any](decode_base64url(token.split('.')[1])!.bytestr())!
		assert claims['iss']!.str() == origin
		assert claims['aud']!.str() == origin
	}
	bad := auth.handle(Request{
		method:  'POST'
		url:     'https://two.example/api/auth/sign-out'
		headers: {
			'cookie':       cookies.join('; ')
			'origin':       'https://one.example'
			'content-type': 'application/json'
		}
		body:    '{}'
	})
	assert bad.status == 403
	token := auth.sign_jwt('{"sub":"server-user"}')!
	claims := json2.decode[map[string]json2.Any](decode_base64url(token.split('.')[1])!.bytestr())!
	assert claims['iss']!.str() == ''
	assert claims['aud']!.str() == ''
	assert audit.messages.any(it.contains('signed a JWT without an issuer or audience'))
	assert (auth.verify_jwt(token, '')!).value == none
}

fn test_preexisting_v2_native_key_envelopes_survive_upstream_ciphertext_migration() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		plugins: [Plugin(JWTPlugin{})]
	}, storage)!
	defer { auth.close() or {} }
	public, private := generate_exported_keypair(JWTOptions{})!
	storage.create_jwk(Jwk{
		id:          'reassigned-id'
		public_key:  public
		private_key: 'v2.' + auth.seal_jwk('public:' + digest(public), private)!
		created_at:  stamp(auth.config.clock())
		alg:         'EdDSA'
		crv:         'Ed25519'
	})!
	token := auth.sign_jwt('{"sub":"migrated-user"}')!
	assert (auth.verify_jwt(token, '')!).value != none
	assert storage.jwks()!.len == 1
}

struct JWTMillisecondClock {
mut:
	now i64 = 1900
}

fn test_jwt_rotation_grace_preserves_fractional_second_boundaries() ! {
	mut clock := &JWTMillisecondClock{}
	mut storage := open_memory()
	mut auth := new(Config{
		secret:       '12345678901234567890123456789012'
		clock:        fn [clock] () i64 {
			return clock.now / 1000
		}
		clock_millis: fn [clock] () i64 {
			return clock.now
		}
		plugins:      [
			Plugin(JWTPlugin{
				options: JWTOptions{
					rotation_interval: 1
					grace_period:      1
				}
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	auth.sign_jwt('{"sub":"first"}')!
	clock.now += 1100
	auth.sign_jwt('{"sub":"second"}')!
	assert storage.jwks()!.len == 2
	first := json2.decode[map[string]json2.Any](auth.get_jwks()!)!
	assert first['keys']!.as_array().len == 2
	clock.now += 1000
	after_grace := json2.decode[map[string]json2.Any](auth.get_jwks()!)!
	assert after_grace['keys']!.as_array().len == 1
}
