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
