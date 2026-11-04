module better_auth

fn test_native_uuid_generation_reaches_typed_auth_and_verification_apis() ! {
	mut auth := new(Config{ secret: 'native-uuid-generation-test-secret-1234', id_strategy: 'uuid' },
		open_memory())!
	defer { auth.close() or {} }
	result := auth.sign_up_email(SignUpInput{
		email:    'uuid@example.com'
		name:     'UUID'
		password: 'password123'
	}, RequestContext{})!
	assert valid_forced_uuid(result.user.id)
	assert result.user.id[14] == `4`
	token := result.token or { return error('missing UUID session token') }
	current := (auth.get_session(RequestContext{
		headers: {
			'cookie': 'better-auth.session_token=' + auth.sign_cookie(token)
		}
	})!).value or { return error('missing UUID session') }
	session := current.session
	assert valid_forced_uuid(session.id)
	assert session.token.len == 64
	auth.with_internal(fn (mut context EndpointContext) !string {
		created := context.create_verification_value(Verification{
			identifier: 'uuid-proof'
			value:      'proof'
			expires_at: 4000000000
		})!
		assert valid_forced_uuid(created.id)
		assert created.id[14] == `4`
		assert context.reserve_verification_value(Verification{
			identifier: 'uuid-reservation'
			value:      'proof'
			expires_at: 4000000000
		})!
		reserved := (context.find_verification_value('uuid-reservation')!).value or {
			return error('missing UUID reservation')
		}

		assert valid_forced_uuid(reserved.id)
		assert reserved.id[14] == `5`
		return 'null'
	})!
}
