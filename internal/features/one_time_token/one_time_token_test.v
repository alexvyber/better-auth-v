module better_auth

import x.json2

fn test_native_one_time_token_typed_api_and_replay() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  'native-one-time-token-test-secret-1234'
		plugins: [
			Plugin(OneTimeTokenPlugin{}),
		]
	}, storage)!
	defer { auth.close() or {} }
	signed := auth.sign_up_email(SignUpInput{
		email:    'ott@example.com'
		name:     'OTT'
		password: 'password123'
	}, RequestContext{})!
	token := signed.token or { return error('missing sign-up token') }
	context := RequestContext{
		headers: {
			'cookie': 'better-auth.session_token=' + auth.sign_cookie(token)
		}
	}
	ott := auth.generate_one_time_token(context)!
	assert ott.len == 32
	result := auth.verify_one_time_token(ott, RequestContext{})!
	assert result.user.id == signed.user.id
	mut rejected := false
	auth.verify_one_time_token(ott, RequestContext{}) or { rejected = true }
	assert rejected
}

fn test_native_verification_api_consumes_latest_and_preserves_hook_payload_dates() ! {
	mut storage := open_memory()
	mut auth := new(Config{ secret: 'native-verification-test-secret-1234' }, storage)!
	defer { auth.close() or {} }
	result := auth.with_internal(fn (mut context EndpointContext) !string {
		context.create_verification_value(Verification{
			identifier: 'handoff'
			value:      'older'
			created_at: '2030-01-01T00:00:00.000Z'
			expires_at: 4000000000
		})!
		context.create_verification_value(Verification{
			identifier: 'handoff'
			value:      'newer'
			created_at: '2030-01-01T00:00:00.001Z'
			expires_at: 4000000000
		})!
		consumed := (context.consume_verification_value('handoff')!).value or {
			return error('missing verification')
		}

		assert consumed.value == 'newer'
		assert (context.consume_verification_value('handoff')!).value == none
		return encode_verification(consumed)
	})!
	assert (json2.decode[map[string]json2.Any](result)!['value'] or { json2.Any('') }).str() == 'newer'
}
