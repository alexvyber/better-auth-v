module better_auth

import x.json2

fn test_native_email_otp_hashed_signin_and_single_use() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  'native-email-otp-test-secret-123456'
		plugins: [
			Plugin(EmailOTPPlugin{
				options: EmailOTPOptions{
					store_otp: 'hashed'
				}
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	code := auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('createVerificationOTP',
			'[{"email":"otp@example.com","type":"sign-in"}]')
	})!
	otp := json2.decode[string](code)!
	assert otp.len == 6
	stored := auth.with_internal(fn (mut context EndpointContext) !string {
		record := (context.find_verification_value('sign-in-otp-otp@example.com')!).value or {
			return error('missing OTP')
		}

		return record.value
	})!
	assert stored == default_one_time_token_hasher(otp)! + ':0'
	response := auth.call(Request{
		method: 'POST'
		url:    '/api/auth/sign-in/email-otp'
		body:   '{"email":"otp@example.com","otp":"${otp}","name":"OTP"}'
	})
	assert response.status == 200, response.body
	fields := json2.decode[map[string]json2.Any](response.body)!
	assert fields['user']!.as_map()['emailVerified']!.bool()
	replay := auth.call(Request{
		method: 'POST'
		url:    '/api/auth/sign-in/email-otp'
		body:   '{"email":"otp@example.com","otp":"${otp}"}'
	})
	assert replay.status == 400
}
