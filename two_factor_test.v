module better_auth

fn test_hotp_rfc4226_and_totp_rfc6238_sha1_vectors() ! {
	secret := '12345678901234567890'
	for counter, expected in ['755224', '287082', '359152', '969429', '338314', '254676', '287922',
		'162583', '399871', '520489'] {
		assert hotp(secret.bytes(), u64(counter), 6)! == expected
	}
	for index, seconds in [i64(59), 1111111109, 1111111111, 1234567890, 2000000000, 20000000000] {
		expected := ['94287082', '07081804', '14050471', '89005924', '69279037', '65353130'][index]
		assert totp_code(secret, seconds * 1000, TOTPOptions{ digits: 8 })! == expected
	}
}

fn test_totp_window_imported_base32_and_invalid_lengths() ! {
	secret := 'base32:GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
	options := TOTPOptions{}
	now := i64(1234567890000)
	expected := totp_code(secret, now, options)!
	assert expected == '005924'
	assert verify_totp_code(secret, expected, now + 30000, options)!
	assert verify_totp_code(secret, expected, now - 30000, options)!
	assert !verify_totp_code(secret, expected, now + 60000, options)!
	assert !verify_totp_code(secret, expected + '0', now, options)!
	assert !verify_totp_code(secret, '', now, options)!
}

fn test_typed_sign_in_returns_a_two_factor_challenge_without_authority() ! {
	secret := 'two-factor-native-secret-32-bytes-minimum'
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  secret
		plugins: [
			Plugin(TwoFactorPlugin{
				options: TwoFactorOptions{
					skip_verification_on_enable: true
				}
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	registered := auth.sign_up_email(SignUpInput{
		email:    'native-factor@example.com'
		password: 'safe-password'
		name:     'Native'
	}, RequestContext{})!
	token := registered.token or { return error('missing registration token') }
	cookie := auth.cookie_name() + '=' + auth.sign_cookie(token)
	enabled := auth.call(Request{
		method:  'POST'
		url:     '/api/auth/two-factor/enable'
		headers: {
			'cookie':       cookie
			'content-type': 'application/json'
		}
		body:    '{"password":"safe-password"}'
	})
	assert enabled.status == 200
	pending := auth.sign_in_email(SignInInput{
		email:    'native-factor@example.com'
		password: 'safe-password'
	}, RequestContext{})!
	assert pending.two_factor_redirect
	assert pending.two_factor_methods == ['totp']
	assert pending.token == none
	assert pending.user.id == ''
	values := pending.headers.filter(it.name == 'set-cookie').map(it.value)
	challenge_cookie := apply_set_cookies('', values)
	assert auth.get_session(RequestContext{
		headers: {
			'cookie': challenge_cookie
		}
	})!.value == none
	record := (storage.two_factors(registered.user.id)!)[0]
	plaintext := symmetric_decrypt(SymmetricSecret(secret), record.secret)!
	code := totp_code(plaintext, auth.clock_millis(), TOTPOptions{})!
	completed := auth.call(Request{
		method:  'POST'
		url:     '/api/auth/two-factor/verify-totp'
		headers: {
			'cookie':       challenge_cookie
			'content-type': 'application/json'
		}
		body:    '{"code":"${code}"}'
	})
	assert completed.status == 200
}
