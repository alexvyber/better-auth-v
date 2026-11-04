module better_auth

import x.json2

fn test_native_anonymous_protected_identity_and_deletion() ! {
	mut auth := new(Config{
		secret:  'native-anonymous-test-secret-123456'
		plugins: [
			Plugin(AnonymousPlugin{}),
		]
	}, open_memory())!
	defer { auth.close() or {} }
	response := auth.call(Request{
		method: 'POST'
		url:    '/api/auth/sign-in/anonymous'
		body:   '{"isAnonymous":false}'
	})
	assert response.status == 200, response.body
	fields := json2.decode[map[string]json2.Any](response.body)!
	assert fields['user']!.as_map()['isAnonymous']!.bool()
	token := fields['token']!.str()
	headers := {
		'cookie': 'better-auth.session_token=' + auth.sign_cookie(token)
	}
	again :=
		auth.call(Request{ method: 'POST', url: '/api/auth/sign-in/anonymous', headers: headers })
	assert again.status == 400
	deleted := auth.call(Request{
		method:  'POST'
		url:     '/api/auth/delete-anonymous-user'
		headers: headers
	})
	assert deleted.status == 200, deleted.body
	assert auth.call(Request{ url: '/api/auth/get-session', headers: headers }).body == 'null'
}
