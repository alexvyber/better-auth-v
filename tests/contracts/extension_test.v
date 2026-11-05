module main

import better_auth
import crypto.sha256
import encoding.hex
import json

struct FixtureHasher {}

fn (_ FixtureHasher) hash(password string) !string {
	return hex.encode(sha256.sum(password.bytes()))
}

fn (h FixtureHasher) verify(password string, encoded string) !bool {
	return (h.hash(password) or { '' }) == encoded
}

struct WhoAmIPlugin {}

fn (_ WhoAmIPlugin) id() string {
	return 'who-am-i'
}

fn (_ WhoAmIPlugin) endpoints() []better_auth.Endpoint {
	return [better_auth.Endpoint{ path: '/who-am-i', handler: who_am_i }]
}

fn who_am_i(mut context better_auth.EndpointContext, req better_auth.Request) !better_auth.Response {
	current := context.require_session(better_auth.RequestContext{ headers: req.headers }, false)!
	return better_auth.Response{
		body: json.encode({
			'email': current.user.email
		})
	}
}

fn test_external_plugin_can_authenticate_inside_the_enclosing_transaction() ! {
	mut storage := better_auth.open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := better_auth.new(better_auth.Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FixtureHasher{}
		plugins:         [better_auth.Plugin(better_auth.BearerPlugin{}), WhoAmIPlugin{}]
	}, storage)!
	defer { auth.close() or {} }
	url := 'http://localhost:3000/api/auth/who-am-i'
	assert auth.handle(better_auth.Request{
		method:  'POST'
		url:     url
		headers: {
			'content-type': 'application/json'
		}
		body:    '{}'
	}).status == 401
	result := auth.sign_up_email(better_auth.SignUpInput{
		email:    'extension@example.com'
		name:     'Extension'
		password: 'password123'
	}, better_auth.RequestContext{})!
	token := result.token or { return error('missing token') }
	response := auth.handle(better_auth.Request{
		method:  'POST'
		url:     url
		headers: {
			'content-type':  'application/json'
			'authorization': 'Bearer ${token}'
		}
		body:    '{}'
	})
	assert response.status == 200
	assert json.decode(map[string]string, response.body)!['email'] == 'extension@example.com'
}
