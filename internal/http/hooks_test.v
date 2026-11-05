module better_auth

import json

struct RoutingRequestHook {}

fn (_ RoutingRequestHook) id() string {
	return 'routing-hook'
}

fn (_ RoutingRequestHook) endpoints() []Endpoint {
	return []Endpoint{}
}

fn (_ RoutingRequestHook) on_request(request Request) !RequestHookResult {
	if request.headers['x-short-circuit'] == 'true' {
		return RequestHookResult{
			response: Response{
				status: 418
				body:   'hook response'
			}
		}
	}
	return RequestHookResult{
		request: Request{
			...request
			url: 'http://localhost:3000/api/auth/ok'
		}
	}
}

fn test_native_request_hooks_replace_requests_and_short_circuit_http_only() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:  'native-hook-test-secret-at-least-32-characters'
		plugins: [Plugin(RoutingRequestHook{})]
	}, storage)!
	defer { auth.close() or {} }
	request := Request{
		url: 'http://localhost:3000/api/auth/not-registered'
	}
	assert auth.handle(request).body == '{"ok":true}'
	assert auth.call(request).status == 404
	response := auth.handle(Request{
		...request
		headers: {
			'x-short-circuit': 'true'
			'origin':          'https://evil.example'
		}
	})
	assert response.status == 418
	assert response.body == 'hook response'
	assert response.headers.any(it.name == 'x-content-type-options' && it.value == 'nosniff')
	assert !response.headers.any(it.name == 'access-control-allow-origin')
}

fn test_prepared_request_keeps_its_trust_snapshot_after_another_request_completes() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:              'native-trust-test-secret-at-least-32-characters'
		trusted_origins_for: fn (ctx RequestContext) ![]string {
			return if ctx.headers['x-tenant'] == 'a' { ['https://a.example'] } else { [
					'https://b.example',
				] }
		}
	}, storage)!
	defer { auth.close() or {} }
	request := Request{
		method:  'POST'
		url:     'http://localhost:3000/api/auth/sign-in/email'
		body:    '{"email":"missing@example.com","password":"password123"}'
		headers: {
			'content-type': 'application/json'
			'x-tenant':     'a'
			'origin':       'https://b.example'
		}
	}
	prepared_a := auth.prepare_request(request, false)!
	prepared_b := auth.prepare_request(Request{
		...request
		headers: {
			'content-type': 'application/json'
			'x-tenant':     'b'
			'origin':       'https://b.example'
		}
	}, false)!
	assert auth.handle_prepared(prepared_b).status == 401
	assert auth.handle_prepared(prepared_a).status == 403
	assert !auth.is_trusted_origin('https://a.example', false)
}

fn test_disabled_origin_policy_does_not_allow_redirect_header_injection() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:               'header-validation-secret-at-least-32-characters'
		disable_origin_check: true
	}, storage)!
	defer { auth.close() or {} }
	response := auth.handle(Request{
		method:  'POST'
		url:     'http://localhost:3000/api/auth/sign-in/email'
		headers: {
			'content-type': 'application/json'
			'origin':       'https://untrusted.example'
		}
		body:    json.encode({
			'email':       'missing@example.com'
			'password':    'password123'
			'callbackURL': '/dashboard\r\nX-Injected: true'
		})
	})
	assert response.status == 403
	assert !response.headers.any(it.value.contains_any('\r\n'))
}
