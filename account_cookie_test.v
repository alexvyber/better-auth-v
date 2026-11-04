module better_auth

import x.json2

fn account_cookie_test_headers(response Response) map[string]string {
	return {
		'cookie': response.headers.filter(it.name == 'set-cookie').map(it.value.all_before(';')).join('; ')
	}
}

fn test_native_account_cookie_chunks_and_retained_secret_versions() ! {
	old_key := SecretEntry{
		version: 1
		value:   'old-account-cookie-key-at-least-thirty-two-bytes'
	}
	new_key := SecretEntry{
		version: 2
		value:   'new-account-cookie-key-at-least-thirty-two-bytes'
	}
	mut old := new(Config{
		secrets: [old_key]
		clock:   fn () i64 {
			return 1893456000
		}
	}, open_memory())!
	defer { old.close() or {} }
	mut current := new(Config{
		secrets: [new_key, old_key]
		clock:   fn () i64 {
			return 1893456000
		}
	}, open_memory())!
	defer { current.close() or {} }
	response := old.set_account_cookie(Response{},
		'{"userId":"user","large":"${'x'.repeat(8000)}"}')!
	assert response.headers.len > 1
	for header in response.headers {
		assert header.value.len <= 4050
	}
	header := RequestContext{
		headers: account_cookie_test_headers(response)
	}
	decoded := current.get_account_cookie(header).value or {
		panic('retained key must read chunks')
	}

	fields := json2.decode[map[string]json2.Any](decoded)!
	assert (fields['userId'] or { panic('missing user') }).str() == 'user'
	fresh := current.set_account_cookie(Response{}, '{"userId":"user"}')!
	assert old.get_account_cookie(RequestContext{ headers: account_cookie_test_headers(fresh) }).value == none
	encrypted := encrypt_oauth_token('plain-token', current.secret_config, true)!
	assert encrypted != 'plain-token'
	assert decrypt_oauth_token(encrypted, current.secret_config, true)! == 'plain-token'
	assert decrypt_oauth_token('ya29.old-plaintext-token', current.secret_config, true)! == 'ya29.old-plaintext-token'
}

fn test_native_account_cookie_binding_preserves_fresh_pending_writes() ! {
	mut auth := new(Config{
		secret:               'account-cookie-binding-secret-at-least-thirty-two-bytes'
		store_account_cookie: true
		cookie_cache:         CookieCacheConfig{
			enabled: true
		}
	}, open_memory())!
	defer { auth.close() or {} }
	stale := auth.set_account_cookie(Response{}, '{"userId":"one"}')!
	auth.request_context = RequestContext{
		headers: account_cookie_test_headers(stale)
	}
	target := SessionResult{
		user: User{
			id: 'two'
		}
	}
	expired := auth.sync_account_cookie(Response{}, target)!
	assert expired.headers.any(it.value.starts_with('better-auth.account_data=;')
		&& it.value.contains('Max-Age=0'))
	fresh := auth.set_account_cookie(Response{}, '{"userId":"two"}')!
	preserved := auth.sync_account_cookie(fresh, target)!
	assert preserved.headers == fresh.headers
	decoded := auth.get_account_cookie(RequestContext{
		headers: account_cookie_test_headers(preserved)
	}).value or { panic('missing fresh cookie') }
	assert (json2.decode[map[string]json2.Any](decoded)!['userId'] or { panic('missing user') }).str() == 'two'
}
