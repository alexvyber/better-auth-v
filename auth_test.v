module better_auth

import crypto.sha256
import encoding.hex
import json
import os
import net.urllib
import x.json2

struct FastHasher {}

fn (_ FastHasher) hash(password string) !string {
	return hex.encode(sha256.sum(password.bytes()))
}

fn (h FastHasher) verify(password string, encoded string) !bool {
	return (h.hash(password) or { '' }) == encoded
}

fn test_real_argon2_passwords() ! {
	h := Argon2Hasher{}
	first := h.hash('correct horse battery staple')!
	second := h.hash('correct horse battery staple')!
	assert first.starts_with('$argon2id$')
	assert first != second
	assert h.verify('correct horse battery staple', first)!
	assert !h.verify('wrong password', first)!
	assert !h.verify('correct horse battery staple', 'invalid hash')!
}

fn test_transaction_rolls_back_user_and_account_when_session_insert_fails() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	storage.db.exec("CREATE TRIGGER fail_session BEFORE INSERT ON auth_session BEGIN SELECT RAISE(ABORT, 'session failure'); END")!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
	}, storage)!
	defer { auth.close() or {} }
	r := auth.call(Request{
		method: 'POST'
		url:    'http://localhost:3000/api/auth/sign-up/email'
		body:   '{"email":"rollback@example.com","name":"Rollback","password":"password123"}'
	})
	assert r.status == 500
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 0
	assert storage.db.q_int('SELECT count(*) FROM auth_account')! == 0
	assert storage.db.q_int('SELECT count(*) FROM auth_session')! == 0
}

fn test_database_keeps_session_tokens_hashed_and_round_trips_parameters() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
		plugins:         [Plugin(BearerPlugin{})]
	}, storage)!
	defer { auth.close() or {} }
	result := auth.sign_up_email(SignUpInput{
		email:    "o'connor@example.com"
		name:     "Robert'); DROP TABLE auth_user;--"
		password: 'password123'
	}, RequestContext{})!
	token := result.token or { return error('expected session') }
	rows := storage.db.exec('SELECT token_hash,data FROM auth_session')!
	assert rows.len == 1
	assert rows[0].vals[0] == digest(token)
	assert !rows[0].vals[1].contains(token)
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 1
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	}
	session := (auth.get_session(ctx)!).value or { return error('expected session') }
	assert session.user.name == result.user.name
	assert session.user.email == "o'connor@example.com"
	auth.sign_out(ctx)!
	assert (auth.get_session(ctx)!).value == none
}

fn test_bearer_is_not_implicitly_enabled() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
	}, storage)!
	defer { auth.close() or {} }
	result := auth.sign_up_email(SignUpInput{
		email:    'user@example.com'
		name:     'User'
		password: 'password123'
	}, RequestContext{})!
	token := result.token or { return error('missing token') }
	r := auth.get_session(RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	})!
	assert r.value == none
}

fn test_password_change_and_revocations_roll_back_together() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
		plugins:         [Plugin(BearerPlugin{})]
	}, storage)!
	defer { auth.close() or {} }
	user := auth.sign_up_email(SignUpInput{
		email:    'user@example.com'
		name:     'User'
		password: 'password123'
	}, RequestContext{})!
	other :=
		auth.sign_in_email(SignInInput{ email: 'user@example.com', password: 'password123' }, RequestContext{})!
	current_token := user.token or { return error('missing token') }
	other_token := other.token or { return error('missing token') }
	storage.db.exec("CREATE TRIGGER fail_password BEFORE UPDATE ON auth_account BEGIN SELECT RAISE(ABORT, 'password failure'); END")!
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ${current_token}'
		}
	}
	auth.change_password(ChangePasswordInput{
		current_password:      'password123'
		new_password:          'replacement123'
		revoke_other_sessions: true
	}, ctx) or {
		assert err.code() == 500
		assert (auth.get_session(RequestContext{
			headers: {
				'authorization': 'Bearer ${other_token}'
			}
		})!).value != none
		return
	}
	assert false, 'expected storage failure'
}

fn test_migrations_are_explicit_idempotent_and_reject_future_versions() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	assert storage.db.tables()!.len == 0
	storage.migrate()!
	storage.migrate()!
	assert storage.db.q_int('SELECT count(*) FROM auth_migration')! == 6
	storage.db.exec('INSERT INTO auth_migration VALUES (99)')!
	storage.migrate() or {
		assert err.msg().contains('newer')
		return
	}
	assert false, 'expected future-version rejection'
}

fn test_storage_errors_are_distinct_from_missing_records() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	storage.user('missing') or {
		assert err.msg().contains('no such table')
		return
	}
	assert false, 'expected storage error'
}

fn test_file_storage_survives_reopening() ! {
	path := os.join_path(os.temp_dir(), 'better-auth-${random_token()!}.db')
	defer { os.rm(path) or {} }
	mut first := open_sqlite(path)!
	first.migrate()!
	u := User{
		id:         'persisted'
		name:       'User'
		email:      'user@example.com'
		created_at: stamp(100)
		updated_at: stamp(100)
	}
	first.create_user(u)!
	first.close()!
	mut reopened := open_sqlite(path)!
	defer { reopened.close() or {} }
	loaded := (reopened.user('persisted')!).value or { return error('missing user') }
	assert json.encode(loaded) == json.encode(u)
}

struct CollisionPlugin {}

fn (_ CollisionPlugin) id() string {
	return 'collision'
}

fn (_ CollisionPlugin) endpoints() []Endpoint {
	return [Endpoint{ path: '/sign-in/email' }]
}

fn test_plugin_cannot_override_a_core_route() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	new(Config{
		secret:          '12345678901234567890123456789012'
		plugins:         [
			Plugin(CollisionPlugin{}),
		]
		password_hasher: FastHasher{}
	}, storage) or {
		assert err.msg().contains('duplicate')
		return
	}
	assert false, 'expected route collision rejection'
}

struct FakeProvider {
	verified bool = true
}

fn (_ FakeProvider) id() string {
	return 'test'
}

fn (_ FakeProvider) authorization_url(state string, challenge string, redirect_uri string) !string {
	assert challenge.len == 43
	assert redirect_uri == 'http://localhost:3000/api/auth/callback/test'
	return 'https://provider.example/authorize?state=' + state
}

fn (p FakeProvider) exchange(code string, verifier string, redirect_uri string) !OAuthIdentity {
	assert code == 'good-code'
	assert verifier.len == 64
	assert redirect_uri == 'http://localhost:3000/api/auth/callback/test'
	return OAuthIdentity{
		id:             'provider-user-123'
		email:          'oauth@example.com'
		email_verified: p.verified
		name:           'OAuth User'
	}
}

struct OAuthStartResponse {
	url string
}

fn start_test_oauth(mut auth Auth) !(string, string) {
	r := auth.call(Request{
		method: 'POST'
		url:    'http://localhost:3000/api/auth/sign-in/social'
		body:   '{"provider":"test","callbackURL":"/dashboard"}'
	})
	assert r.status == 200
	url := json.decode(OAuthStartResponse, r.body)!.url
	state := urllib.parse(url)!.query().get('state') or { return error('missing state') }
	mut cookie := ''
	for header in r.headers {
		if header.name == 'set-cookie' { cookie = header.value.all_before(';') }
	}
	assert cookie != ''
	return state, cookie
}

fn test_oauth_binds_state_to_browser_and_rejects_replay() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:           '12345678901234567890123456789012'
		password_hasher:  FastHasher{}
		social_providers: [OAuthProvider(FakeProvider{})]
	}, storage)!
	defer { auth.close() or {} }
	state, cookie := start_test_oauth(mut auth)!
	url := 'http://localhost:3000/api/auth/callback/test?code=good-code&state=' + state
	assert auth.handle(Request{ url: url }).status == 403
	completed := auth.handle(Request{
		url:     url
		headers: {
			'cookie': cookie
		}
	})
	assert completed.status == 302
	mut session_cookie := ''
	for header in completed.headers {
		if header.name == 'set-cookie' && header.value.starts_with('better-auth.session_token=') {
			session_cookie = header.value.all_before(';')
		}
	}
	assert session_cookie != ''
	current := (auth.get_session(RequestContext{
		headers: {
			'cookie': session_cookie
		}
	})!).value or { return error('missing OAuth session') }
	assert current.user.email == 'oauth@example.com'
	assert current.user.email_verified
	assert auth.handle(Request{
		url:     url
		headers: {
			'cookie': cookie
		}
	}).status == 400
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 1
	state2, cookie2 := start_test_oauth(mut auth)!
	assert auth.handle(Request{
		url:     'http://localhost:3000/api/auth/callback/test?code=good-code&state=' + state2
		headers: {
			'cookie': cookie2
		}
	}).status == 302
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 1
}

fn test_oauth_never_links_existing_accounts_by_email_implicitly() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:           '12345678901234567890123456789012'
		password_hasher:  FastHasher{}
		social_providers: [OAuthProvider(FakeProvider{})]
	}, storage)!
	defer { auth.close() or {} }
	auth.sign_up_email(SignUpInput{
		email:    'oauth@example.com'
		password: 'password123'
		name:     'Existing'
	}, RequestContext{})!
	state, cookie := start_test_oauth(mut auth)!
	r := auth.handle(Request{
		url:     'http://localhost:3000/api/auth/callback/test?code=good-code&state=' + state
		headers: {
			'cookie': cookie
		}
	})
	assert r.status == 409
	assert storage.db.q_int("SELECT count(*) FROM auth_account WHERE provider_id='test'")! == 0
}

fn test_oauth_rejects_unverified_provider_email() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:           '12345678901234567890123456789012'
		password_hasher:  FastHasher{}
		social_providers: [OAuthProvider(FakeProvider{
			verified: false
		})]
	}, storage)!
	defer { auth.close() or {} }
	state, cookie := start_test_oauth(mut auth)!
	r := auth.handle(Request{
		url:     'http://localhost:3000/api/auth/callback/test?code=good-code&state=' + state
		headers: {
			'cookie': cookie
		}
	})
	assert r.status == 403
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 0
}

fn test_close_is_idempotent_and_rejects_further_requests() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
	}, storage)!
	auth.close()!
	auth.close()!
	assert auth.handle(Request{ url: 'http://localhost:3000/api/auth/ok' }).status == 503
}

fn test_rate_limit_keys_remain_bounded_for_dynamic_callback_paths() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
	}, storage)!
	defer { auth.close() or {} }
	for i in 0 .. 20 {
		auth.handle(Request{ url: 'http://localhost:3000/api/auth/callback/provider-${i}' })
		auth.handle(Request{ url: 'http://localhost:3000/api/auth/reset-password/token-${i}' })
	}
	assert auth.limits.len == 2
}

fn test_oauth_new_user_cannot_bypass_registration_policy() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:             '12345678901234567890123456789012'
		password_hasher:    FastHasher{}
		social_providers:   [OAuthProvider(FakeProvider{})]
		validate_user_info: fn (user User, source UserInfoSource) !ValidationDecision {
			assert source.method == 'oauth'
			assert user.email == 'oauth@example.com'
			info := source.oauth or { return error('missing provider source') }
			assert info.provider_id == 'test'
			return ValidationDecision{
				error:             'registration_closed'
				error_description: 'Registration closed'
			}
		}
	}, storage)!
	defer { auth.close() or {} }
	state, cookie := start_test_oauth(mut auth)!
	response := auth.handle(Request{
		url:     'http://localhost:3000/api/auth/callback/test?code=good-code&state=' + state
		headers: {
			'cookie': cookie
		}
	})
	assert response.status == 403
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 0
}

fn test_typed_additional_fields_preserve_data_and_cannot_override_core_input() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
		plugins:         [Plugin(BearerPlugin{})]
		user_fields:     {
			'team': AdditionalField{
				field_type: 'string'
				required:   true
			}
		}
	}, storage)!
	defer { auth.close() or {} }
	result := auth.sign_up_email(SignUpInput{
		email:             'team@example.com'
		password:          'password123'
		name:              'Team'
		additional_fields: {
			'team': json2.Any('V')
		}
	}, RequestContext{})!
	team := result.user.additional_fields['team'] or { return error('missing team') }
	assert team.str() == 'V'
	token := result.token or { return error('missing token') }
	current := (auth.get_session(RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	})!).value or { return error('missing session') }
	assert (current.user.additional_fields['team'] or { return error('missing team') }).str() == 'V'
	auth.sign_up_email(SignUpInput{
		email:             'other@example.com'
		password:          'password123'
		name:              'Team'
		additional_fields: {
			'email': json2.Any('override@example.com')
		}
	}, RequestContext{}) or {
		assert err.code() == 400
		return
	}
	assert false, 'reserved input must be rejected'
}

struct TestClock {
mut:
	now i64 = 1000000000
}

fn test_deferred_session_get_is_compatible_with_a_read_only_database() ! {
	mut clock := &TestClock{}
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:                '12345678901234567890123456789012'
		password_hasher:       FastHasher{}
		plugins:               [Plugin(BearerPlugin{})]
		defer_session_refresh: true
		session_update_age:    0
		session_expires_in:    60
		clock:                 fn [clock] () i64 {
			return clock.now
		}
	}, storage)!
	defer { auth.close() or {} }
	registered := auth.sign_up_email(SignUpInput{
		email:    'readonly@example.com'
		name:     'Read Only'
		password: 'password123'
	}, RequestContext{})!
	token := registered.token or { return error('missing token') }
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	}
	storage.db.exec('PRAGMA query_only = ON')!
	current := (auth.get_session(ctx)!).value or { return error('missing session') }
	assert current.needs_refresh or { false }
	clock.now += 61
	assert (auth.get_session(ctx)!).value == none
	assert storage.db.q_int('SELECT count(*) FROM auth_session')! == 1
	storage.db.exec('PRAGMA query_only = OFF')!
	response := auth.call(Request{
		method:  'POST'
		url:     'http://localhost:3000/api/auth/get-session'
		headers: ctx.headers
		body:    '{}'
	})
	assert response.status == 200
	assert response.body == 'null'
	assert storage.db.q_int('SELECT count(*) FROM auth_session')! == 0
}

fn test_typed_session_fields_update_and_list_round_trip() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: FastHasher{}
		plugins:         [Plugin(BearerPlugin{})]
		session_fields:  {
			'theme': AdditionalField{
				field_type:    'string'
				default_value: json2.Any('light')
			}
		}
	}, storage)!
	defer { auth.close() or {} }
	created := auth.sign_up_email(SignUpInput{
		email:    'session-fields@example.com'
		name:     'Session Fields'
		password: 'password123'
	}, RequestContext{})!
	token := created.token or { return error('missing token') }
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	}
	updated := auth.update_session({
		'theme': json2.Any('dark')
	}, ctx)!
	assert (updated.additional_fields['theme'] or { return error('missing theme') }).str() == 'dark'
	listed := auth.list_sessions(ctx)!
	assert listed.len == 1
	assert (listed[0].additional_fields['theme'] or { return error('missing theme') }).str() == 'dark'
}
