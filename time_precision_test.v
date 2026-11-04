module better_auth

import json

@[heap]
struct PrecisionClock {
mut:
	now i64
}

@[heap]
struct PrecisionDelivery {
mut:
	token        string
	request_url  string
	request_body string
}

fn test_legacy_verification_rows_and_native_reset_request_metadata() ! {
	mut clock := &PrecisionClock{
		now: 1234
	}
	mut delivery := &PrecisionDelivery{}
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	storage.create_user(User{
		id:         'owner'
		email:      'legacy@example.com'
		name:       'Legacy'
		created_at: stamp_millis(clock.now)
		updated_at: stamp_millis(clock.now)
	})!
	token := random_token()!
	id := digest(token)
	// An actual pre-upgrade JSON row has no millisecond-expiry field.
	legacy := '{"id":${json.encode(id)},"identifier":"reset-password","value":"owner","expires_at":2}'
	storage.db.exec_param_many('INSERT INTO auth_verification (id,identifier,data) VALUES (?,?,?)', [
		id,
		'reset-password',
		legacy,
	])!
	mut auth := new(Config{
		secret:                    'legacy-expiry-secret-at-least-32-characters'
		clock:                     fn [clock] () i64 {
			return clock.now / 1000
		}
		clock_millis:              fn [clock] () i64 {
			return clock.now
		}
		password_reset_expires_in: 1
		send_email:                fn [mut delivery] (message EmailMessage) ! {
			request := message.request or { return error('HTTP request metadata was lost') }
			delivery.token = message.token
			delivery.request_url = request.url
			delivery.request_body = request.body
		}
	}, storage)!
	defer { auth.close() or {} }
	assert auth.token_user(token, 'reset-password')!.id == 'owner'
	clock.now = 2000
	assert auth.token_user(token, 'reset-password')!.id == 'owner'
	clock.now = 2001
	mut expired := false
	auth.token_user(token, 'reset-password') or {
		expired = true
		User{}
	}
	assert expired
	response := auth.handle(Request{
		method:  'POST'
		url:     'http://localhost:3000/api/auth/request-password-reset'
		headers: {
			'content-type': 'application/json'
			'origin':       'http://localhost:3000'
		}
		body:    '{"email":"legacy@example.com"}'
	})
	assert response.status == 200
	assert delivery.request_url.ends_with('/request-password-reset')
	assert delivery.request_body == '{"email":"legacy@example.com"}'
	created := (storage.verification(digest(delivery.token))!).value or {
		return error('missing new verification row')
	}

	assert (created.expires_at_millis or { -1 }) == 3001
}

fn test_native_secondary_ttl_uses_milliseconds_and_keeps_increment_deadlines() ! {
	mut clock := &PrecisionClock{
		now: 1900
	}
	mut storage := memory_secondary_storage_with_millis(fn [clock] () i64 {
		return clock.now
	})
	storage.set('counter', '1', 1)!
	storage.set('persistent', 'value', 0)!
	clock.now = 2000
	assert ((storage.get('counter')!).value or { 'missing' }) == '1'
	assert storage.increment('counter', 30)! == 2
	clock.now = 2899
	assert ((storage.get('counter')!).value or { 'missing' }) == '2'
	clock.now = 2900
	assert (storage.get('counter')!).value == none
	clock.now = 1000000
	assert ((storage.get_and_delete('persistent')!).value or { 'missing' }) == 'value'
	assert (storage.get('persistent')!).value == none
}
