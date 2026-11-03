module better_auth

import crypto.sha256
import encoding.hex
import encoding.base64
import json
import os

struct SecondaryTestHasher {}

fn test_v1_rows_survive_migration_to_sealed_tokens_and_column_aliases() ! {
	mut storage := open_sqlite_with_options(':memory:', SQLiteOptions{
		account_fields: {
			'providerId': 'provider'
			'accountId':  'subject'
		}
	})!
	storage.db.exec('CREATE TABLE auth_migration (version INTEGER PRIMARY KEY)')!
	for statement in schema_v1 {
		storage.db.exec(statement)!
	}
	storage.db.exec('INSERT INTO auth_migration VALUES (1)')!
	user := User{
		id:    'legacy-user'
		email: 'legacy@example.com'
		name:  'Legacy'
	}
	storage.create_user(user)!
	storage.db.exec_param_many('INSERT INTO auth_account VALUES (?,?,?,?,?)', [
		'legacy-account',
		user.id,
		'credential',
		user.id,
		'{"id":"legacy-account","user_id":"legacy-user","provider_id":"credential","account_id":"legacy-user","password":"legacy-hash"}',
	])!
	token := 'ab'.repeat(32)
	session := Session{
		id:         'legacy-session'
		user_id:    user.id
		expires_at: stamp(1000000600)
		created_at: stamp(1000000000)
		updated_at: stamp(1000000000)
	}
	storage.db.exec_param_many('INSERT INTO auth_session VALUES (?,?,?,?,?)', [session.id, user.id,
		digest(token), encode_session(session), '1'])!
	storage.migrate()!
	storage.migrate()!
	assert storage.db.q_int('SELECT count(*) FROM auth_migration')! == 4
	account := (storage.account(user.id, 'credential')!).value or {
		return error('legacy account lost')
	}

	assert account.provider_id == 'credential'
	assert account.user_id == user.id
	assert account.password == 'legacy-hash'
	assert json.encode(account).contains('"userId"')
	mut auth := new(Config{
		secret:  '12345678901234567890123456789012'
		clock:   fn () i64 {
			return 1000000000
		}
		plugins: [Plugin(BearerPlugin{})]
	}, storage)!
	defer { auth.close() or {} }
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ' + token
		}
	}
	assert ((auth.get_session(ctx)!).value or { return error('legacy session lost') }).session.token == token
	assert auth.list_sessions(ctx)![0].token == session.id
	auth.revoke_session(session.id, ctx)!
	assert (auth.get_session(ctx)!).value == none
}

fn (_ SecondaryTestHasher) hash(password string) !string {
	return hex.encode(sha256.sum(password.bytes()))
}

fn (h SecondaryTestHasher) verify(password string, encoded string) !bool {
	return h.hash(password)! == encoded
}

struct SecondaryTestClock {
mut:
	now i64 = 1000000000
}

fn take_secondary_once(mut cache MemorySecondaryStorage) int {
	value := cache.get_and_delete('once') or { return 0 }
	return if value.value != none { 1 } else { 0 }
}

fn test_secondary_ttl_counters_and_atomic_consumption() ! {
	mut clock := &SecondaryTestClock{}
	mut cache := memory_secondary_storage(fn [clock] () i64 {
		return clock.now
	})
	assert cache.increment('counter', 10)! == 1
	clock.now += 5
	assert cache.increment('counter', 10)! == 2
	clock.now += 5
	assert (cache.get('counter')!).value == none
	assert cache.increment('counter', 10)! == 1
	cache.set('once', 'token', 0)!
	mut threads := []thread int{}
	for _ in 0 .. 32 {
		threads << spawn take_secondary_once(mut cache)
	}
	mut total := 0
	for result in threads.wait() {
		total += result
	}
	assert total == 1
	assert (cache.get('once')!).value == none
}

struct SecondaryHookLog {
mut:
	events []string
	token  string
}

struct SecondaryTestHook {
	log          &SecondaryHookLog
	revoke_after bool
}

fn (h SecondaryTestHook) run(mut context EndpointContext, event DatabaseEvent) !HookResult {
	mut log := h.log
	log.events << '${event.model}.${event.operation}.${event.phase}'
	if event.phase == 'before' && event.operation == 'create' {
		assert context.auth.transaction_active
	} else if event.phase == 'after' {
		assert !context.auth.transaction_active
	}
	if event.model == 'user' && event.operation == 'create' && event.phase == 'before' {
		return HookResult{
			data_json: '{"name":"Changed by native hook"}'
		}
	}
	if event.model == 'session' && event.operation == 'create' {
		session := decode_session(event.data_json)!
		log.token = session.token
		if event.phase == 'after' && h.revoke_after { context.delete_session(session.token)! }
	}
	return HookResult{}
}

fn test_primary_secondary_sessions_round_trip_and_refresh_user_data() ! {
	mut clock := &SecondaryTestClock{}
	mut cache := memory_secondary_storage(fn [clock] () i64 {
		return clock.now
	})
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:            '12345678901234567890123456789012'
		password_hasher:   SecondaryTestHasher{}
		secondary_storage: cache
		plugins:           [Plugin(BearerPlugin{})]
		clock:             fn [clock] () i64 {
			return clock.now
		}
	}, storage)!
	defer { auth.close() or {} }
	created := auth.sign_up_email(SignUpInput{
		email:    'primary@example.com'
		name:     'Primary'
		password: 'password123'
	}, RequestContext{})!
	token := created.token or { return error('missing token') }
	assert storage.db.q_int('SELECT count(*) FROM auth_session')! == 0
	assert (cache.get(token)!).value != none
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	}
	current := (auth.get_session(ctx)!).value or { return error('missing cached session') }
	assert current.user.id == created.user.id
	assert auth.list_sessions(ctx)![0].token == token
	auth.with_internal(fn [created] (mut context EndpointContext) !string {
		context.update_user(User{ ...created.user, name: 'Updated' })!
		return 'null'
	})!
	updated := (auth.get_session(ctx)!).value or { return error('missing updated session') }
	assert updated.user.name == 'Updated'
	auth.sign_out(ctx)!
	assert (auth.get_session(ctx)!).value == none
	assert (cache.get(token)!).value == none
	assert (cache.get('active-sessions-' + created.user.id)!).value == none
}

fn test_mirrors_and_after_hooks_run_only_for_committed_work() ! {
	mut clock := &SecondaryTestClock{}
	mut cache := memory_secondary_storage(fn [clock] () i64 {
		return clock.now
	})
	mut log := &SecondaryHookLog{}
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:                    '12345678901234567890123456789012'
		password_hasher:           SecondaryTestHasher{}
		secondary_storage:         cache
		store_session_in_database: true
		database_hooks:            [DatabaseHook(SecondaryTestHook{
			log: log
		})]
		before_commit:             fn (mut _ EndpointContext) ! {
			return error('transaction aborted')
		}
	}, storage)!
	defer { auth.close() or {} }
	r := auth.call(Request{
		method: 'POST'
		url:    'http://localhost:3000/api/auth/sign-up/email'
		body:   '{"email":"rollback@example.com","name":"Rollback","password":"password123"}'
	})
	assert r.status == 500
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 0
	assert storage.db.q_int('SELECT count(*) FROM auth_session')! == 0
	for event in log.events {
		assert event.ends_with('.before')
	}
	assert log.token != ''
	assert (cache.get(log.token)!).value == none
}

fn test_after_hook_can_revoke_a_committed_mirrored_session() ! {
	mut clock := &SecondaryTestClock{}
	mut cache := memory_secondary_storage(fn [clock] () i64 {
		return clock.now
	})
	mut log := &SecondaryHookLog{}
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:                    '12345678901234567890123456789012'
		password_hasher:           SecondaryTestHasher{}
		secondary_storage:         cache
		store_session_in_database: true
		database_hooks:            [
			DatabaseHook(SecondaryTestHook{
				log:          log
				revoke_after: true
			}),
		]
	}, storage)!
	defer { auth.close() or {} }
	created := auth.sign_up_email(SignUpInput{
		email:    'revoked@example.com'
		name:     'Original'
		password: 'password123'
	}, RequestContext{})!
	token := created.token or { return error('missing token') }
	assert created.user.name == 'Changed by native hook'
	assert storage.db.q_int('SELECT count(*) FROM auth_user')! == 1
	assert storage.db.q_int('SELECT count(*) FROM auth_session')! == 0
	assert (cache.get(token)!).value == none
	assert 'session.create.after' in log.events
	assert 'session.delete.after' in log.events
}

fn test_preserved_session_rows_are_expired_and_never_restored_from_database() ! {
	mut clock := &SecondaryTestClock{}
	mut cache := memory_secondary_storage(fn [clock] () i64 {
		return clock.now
	})
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:                       '12345678901234567890123456789012'
		password_hasher:              SecondaryTestHasher{}
		secondary_storage:            cache
		store_session_in_database:    true
		preserve_session_in_database: true
		clock:                        fn [clock] () i64 {
			return clock.now
		}
		plugins:                      [Plugin(BearerPlugin{})]
	}, storage)!
	defer { auth.close() or {} }
	created := auth.sign_up_email(SignUpInput{
		email:    'preserved@example.com'
		name:     'Preserved'
		password: 'password123'
	}, RequestContext{})!
	token := created.token or { return error('missing token') }
	ctx := RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	}
	auth.sign_out(ctx)!
	assert (auth.get_session(ctx)!).value == none
	rows := storage.sessions(created.user.id)!
	assert rows.len == 1
	assert epoch(rows[0].expires_at)! == clock.now
	assert (cache.get(token)!).value == none
}

fn test_database_session_tokens_are_recoverable_only_with_authentication() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	mut auth := new(Config{
		secret:          '12345678901234567890123456789012'
		password_hasher: SecondaryTestHasher{}
		plugins:         [Plugin(BearerPlugin{})]
	}, storage)!
	defer { auth.close() or {} }
	created := auth.sign_up_email(SignUpInput{
		email:    'encrypted@example.com'
		name:     'Encrypted'
		password: 'password123'
	}, RequestContext{})!
	token := created.token or { return error('missing token') }
	stored := storage.sessions(created.user.id)![0]
	assert stored.token == ''
	assert stored.encrypted_token != ''
	assert auth.unseal_session_token(stored)! == token
	assert !storage.db.q_string('SELECT data FROM auth_session')!.contains(token)
	assert auth.list_sessions(RequestContext{
		headers: {
			'authorization': 'Bearer ${token}'
		}
	})![0].token == token
	mut corrupted := base64.url_decode(stored.encrypted_token)
	corrupted[corrupted.len - 1] ^= 1
	auth.unseal_session_token(Session{ ...stored, encrypted_token: base64.url_encode(corrupted) }) or {
		return
	}
	assert false, 'tampered authentication tag must fail'
}

fn test_account_columns_are_migrated_and_queried_using_real_aliases() ! {
	path := os.join_path(os.temp_dir(), 'ba-columns-${random_token()!}.db')
	defer { os.rm(path) or {} }
	mut original := open_sqlite(path)!
	original.migrate()!
	original.create_user(User{ id: 'mapped-user', email: 'mapped@example.com', name: 'Mapped' })!
	original.create_account(Account{
		id:          'mapped-account'
		user_id:     'mapped-user'
		provider_id: 'credential'
		account_id:  'mapped-user'
		password:    'hash'
	})!
	original.close()!
	mut mapped := open_sqlite_with_options(path, SQLiteOptions{
		account_fields: {
			'providerId': 'provider key'
			'accountId':  'external"subject'
			'userId':     'owner'
			'id':         'record_id'
		}
	})!
	defer { mapped.close() or {} }
	mapped.migrate()!
	mapped.migrate()!
	columns := mapped.db.columns('auth_account')!
	assert 'provider key' in columns
	assert 'external"subject' in columns
	assert 'provider_id' !in columns
	account := (mapped.account('mapped-user', 'credential')!).value or {
		return error('mapped record missing')
	}

	assert account.id == 'mapped-account'
	assert account.password == 'hash'
	mapped.set_password('mapped-user', 'new-hash')!
	assert (mapped.account_by_provider('credential', 'mapped-user')!).value or {
		return error('mapped account missing')
	} == Account{
		...account
		password: 'new-hash'
	}
	mapped.delete_account('mapped-account')!
	assert mapped.accounts('mapped-user')!.len == 0
}
