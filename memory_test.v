module better_auth

fn test_memory_adapter_rolls_back_cascades_and_keeps_canonical_credentials() ! {
	mut storage := open_memory()
	defer { storage.close() or {} }
	u := User{
		id:    'owner'
		email: 'owner@example.com'
		name:  'Owner'
	}
	storage.create_user(u)!
	storage.create_account(Account{
		id:          'other'
		user_id:     u.id
		provider_id: 'credential'
		account_id:  'other'
		password:    'not-canonical'
	})!
	storage.create_account(Account{
		id:          'canonical'
		user_id:     u.id
		provider_id: 'credential'
		account_id:  u.id
		password:    'canonical-hash'
	})!
	storage.create_session(Session{
		id:              'session'
		user_id:         u.id
		token:           'never-stored'
		encrypted_token: 'sealed'
		persistent:      false
	}, 'digest')!
	storage.create_verification(Verification{
		id:         'verification'
		identifier: 'reset'
		value:      u.id
		expires_at: 12345
	})!
	assert ((storage.account(u.id, 'credential')!).value or { return error('missing credential') }).password == 'canonical-hash'
	assert ((storage.session('digest')!).value or { return error('missing session') }).token == ''
	storage.begin()!
	storage.set_password(u.id, 'changed')!
	storage.delete_user(u.id)!
	storage.delete_verification('verification')!
	assert (storage.user(u.id)!).value == none
	assert storage.accounts(u.id)!.len == 0
	assert (storage.session('digest')!).value == none
	storage.rollback()!
	assert ((storage.user_by_email('OWNER@example.com')!).value or { return error('user lost') }).id == u.id
	assert ((storage.account(u.id, 'credential')!).value or { return error('account lost') }).password == 'canonical-hash'
	session := (storage.session('digest')!).value or { return error('session lost') }
	assert !session.persistent
	assert session.encrypted_token == 'sealed'
	assert (storage.verification('verification')!).value != none
	storage.begin()!
	storage.delete_user(u.id)!
	storage.commit()!
	assert (storage.user(u.id)!).value == none
	assert storage.accounts(u.id)!.len == 0
	assert (storage.session('digest')!).value == none
}

fn test_memory_adapter_enforces_unique_and_foreign_keys_without_partial_writes() ! {
	mut storage := open_memory()
	defer { storage.close() or {} }
	storage.create_user(User{ id: 'owner', email: 'owner@example.com' })!
	mut rejected := 0
	storage.create_user(User{ id: 'different-id', email: 'OWNER@example.com' }) or { rejected++ }
	storage.create_account(Account{ id: 'orphan', user_id: 'missing' }) or { rejected++ }
	storage.create_session(Session{ id: 'orphan', user_id: 'missing' }, 'missing') or { rejected++ }
	storage.create_session(Session{ id: 'first', user_id: 'owner' }, 'token')!
	storage.create_session(Session{ id: 'duplicate', user_id: 'owner' }, 'token') or { rejected++ }
	assert rejected == 4
	assert storage.users()!.len == 1
	assert storage.accounts('')!.len == 0
	assert storage.sessions('owner')!.len == 1
	assert ((storage.session('token')!).value or { return error('session lost') }).id == 'first'
}

fn test_memory_read_transactions_reject_writes_and_transactions_can_be_reused() ! {
	mut storage := open_memory()
	defer { storage.close() or {} }
	storage.begin_read()!
	assert storage.users()!.len == 0
	mut rejected := 0
	storage.create_user(User{ id: 'blocked' }) or { rejected++ }
	storage.begin() or { rejected++ }
	assert rejected == 2
	storage.commit()!
	storage.begin()!
	storage.create_user(User{ id: 'committed', email: 'committed@example.com' })!
	storage.commit()!
	assert (storage.user('committed')!).value != none
}
