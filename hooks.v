module better_auth

import json
import time
import x.json2

struct AfterCommitTask {
	kind    string
	event   DatabaseEvent
	session Session
	user    User
}

fn merge_record_json(base string, patch string) !string {
	mut fields := json2.decode[map[string]json2.Any](base)!
	updates := json2.decode[map[string]json2.Any](patch)!
	for key, value in updates {
		fields[key] = value
	}
	return json2.Any(fields).json_str()
}

fn (mut a Auth) before_record(model string, operation string, data string) !Lookup[string] {
	mut encoded := data
	mut context := EndpointContext{
		auth: a
	}
	for hook in a.config.database_hooks {
		result := hook.run(mut context, DatabaseEvent{
			model:     model
			operation: operation
			phase:     'before'
			data_json: encoded
		}) or { return as_application_error(err) }
		if result.cancel { return Lookup[string]{} }
		if patch := result.data_json { encoded = merge_record_json(encoded, patch)! }
	}
	return Lookup[string]{
		value: encoded
	}
}

fn (mut a Auth) after_record(model string, operation string, data string) ! {
	if a.config.database_hooks.len == 0 { return }
	a.queue_task(AfterCommitTask{
		kind:  'hook'
		event: DatabaseEvent{
			model:     model
			operation: operation
			phase:     'after'
			data_json: data
		}
	})!
}

fn (mut a Auth) queue_task(task AfterCommitTask) ! {
	if a.transaction_active && a.transactions_enabled {
		a.pending_tasks << task
	} else {
		a.run_task(task)!
	}
}

fn (mut a Auth) run_task(task AfterCommitTask) ! {
	if task.kind == 'remove-session' {
		a.remove_cached_session(task.session)!
		return
	}
	if task.kind == 'password-reset' {
		a.config.on_password_reset(task.user)!
		return
	}
	if task.kind == 'mirror-session' {
		a.mirror_session(task.session) or {
			a.config.log('error', 'Failed to mirror committed session to secondary storage')
		}
		return
	}
	mut context := EndpointContext{
		auth: a
	}
	for hook in a.config.database_hooks {
		hook.run(mut context, task.event) or { return as_application_error(err) }
	}
}

fn (mut a Auth) begin_transaction(read_only bool) ! {
	if a.transaction_active { return error('transaction is already active') }
	if a.transactions_enabled {
		if read_only {
			a.storage.begin_read()!
		} else {
			a.storage.begin()!
		}
	}
	a.transaction_active = true
	a.pending_tasks = []AfterCommitTask{}
	a.secondary_created = []Session{}
}

fn (mut a Auth) commit_transaction() ! {
	mut context := EndpointContext{
		auth: a
	}
	a.config.before_commit(mut context)!
	if a.transactions_enabled { a.storage.commit()! }
	a.transaction_active = false
	a.secondary_created = []Session{}
	tasks := a.pending_tasks.clone()
	a.pending_tasks = []AfterCommitTask{}
	for task in tasks {
		a.run_task(task)!
	}
}

fn (mut a Auth) rollback_transaction() {
	if !a.transaction_active { return }
	if a.transactions_enabled { a.storage.rollback() or {
			a.config.log('error', 'Database rollback failed')} }
	a.transaction_active = false
	a.pending_tasks = []AfterCommitTask{}
	for session in a.secondary_created {
		a.remove_cached_session(session) or {
			a.config.log('error', 'Failed to remove rolled-back secondary session')
		}
	}
	a.secondary_created = []Session{}
}

// Trusted server-side internal operations get the same transaction and hooks as
// HTTP operations. Hooks use their existing EndpointContext to avoid re-locking.
pub fn (mut a Auth) with_internal(operation fn (mut EndpointContext) !string) !string {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed { return error('Auth instance is closed') }
	a.begin_transaction(false)!
	defer { a.rollback_transaction() }
	mut context := EndpointContext{
		auth: a
	}
	result := operation(mut context)!
	a.commit_transaction()!
	return result
}

// EndpointContext already owns Auth's lock. Nested work shares an active
// transaction; after-commit work starts a new one without re-locking Auth.
pub fn (c &EndpointContext) has_active_transaction() bool {
	return c.auth.transaction_active
}

pub fn (mut c EndpointContext) with_transaction(operation fn (mut EndpointContext) !string) !string {
	if c.auth.transaction_active { return operation(mut c) }
	c.auth.begin_transaction(false)!
	defer { c.auth.rollback_transaction() }
	result := operation(mut c)!
	c.auth.commit_transaction()!
	return result
}

fn (mut a Auth) persist_user(user User) !User {
	mut prepared := user
	for plugin in a.config.plugins {
		if plugin is UserCreationPlugin { prepared = plugin.prepare_user(prepared)! }
	}
	encoded := (a.before_record('user', 'create', encode_user(prepared))!).value or {
		return fail(400, 'FAILED_TO_CREATE_USER', 'Failed to create user')
	}

	decoded := decode_user(encoded)!
	actual := User{
		...decoded
		additional_fields: fill_field_defaults(a.config.user_fields, decoded.additional_fields)!
	}
	a.storage.create_user(actual)!
	a.after_record('user', 'create', encode_user(actual))!
	return actual
}

fn (mut a Auth) update_user_record(user User) !User {
	encoded := (a.before_record('user', 'update', encode_user(user))!).value or { return user }
	mut actual := decode_user(encoded)!
	if actual.id != user.id { return error('user update hook cannot change the primary key') }
	mut storage := a.storage
	if mut storage is UserUpdateReturningStorage {
		actual = storage.update_user_returning(actual)!
	} else {
		a.storage.update_user(actual)!
	}
	a.refresh_cached_user(actual)!
	a.after_record('user', 'update', encode_user(actual))!
	return actual
}

fn (mut a Auth) persist_account(account Account) !Account {
	now := stamp_millis(a.clock_millis())
	prepared := Account{
		...account
		created_at: if account.created_at == '' { now } else { account.created_at }
		updated_at: if account.updated_at == '' { now } else { account.updated_at }
	}
	encoded := (a.before_record('account', 'create', json.encode(prepared))!).value or {
		return fail(400, 'FAILED_TO_CREATE_ACCOUNT', 'Failed to create account')
	}

	actual := decode_account(encoded)!
	a.storage.create_account(actual)!
	a.after_record('account', 'create', json.encode(actual))!
	return actual
}

fn (mut a Auth) update_password(user_id string, password string) ! {
	if _ := (a.intercept_internal('updatePassword',
		'[${json.encode(user_id)},${json.encode(password)}]')!).value
	{
		return
	}
	account := (a.storage.account(user_id, 'credential')!).value or {
		return fail(400, 'CREDENTIAL_ACCOUNT_NOT_FOUND', 'Credential account not found')
	}

	updated := Account{
		...account
		password:   password
		updated_at: time.unix_milli(a.clock_millis()).format_rfc3339()
	}
	encoded := (a.before_record('account', 'update', json.encode(updated))!).value or { return }
	actual := decode_account(encoded)!
	a.storage.update_account(actual)!
	a.after_record('account', 'update', json.encode(actual))!
}

fn (mut a Auth) update_account_record(account Account, patch string) ! {
	if _ := (a.intercept_internal('updateAccount', '[${json.encode(account.id)},${patch}]')!).value {
		return
	}
	updated := decode_account(merge_record_json(json.encode(account), patch)!)!
	prepared := Account{
		...updated
		updated_at: time.unix_milli(a.clock_millis()).format_rfc3339()
	}
	encoded := (a.before_record('account', 'update', json.encode(prepared))!).value or { return }
	a.storage.update_account(decode_account(encoded)!)!
	a.after_record('account', 'update', encoded)!
}

fn (mut a Auth) remove_verification(id string) ! {
	value := (a.storage.verification(id)!).value or { return }
	mut encoded := encode_verification(value)
	if value.created_at == '' { encoded = json.encode(value) }
	if (a.before_record('verification', 'delete', encoded)!).value == none {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}
	a.storage.delete_verification(id)!
	a.after_record('verification', 'delete', encoded)!
}

fn (mut a Auth) remove_user(id string) ! {
	user := (a.storage.user(id)!).value or { return }
	if (a.before_record('user', 'delete', encode_user(user))!).value == none { return }
	a.remove_user_sessions(id, '')!
	for account in a.storage.accounts(id)! {
		a.remove_account(account.id)!
	}
	a.storage.delete_user(id)!
	a.after_record('user', 'delete', encode_user(user))!
}

pub fn (mut c EndpointContext) users() ![]User {
	return c.auth.storage.users()
}

pub fn (mut c EndpointContext) find_session(token string) !Lookup[SessionResult] {
	return c.auth.find_session_record(token)
}

pub fn (mut c EndpointContext) list_sessions(user_id string) ![]Session {
	return c.auth.user_sessions(user_id)
}

pub fn (mut c EndpointContext) delete_session(token string) ! {
	c.auth.remove_session(token)!
}

pub fn (mut c EndpointContext) delete_user_sessions(user_id string) ! {
	c.auth.remove_user_sessions(user_id, '')!
}

pub fn (mut c EndpointContext) update_session(session Session) !Session {
	return c.auth.update_session_record(session)
}

// A trusted adapter operation changes the database row directly. It deliberately
// bypasses lifecycle hooks and cache updates, just as an underlying DB adapter does.
pub fn (mut c EndpointContext) adapter_update_session(id string, patch_json string) !Lookup[Session] {
	current := (c.auth.storage.session_by_id(id)!).value or { return Lookup[Session]{} }
	updated := decode_session(merge_record_json(encode_session(current), patch_json)!)!
	if updated.id != current.id || updated.user_id != current.user_id
		|| updated.token != current.token {
		return error('adapter session update cannot change identity')
	}
	actual := Session{
		...updated
		persistent:      current.persistent
		encrypted_token: current.encrypted_token
	}
	c.auth.storage.update_session(actual)!
	return Lookup[Session]{
		value: actual
	}
}

pub fn (mut c EndpointContext) create_user(user User) !User {
	return c.auth.persist_user(user)
}

pub fn (mut c EndpointContext) update_user(user User) !User {
	return c.auth.update_user_record(user)
}

pub fn (mut c EndpointContext) create_account(account Account) !Account {
	return c.auth.persist_account(account)
}

fn (mut a Auth) remove_account(id string) ! {
	account := (a.storage.account_by_id(id)!).value or { return }
	if (a.before_record('account', 'delete', json.encode(account))!).value == none { return }
	a.storage.delete_account(id)!
	a.after_record('account', 'delete', json.encode(account))!
}

pub fn (mut c EndpointContext) accounts(user_id string) ![]Account {
	return c.auth.storage.accounts(user_id)
}
