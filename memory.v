module better_auth

// The in-process adapter owns records independently of SQLite. Like a database
// connection, it is serialized by Auth; independent Auth instances need their own
// adapters. A transaction snapshots maps and restores them on rollback.
struct MemoryRecords {
mut:
	keys          map[string]Jwk
	users         map[string]User
	accounts      map[string]Account
	sessions      map[string]Session
	token_hashes  map[string]string
	verifications map[string]Verification
}

@[heap]
pub struct MemoryStorage {
mut:
	records     MemoryRecords
	backup      MemoryRecords
	transaction bool
	read_only   bool
	closed      bool
}

pub fn open_memory() &MemoryStorage {
	return &MemoryStorage{}
}

fn (s &MemoryStorage) check_open() ! {
	if s.closed { return error('memory adapter is closed') }
}

fn (s &MemoryStorage) check_write() ! {
	s.check_open()!
	if s.read_only { return error('cannot write a read-only transaction') }
}

pub fn (mut s MemoryStorage) begin() ! {
	s.check_open()!
	if s.transaction { return error('transaction is already active') }
	s.backup = MemoryRecords{
		keys:          s.records.keys.clone()
		users:         s.records.users.clone()
		accounts:      s.records.accounts.clone()
		sessions:      s.records.sessions.clone()
		token_hashes:  s.records.token_hashes.clone()
		verifications: s.records.verifications.clone()
	}
	s.transaction = true
}

pub fn (mut s MemoryStorage) jwks() ![]Jwk {
	s.check_open()!
	return s.records.keys.values()
}

pub fn (mut s MemoryStorage) create_jwk(key Jwk) ! {
	s.check_write()!
	if key.id in s.records.keys { return error('duplicate JWK id') }
	s.records.keys[key.id] = key
}

pub fn (mut s MemoryStorage) begin_read() ! {
	s.begin()!
	s.read_only = true
}

pub fn (mut s MemoryStorage) commit() ! {
	s.check_open()!
	if !s.transaction { return error('no transaction is active') }
	s.backup = MemoryRecords{}
	s.transaction = false
	s.read_only = false
}

pub fn (mut s MemoryStorage) rollback() ! {
	s.check_open()!
	if !s.transaction { return error('no transaction is active') }
	s.records = s.backup
	s.backup = MemoryRecords{}
	s.transaction = false
	s.read_only = false
}

pub fn (mut s MemoryStorage) close() ! {
	s.records = MemoryRecords{}
	s.backup = MemoryRecords{}
	s.closed = true
}

pub fn (mut s MemoryStorage) user(id string) !Lookup[User] {
	s.check_open()!
	if user := s.records.users[id] { return Lookup[User]{
			value: user
		} }
	return Lookup[User]{}
}

pub fn (mut s MemoryStorage) user_by_email(email string) !Lookup[User] {
	s.check_open()!
	for _, user in s.records.users {
		if user.email.to_lower() == email.to_lower() { return Lookup[User]{
				value: user
			} }
	}
	return Lookup[User]{}
}

pub fn (mut s MemoryStorage) users() ![]User {
	s.check_open()!
	return s.records.users.values()
}

pub fn (mut s MemoryStorage) create_user(user User) ! {
	s.check_write()!
	if user.id in s.records.users || (s.user_by_email(user.email)!).value != none {
		return error('duplicate user id or email')
	}
	s.records.users[user.id] = user
}

pub fn (mut s MemoryStorage) update_user(user User) ! {
	s.check_write()!
	if existing := (s.user_by_email(user.email)!).value {
		if existing.id != user.id { return error('duplicate user email') }
	}
	if user.id in s.records.users { s.records.users[user.id] = user }
}

pub fn (mut s MemoryStorage) delete_user(id string) ! {
	s.check_write()!
	s.records.users.delete(id)
	for account in s.accounts(id)! {
		s.records.accounts.delete(account.id)
	}
	s.delete_sessions(id, '')!
}

pub fn (mut s MemoryStorage) account(user_id string, provider string) !Lookup[Account] {
	s.check_open()!
	for _, account in s.records.accounts {
		if account.user_id == user_id && account.provider_id == provider
			&& (provider != 'credential' || account.account_id == user_id) {
			return Lookup[Account]{
				value: account
			}
		}
	}
	return Lookup[Account]{}
}

pub fn (mut s MemoryStorage) account_by_provider(provider string, subject string) !Lookup[Account] {
	s.check_open()!
	for _, account in s.records.accounts {
		if account.provider_id == provider && account.account_id == subject {
			return Lookup[Account]{
				value: account
			}
		}
	}
	return Lookup[Account]{}
}

pub fn (mut s MemoryStorage) accounts(user_id string) ![]Account {
	s.check_open()!
	return s.records.accounts.values().filter(user_id == '' || it.user_id == user_id)
}

pub fn (mut s MemoryStorage) account_by_id(id string) !Lookup[Account] {
	s.check_open()!
	if account := s.records.accounts[id] { return Lookup[Account]{
			value: account
		} }
	return Lookup[Account]{}
}

pub fn (mut s MemoryStorage) delete_account(id string) ! {
	s.check_write()!
	s.records.accounts.delete(id)
}

pub fn (mut s MemoryStorage) create_account(account Account) ! {
	s.check_write()!
	if account.user_id !in s.records.users { return error('account user does not exist') }
	if account.id in s.records.accounts
		|| (s.account_by_provider(account.provider_id, account.account_id)!).value != none {
		return error('duplicate account key')
	}
	s.records.accounts[account.id] = account
}

pub fn (mut s MemoryStorage) set_password(user_id string, password string) ! {
	s.check_write()!
	if account := (s.account(user_id, 'credential')!).value {
		s.records.accounts[account.id] = Account{
			...account
			password: password
		}
	}
}

pub fn (mut s MemoryStorage) create_session(session Session, token_hash string) ! {
	s.check_write()!
	if session.user_id !in s.records.users { return error('session user does not exist') }
	if session.id in s.records.sessions || token_hash in s.records.token_hashes {
		return error('duplicate session id or token')
	}
	s.records.sessions[session.id] = Session{
		...session
		token: ''
	}
	s.records.token_hashes[token_hash] = session.id
}

pub fn (mut s MemoryStorage) session(token_hash string) !Lookup[Session] {
	s.check_open()!
	id := s.records.token_hashes[token_hash] or { return Lookup[Session]{} }
	return s.session_by_id(id)
}

pub fn (mut s MemoryStorage) session_by_id(id string) !Lookup[Session] {
	s.check_open()!
	if session := s.records.sessions[id] { return Lookup[Session]{
			value: session
		} }
	return Lookup[Session]{}
}

pub fn (mut s MemoryStorage) sessions(user_id string) ![]Session {
	s.check_open()!
	return s.records.sessions.values().filter(it.user_id == user_id)
}

pub fn (mut s MemoryStorage) update_session(session Session) ! {
	s.check_write()!
	if session.user_id !in s.records.users { return error('session user does not exist') }
	if session.id in s.records.sessions { s.records.sessions[session.id] = Session{
			...session
			token: ''
		} }
}

pub fn (mut s MemoryStorage) delete_session(id string) ! {
	s.check_write()!
	s.records.sessions.delete(id)
	for hash, session_id in s.records.token_hashes.clone() {
		if session_id == id { s.records.token_hashes.delete(hash) }
	}
}

pub fn (mut s MemoryStorage) delete_sessions(user_id string, except_id string) ! {
	s.check_write()!
	for session in s.sessions(user_id)! {
		if session.id != except_id { s.delete_session(session.id)! }
	}
}

pub fn (mut s MemoryStorage) create_verification(value Verification) ! {
	s.check_write()!
	if value.id in s.records.verifications { return error('duplicate verification id') }
	s.records.verifications[value.id] = value
}

pub fn (mut s MemoryStorage) verification(id string) !Lookup[Verification] {
	s.check_open()!
	if value := s.records.verifications[id] { return Lookup[Verification]{
			value: value
		} }
	return Lookup[Verification]{}
}

pub fn (mut s MemoryStorage) delete_verification(id string) ! {
	s.check_write()!
	s.records.verifications.delete(id)
}

pub fn (mut s MemoryStorage) update_account(updated Account) ! {
	old := (s.account_by_id(updated.id)!).value or { return error('account not found') }
	if old.user_id != updated.user_id || old.provider_id != updated.provider_id
		|| old.account_id != updated.account_id {
		return error('account update cannot change identity')
	}
	s.check_write()!
	s.records.accounts[updated.id] = updated
}

// Trusted adapter inspection, never exposed through an HTTP endpoint.
pub fn (mut s MemoryStorage) verifications() ![]Verification {
	s.check_open()!
	return s.records.verifications.values()
}
