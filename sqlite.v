module better_auth

import db.sqlite
import json

pub struct SQLiteStorage {
mut:
	db      sqlite.DB
	options SQLiteOptions
}

pub struct SQLiteOptions {
pub:
	account_fields map[string]string
}

const account_columns = {
	'id':         'id'
	'userId':     'user_id'
	'providerId': 'provider_id'
	'accountId':  'account_id'
}

fn sql_identifier(name string) string {
	return '"' + name.replace('"', '""') + '"'
}

fn (s &SQLiteStorage) account_column(name string) string {
	return sql_identifier(s.options.account_fields[name] or { account_columns[name] })
}

// Opening storage never changes its schema. Call migrate explicitly.
pub fn open_sqlite(path string) !SQLiteStorage {
	return open_sqlite_with_options(path, SQLiteOptions{})
}

pub fn open_sqlite_with_options(path string, options SQLiteOptions) !SQLiteStorage {
	mut used := {
		'data': true
	}
	for name, _ in options.account_fields {
		if name !in account_columns { return error('unsupported account column mapping: ${name}') }
	}
	for name, fallback in account_columns {
		column := options.account_fields[name] or { fallback }
		if column == '' || column.contains('\x00') || column.to_lower() in used {
			return error('invalid or duplicate account column name')
		}
		used[column.to_lower()] = true
	}
	db := sqlite.connect(path)!
	db.exec('PRAGMA foreign_keys = ON')!
	db.busy_timeout(5000)
	return SQLiteStorage{
		db:      db
		options: SQLiteOptions{
			account_fields: options.account_fields.clone()
		}
	}
}

pub fn (mut s SQLiteStorage) migrate() ! {
	s.db.exec('CREATE TABLE IF NOT EXISTS auth_migration (version INTEGER PRIMARY KEY)')!
	version := s.db.q_int('SELECT coalesce(max(version), 0) FROM auth_migration')!
	if version > 4 { return error('database schema is newer than this library') }
	s.begin()!
	mut committed := false
	defer {
		if !committed { s.rollback() or {} }
	}
	if version == 0 {
		for statement in schema_v1 {
			s.db.exec(statement)!
		}
		s.db.exec('INSERT INTO auth_migration VALUES (1)')!
	}
	if version < 2 {
		s.db.exec("ALTER TABLE auth_session ADD COLUMN encrypted_token TEXT NOT NULL DEFAULT ''")!
		s.db.exec('INSERT INTO auth_migration VALUES (2)')!
	}
	if version < 3 {
		s.db.exec('CREATE TABLE auth_column_mapping (model TEXT NOT NULL, field TEXT NOT NULL, column_name TEXT NOT NULL, PRIMARY KEY(model,field))')!
		for name, column in account_columns {
			s.db.exec_param2("INSERT INTO auth_column_mapping VALUES ('account',?,?)", name, column)!
		}
		s.db.exec('INSERT INTO auth_migration VALUES (3)')!
	}
	s.migrate_account_columns()!
	if version < 4 {
		s.db.exec('CREATE TABLE auth_jwks (id TEXT PRIMARY KEY, data TEXT NOT NULL)')!
		s.db.exec('INSERT INTO auth_migration VALUES (4)')!
	}
	s.commit()!
	committed = true
}

pub fn (mut s SQLiteStorage) jwks() ![]Jwk {
	rows := s.db.exec('SELECT data FROM auth_jwks ORDER BY rowid')!
	mut result := []Jwk{}
	for row in rows {
		result << json.decode(Jwk, row.vals[0])!
	}
	return result
}

pub fn (mut s SQLiteStorage) create_jwk(key Jwk) ! {
	s.db.exec_param2('INSERT INTO auth_jwks (id,data) VALUES (?,?)', key.id, json.encode(key))!
}

fn (mut s SQLiteStorage) migrate_account_columns() ! {
	mut previous := map[string]string{}
	mut destinations := map[string]string{}
	mut temporary := map[string]string{}
	for name, fallback in account_columns {
		rows :=
			s.db.exec_param("SELECT column_name FROM auth_column_mapping WHERE model='account' AND field=?", name)!
		if rows.len != 1 { return error('account column metadata is missing') }
		target := s.options.account_fields[name] or { fallback }
		if rows[0].vals[0] != target {
			previous[name] = rows[0].vals[0]
			destinations[name] = target
			temporary[name] = '__ba_' + random_token()!
		}
	}
	for name, column in previous {
		s.db.exec('ALTER TABLE auth_account RENAME COLUMN ${sql_identifier(column)} TO ${sql_identifier(temporary[name])}')!
	}
	for name, column in destinations {
		s.db.exec('ALTER TABLE auth_account RENAME COLUMN ${sql_identifier(temporary[name])} TO ${sql_identifier(column)}')!
		s.db.exec_param2("UPDATE auth_column_mapping SET column_name=? WHERE model='account' AND field=?",
			column, name)!
	}
}

const schema_v1 = [
	'CREATE TABLE auth_user (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, data TEXT NOT NULL)',
	'CREATE TABLE auth_account (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE, provider_id TEXT NOT NULL, account_id TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(provider_id, account_id))',
	'CREATE INDEX auth_account_user ON auth_account(user_id)',
	'CREATE TABLE auth_session (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, data TEXT NOT NULL, persistent INTEGER NOT NULL CHECK(persistent IN (0,1)))',
	'CREATE INDEX auth_session_user ON auth_session(user_id)',
	'CREATE TABLE auth_verification (id TEXT PRIMARY KEY, identifier TEXT NOT NULL, data TEXT NOT NULL)',
]

pub fn (mut s SQLiteStorage) begin() ! {
	s.db.exec('BEGIN IMMEDIATE')!
}

pub fn (mut s SQLiteStorage) begin_read() ! {
	s.db.exec('BEGIN')!
}

pub fn (mut s SQLiteStorage) commit() ! {
	s.db.exec('COMMIT')!
}

pub fn (mut s SQLiteStorage) rollback() ! {
	s.db.exec('ROLLBACK')!
}

pub fn (mut s SQLiteStorage) close() ! {
	s.db.close()!
}

pub fn (mut s SQLiteStorage) user(id string) !Lookup[User] {
	rows := s.db.exec_param('SELECT data FROM auth_user WHERE id = ?', id)!
	if rows.len == 0 { return Lookup[User]{} }
	return Lookup[User]{
		value: decode_user(rows[0].vals[0])!
	}
}

pub fn (mut s SQLiteStorage) user_by_email(email string) !Lookup[User] {
	rows := s.db.exec_param('SELECT data FROM auth_user WHERE email = ?', email)!
	if rows.len == 0 { return Lookup[User]{} }
	return Lookup[User]{
		value: decode_user(rows[0].vals[0])!
	}
}

pub fn (mut s SQLiteStorage) create_user(u User) ! {
	s.db.exec_param_many('INSERT INTO auth_user (id,email,data) VALUES (?,?,?)', [u.id, u.email,
		encode_user(u)])!
}

pub fn (mut s SQLiteStorage) users() ![]User {
	rows := s.db.exec('SELECT data FROM auth_user ORDER BY rowid')!
	mut users := []User{}
	for row in rows {
		users << decode_user(row.vals[0])!
	}
	return users
}

pub fn (mut s SQLiteStorage) update_user(u User) ! {
	s.db.exec_param_many('UPDATE auth_user SET email=?,data=? WHERE id=?', [u.email, encode_user(u),
		u.id])!
}

pub fn (mut s SQLiteStorage) delete_user(id string) ! {
	s.db.exec_param('DELETE FROM auth_user WHERE id=?', id)!
}

pub fn (mut s SQLiteStorage) account(user_id string, provider string) !Lookup[Account] {
	query := if provider == 'credential' {
		'SELECT data FROM auth_account WHERE ${s.account_column('userId')}=? AND ${s.account_column('providerId')}=? AND ${s.account_column('accountId')}=${s.account_column('userId')}'
	} else {
		'SELECT data FROM auth_account WHERE ${s.account_column('userId')}=? AND ${s.account_column('providerId')}=?'
	}
	rows := s.db.exec_param2(query, user_id, provider)!
	if rows.len == 0 { return Lookup[Account]{} }
	return Lookup[Account]{
		value: decode_account(rows[0].vals[0])!
	}
}

pub fn (mut s SQLiteStorage) create_account(a Account) ! {
	s.db.exec_param_many('INSERT INTO auth_account (${s.account_column('id')},${s.account_column('userId')},${s.account_column('providerId')},${s.account_column('accountId')},data) VALUES (?,?,?,?,?)', [
		a.id,
		a.user_id,
		a.provider_id,
		a.account_id,
		json.encode(a),
	])!
}

pub fn (mut s SQLiteStorage) account_by_provider(provider string, account_id string) !Lookup[Account] {
	rows := s.db.exec_param2('SELECT data FROM auth_account WHERE ${s.account_column('providerId')}=? AND ${s.account_column('accountId')}=?',
		provider, account_id)!
	if rows.len == 0 { return Lookup[Account]{} }
	return Lookup[Account]{
		value: decode_account(rows[0].vals[0])!
	}
}

pub fn (mut s SQLiteStorage) set_password(user_id string, hash string) ! {
	old := (s.account(user_id, 'credential')!).value or {
		return error('credential account not found')
	}

	updated := Account{
		...old
		password: hash
	}
	s.db.exec_param2('UPDATE auth_account SET data=? WHERE ${s.account_column('id')}=?',
		json.encode(updated), old.id)!
}

pub fn (mut s SQLiteStorage) create_session(session Session, token_hash string) ! {
	stored := Session{
		...session
		token: ''
	}
	s.db.exec_param_many('INSERT INTO auth_session (id,user_id,token_hash,data,persistent,encrypted_token) VALUES (?,?,?,?,?,?)', [
		session.id,
		session.user_id,
		token_hash,
		encode_session(stored),
		if session.persistent { '1' } else { '0' },
		session.encrypted_token,
	])!
}

pub fn (mut s SQLiteStorage) session(token_hash string) !Lookup[Session] {
	rows := s.db.exec_param('SELECT data,persistent,encrypted_token FROM auth_session WHERE token_hash=?',
		token_hash)!
	if rows.len == 0 { return Lookup[Session]{} }
	parsed := decode_session(rows[0].vals[0])!
	return Lookup[Session]{
		value: Session{
			...parsed
			persistent:      rows[0].vals[1] == '1'
			encrypted_token: rows[0].vals[2]
		}
	}
}

pub fn (mut s SQLiteStorage) sessions(user_id string) ![]Session {
	rows := s.db.exec_param('SELECT data,persistent,encrypted_token FROM auth_session WHERE user_id=? ORDER BY rowid',
		user_id)!
	mut result := []Session{}
	for row in rows {
		parsed := decode_session(row.vals[0])!
		result << Session{
			...parsed
			persistent:      row.vals[1] == '1'
			encrypted_token: row.vals[2]
		}
	}
	return result
}

pub fn (mut s SQLiteStorage) session_by_id(id string) !Lookup[Session] {
	rows :=
		s.db.exec_param('SELECT data,persistent,encrypted_token FROM auth_session WHERE id=?', id)!
	if rows.len == 0 { return Lookup[Session]{} }
	parsed := decode_session(rows[0].vals[0])!
	return Lookup[Session]{
		value: Session{
			...parsed
			persistent:      rows[0].vals[1] == '1'
			encrypted_token: rows[0].vals[2]
		}
	}
}

pub fn (mut s SQLiteStorage) update_session(session Session) ! {
	stored := Session{
		...session
		token: ''
	}
	s.db.exec_param2('UPDATE auth_session SET data=? WHERE id=?', encode_session(stored),
		session.id)!
}

pub fn (mut s SQLiteStorage) delete_session(id string) ! {
	s.db.exec_param('DELETE FROM auth_session WHERE id=?', id)!
}

pub fn (mut s SQLiteStorage) delete_sessions(user_id string, except_id string) ! {
	s.db.exec_param2('DELETE FROM auth_session WHERE user_id=? AND id != ?', user_id, except_id)!
}

pub fn (mut s SQLiteStorage) create_verification(v Verification) ! {
	s.db.exec_param_many('INSERT INTO auth_verification (id,identifier,data) VALUES (?,?,?)', [
		v.id,
		v.identifier,
		json.encode(v),
	])!
}

pub fn (mut s SQLiteStorage) verification(id string) !Lookup[Verification] {
	rows := s.db.exec_param('SELECT data FROM auth_verification WHERE id=?', id)!
	if rows.len == 0 { return Lookup[Verification]{} }
	return Lookup[Verification]{
		value: json.decode(Verification, rows[0].vals[0])!
	}
}

pub fn (mut s SQLiteStorage) delete_verification(id string) ! {
	s.db.exec_param('DELETE FROM auth_verification WHERE id=?', id)!
}

pub fn (mut s SQLiteStorage) accounts(user_id string) ![]Account {
	rows := if user_id == '' {
		s.db.exec('SELECT data FROM auth_account ORDER BY rowid')!
	} else {
		s.db.exec_param('SELECT data FROM auth_account WHERE ${s.account_column('userId')}=? ORDER BY rowid',
			user_id)!
	}
	mut accounts := []Account{}
	for row in rows {
		accounts << decode_account(row.vals[0])!
	}
	return accounts
}

pub fn (mut s SQLiteStorage) account_by_id(id string) !Lookup[Account] {
	rows := s.db.exec_param('SELECT data FROM auth_account WHERE ${s.account_column('id')}=?', id)!
	if rows.len == 0 { return Lookup[Account]{} }
	return Lookup[Account]{
		value: decode_account(rows[0].vals[0])!
	}
}

pub fn (mut s SQLiteStorage) delete_account(id string) ! {
	s.db.exec_param('DELETE FROM auth_account WHERE ${s.account_column('id')}=?', id)!
}
