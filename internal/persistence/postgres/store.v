module better_auth

import better_auth.schema as model_schema
import better_auth.storage.postgres as postgres_driver
import json
import x.json2

pub struct PostgresOptions {
pub:
	connection_string string @[json: connectionString]
	schema            string = 'public'
	uuid_ids          bool @[json: uuidIds]
	tables            map[string]string
	fields            map[string]map[string]string
	column_types      map[string]map[string]string @[json: columnTypes]
}

// One libpq connection is pinned for the adapter's lifetime. Auth serializes it;
// independent Auth instances use independent connections and database atomics.
pub struct PostgresStorage {
mut:
	adapter_models    map[string]AdapterModel
	connection        &postgres_driver.Connection
	options           PostgresOptions
	model_fields      map[string]map[string]AdditionalField
	user_fields       map[string]AdditionalField
	session_fields    map[string]AdditionalField
	snapshots         map[string]string
	profile_snapshots map[string]string
	transaction       bool
}

pub interface ConfigurableStorage {
mut:
	configure_fields(user_fields map[string]AdditionalField, session_fields map[string]AdditionalField) !
}

pub interface UserUpdateReturningStorage {
mut:
	update_user_returning(user User) !User
}

pub interface PlainSessionTokenStorage {
	stores_plain_session_tokens() bool
}

pub interface AtomicVerificationStorage {
mut:
	take_verification(id string, identifier string) !Lookup[Verification]
}

pub fn open_postgres(options PostgresOptions) !PostgresStorage {
	if options.connection_string == '' { return error('PostgreSQL connection string is required') }
	if options.schema == '' || options.schema.contains('\x00') {
		return error('invalid PostgreSQL schema')
	}
	for model, table in options.tables {
		if !model_schema.is_core_model(model) || table == '' || table.contains('\x00') {
			return error('invalid PostgreSQL table mapping')
		}
	}
	for model, fields in options.fields {
		if !model_schema.is_core_model(model) {
			return error('invalid PostgreSQL field mapping model')
		}
		mut used := map[string]bool{}
		for _, column in fields {
			if column == '' || column.contains('\x00') || column in used {
				return error('invalid PostgreSQL field mapping')
			}
			used[column] = true
		}
	}
	connection := postgres_driver.open(options.connection_string)!
	return PostgresStorage{
		connection: connection
		options:    options
	}
}

pub fn (mut storage PostgresStorage) configure_fields(user_fields map[string]AdditionalField, session_fields map[string]AdditionalField) ! {
	storage.user_fields = user_fields.clone()
	storage.session_fields = session_fields.clone()
	for model in ['user', 'session', 'account', 'verification', 'jwks', 'rateLimit', 'twoFactor',
		'organization', 'member', 'invitation', 'organizationRole'] {
		mut used := map[string]bool{}
		for field in storage.logical_fields(model) {
			column := storage.column(model, field)
			if column in used { return error('duplicate PostgreSQL column mapping') }
			used[column] = true
		}
	}
}

pub fn (_ PostgresStorage) stores_plain_session_tokens() bool {
	return true
}

fn (storage &PostgresStorage) table(model string) string {
	return sql_identifier(storage.options.schema) + '.' + sql_identifier(storage.options.tables[model] or {
		if custom := storage.adapter_models[model] {
			if custom.name != '' { custom.name } else { model }
		} else {
			model
		}
	})
}

fn (storage &PostgresStorage) column(model string, field string) string {
	if mapping := storage.options.fields[model] {
		if value := mapping[field] { return value }
	}
	if extra := storage.additional(model)[field] {
		if extra.field_name != '' { return extra.field_name }
	}
	return field
}

fn (storage &PostgresStorage) column_sql(model string, field string) string {
	return sql_identifier(storage.column(model, field))
}

fn (storage &PostgresStorage) additional(model string) map[string]AdditionalField {
	return if model == 'user' {
		storage.user_fields
	} else if model == 'session' {
		storage.session_fields
	} else {
		storage.model_fields[model] or {
			(storage.adapter_models[model] or { AdapterModel{} }).fields
		}
	}
}

fn (storage &PostgresStorage) logical_fields(model string) []string {
	mut fields := model_schema.core_fields_or_id(model).clone()
	for field, _ in storage.additional(model) {
		fields << field
	}
	return fields
}

fn (storage &PostgresStorage) is_date(model string, field string) bool {
	if field in ['createdAt', 'updatedAt', 'expiresAt', 'accessTokenExpiresAt',
		'refreshTokenExpiresAt', 'lockedUntil'] {
		return true
	}
	return (storage.additional(model)[field] or { AdditionalField{} }).field_type == 'date'
}

fn (mut storage PostgresStorage) decode_row(model string, encoded string) !string {
	physical := json2.decode[map[string]json2.Any](encoded)!
	mut logical := map[string]json2.Any{}
	for field in storage.logical_fields(model) {
		// V 0.5.2 json2 retains escapes in object keys. Compare the encoded key body.
		encoded_key := json.encode(storage.column(model, field))
		if value := physical[encoded_key[1..encoded_key.len - 1]] {
			logical[field] = if storage.is_date(model, field) && value is string {
				json2.Any(stamp_millis(epoch_millis(value.str())!))
			} else {
				value
			}
		}
	}
	result := json2.Any(logical).json_str()
	if id := logical['id'] { storage.snapshots[model + '|' + id.str()] = result }
	return result
}

fn (mut storage PostgresStorage) select_rows(model string, where string, parameters []string) ![]string {
	rows := storage.connection.exec_param_many('SELECT to_jsonb(t)::text FROM ${storage.table(model)} t ${where}',
		parameters)!
	mut result := []string{}
	for row in rows {
		result << storage.decode_row(model, row.val(0))!
	}
	return result
}

fn (storage &PostgresStorage) physical_data(model string, input map[string]json2.Any) map[string]json2.Any {
	mut output := map[string]json2.Any{}
	for logical in storage.logical_fields(model) {
		if value := input[logical] { output[storage.column(model, logical)] = value }
	}
	return output
}

fn (mut storage PostgresStorage) create_row(model string, encoded string) ! {
	logical := json2.decode[map[string]json2.Any](encoded)!
	fields := storage.physical_data(model, logical)
	if fields.len == 0 { return error('PostgreSQL insert requires fields') }
	columns := fields.keys().map(sql_identifier(it)).join(',')
	selected := fields.keys().map('r.' + sql_identifier(it)).join(',')
	conflict := if model == 'verification' {
		' ON CONFLICT (${storage.column_sql(model, 'id')}) DO NOTHING RETURNING ${storage.column_sql(model, 'id')}'
	} else {
		''
	}
	rows := storage.connection.exec_param('INSERT INTO ${storage.table(model)} (${columns}) SELECT ${selected} FROM jsonb_populate_record(NULL::${storage.table(model)}, $1::jsonb) r${conflict}',
		json2.Any(fields).json_str())!
	if model == 'verification' && rows.len == 0 { return error('duplicate verification id') }
	if id := logical['id'] { storage.snapshots[model + '|' + id.str()] = encoded }
}

fn (mut storage PostgresStorage) update_row(model string, encoded string) ! {
	logical := json2.decode[map[string]json2.Any](encoded)!
	id := logical['id'] or { return error('PostgreSQL update requires id') }
	original := if snapshot := storage.snapshots[model + '|' + id.str()] {
		json2.decode[map[string]json2.Any](snapshot)!
	} else {
		map[string]json2.Any{}
	}
	mut patch := map[string]json2.Any{}
	for field, value in logical {
		if field == 'id' { continue
		 }
		if previous := original[field] {
			if previous.json_str() == value.json_str() { continue
			 }
		}
		patch[field] = value
	}
	fields := storage.physical_data(model, patch)
	if fields.len == 0 { return }
	assignments := fields.keys().map(sql_identifier(it)).join(',')
	selected := fields.keys().map('r.' + sql_identifier(it)).join(',')
	storage.connection.exec_param2('UPDATE ${storage.table(model)} SET (${assignments}) = (SELECT ${selected} FROM jsonb_populate_record(NULL::${storage.table(model)}, $1::jsonb) r) WHERE ${storage.column_sql(model,
		'id')}=$2', json2.Any(fields).json_str(), id.str())!
	storage.snapshots[model + '|' + id.str()] = encoded
}

fn (mut storage PostgresStorage) delete_row(model string, id string) ! {
	storage.connection.exec_param('DELETE FROM ${storage.table(model)} WHERE ${storage.column_sql(model,
		'id')}=$1', id)!
	storage.snapshots.delete(model + '|' + id)
}

pub fn (mut storage PostgresStorage) begin() ! {
	storage.connection.exec('BEGIN')!
	storage.transaction = true
	storage.snapshots.clear()
}

pub fn (mut storage PostgresStorage) begin_read() ! {
	storage.connection.exec('BEGIN READ ONLY')!
	storage.transaction = true
	storage.snapshots.clear()
}

pub fn (mut storage PostgresStorage) commit() ! {
	storage.connection.exec('COMMIT')!
	storage.transaction = false
	storage.snapshots.clear()
}

pub fn (mut storage PostgresStorage) rollback() ! {
	storage.connection.exec('ROLLBACK')!
	storage.transaction = false
	storage.snapshots.clear()
}

pub fn (mut storage PostgresStorage) close() ! {
	storage.connection.close()!
}

pub fn (mut storage PostgresStorage) users() ![]User {
	rows := storage.select_rows('user', '', [])!
	return rows.map(decode_user(it)!)
}

fn postgres_uuid_identifier(value string) bool {
	if value.len != 36 { return false }
	for index, byte in value.bytes() {
		if index in [8, 13, 18, 23] {
			if byte != `-` { return false }
			continue
		}
		if !(byte >= `0` && byte <= `9`) && !(byte >= `a` && byte <= `f`) && !(byte >= `A`
			&& byte <= `F`) {
			return false
		}
	}
	return true
}

pub fn (mut storage PostgresStorage) user(id string) !Lookup[User] {
	if storage.sql_type('user', 'id')! == 'uuid' && !postgres_uuid_identifier(id) {
		return Lookup[User]{}
	}

	rows := storage.select_rows('user', 'WHERE ${storage.column_sql('user', 'id')}=$1', [
		id,
	])!
	return if rows.len > 0 {
		Lookup[User]{
			value: decode_user(rows[0])!
		}
	} else {
		Lookup[User]{}
	}
}

pub fn (mut storage PostgresStorage) user_by_email(email string) !Lookup[User] {
	rows := storage.select_rows('user',
		'WHERE lower(${storage.column_sql('user', 'email')})=lower($1)', [email])!
	return if rows.len > 0 {
		Lookup[User]{
			value: decode_user(rows[0])!
		}
	} else {
		Lookup[User]{}
	}
}

pub fn (mut storage PostgresStorage) create_user(user User) ! {
	storage.create_row('user', encode_user(user))!
}

pub fn (mut storage PostgresStorage) update_user(user User) ! {
	storage.update_row('user', encode_user(user))!
}

// Read back database defaults and application changes before hooks or cache mirroring.
pub fn (mut storage PostgresStorage) update_user_returning(user User) !User {
	storage.update_user(user)!
	return (storage.user(user.id)!).value or { return error('updated PostgreSQL user disappeared') }
}

pub fn (mut storage PostgresStorage) delete_user(id string) ! {
	storage.delete_row('user', id)!
}

pub fn (mut storage PostgresStorage) accounts(user_id string) ![]Account {
	where := if user_id == '' { '' } else { 'WHERE ${storage.column_sql('account', 'userId')}=$1' }
	parameters := if user_id == '' { []string{} } else { [user_id] }
	rows := storage.select_rows('account', '${where} ORDER BY ${storage.column_sql('account',
		'createdAt')},${storage.column_sql('account', 'id')}', parameters)!
	return rows.map(decode_account(it)!)
}

pub fn (mut storage PostgresStorage) account(user_id string, provider string) !Lookup[Account] {
	rows := storage.select_rows('account', 'WHERE ${storage.column_sql('account', 'userId')}=$1 AND ${storage.column_sql('account',
		'providerId')}=$2 AND ($2<>\'credential\' OR ${storage.column_sql('account', 'accountId')}=${storage.column_sql('account',
		'userId')}::text) ORDER BY ${storage.column_sql('account', 'createdAt')},${storage.column_sql('account', 'id')} LIMIT 1', [
		user_id,
		provider,
	])!
	return if rows.len > 0 {
		Lookup[Account]{
			value: decode_account(rows[0])!
		}
	} else {
		Lookup[Account]{}
	}
}

pub fn (mut storage PostgresStorage) account_by_provider(provider string, account_id string) !Lookup[Account] {
	rows := storage.select_rows('account', 'WHERE ${storage.column_sql('account', 'providerId')}=$1 AND ${storage.column_sql('account',
		'accountId')}=$2 LIMIT 1', [provider, account_id])!
	return if rows.len > 0 {
		Lookup[Account]{
			value: decode_account(rows[0])!
		}
	} else {
		Lookup[Account]{}
	}
}

pub fn (mut storage PostgresStorage) account_by_id(id string) !Lookup[Account] {
	rows := storage.select_rows('account', 'WHERE ${storage.column_sql('account', 'id')}=$1', [
		id,
	])!
	return if rows.len > 0 {
		Lookup[Account]{
			value: decode_account(rows[0])!
		}
	} else {
		Lookup[Account]{}
	}
}

pub fn (mut storage PostgresStorage) create_account(account Account) ! {
	storage.create_row('account', json.encode(account))!
}

pub fn (mut storage PostgresStorage) update_account(account Account) ! {
	storage.update_row('account', json.encode(account))!
}

pub fn (mut storage PostgresStorage) delete_account(id string) ! {
	storage.delete_row('account', id)!
}

pub fn (mut storage PostgresStorage) set_password(user_id string, password string) ! {
	storage.connection.exec_param2('UPDATE ${storage.table('account')} SET ${storage.column_sql('account',
		'password')}=$1 WHERE ${storage.column_sql('account', 'userId')}=$2 AND ${storage.column_sql('account',
		'providerId')}=\'credential\' AND ${storage.column_sql('account', 'accountId')}=${storage.column_sql('account',
		'userId')}::text', password, user_id)!
}

pub fn (mut storage PostgresStorage) create_session(session Session, _ string) ! {
	storage.create_row('session', encode_session(session))!
}

pub fn (mut storage PostgresStorage) update_session(session Session) ! {
	storage.update_row('session', encode_session(session))!
}

pub fn (mut storage PostgresStorage) session(token_hash string) !Lookup[Session] {
	rows := storage.select_rows('session', 'WHERE encode(sha256(convert_to(${storage.column_sql('session',
		'token')},\'UTF8\')),\'hex\')=$1', [token_hash])!
	return if rows.len > 0 {
		Lookup[Session]{
			value: decode_session(rows[0])!
		}
	} else {
		Lookup[Session]{}
	}
}

pub fn (mut storage PostgresStorage) session_by_id(id string) !Lookup[Session] {
	rows := storage.select_rows('session', 'WHERE ${storage.column_sql('session', 'id')}=$1', [
		id,
	])!
	return if rows.len > 0 {
		Lookup[Session]{
			value: decode_session(rows[0])!
		}
	} else {
		Lookup[Session]{}
	}
}

pub fn (mut storage PostgresStorage) sessions(user_id string) ![]Session {
	rows := storage.select_rows('session', 'WHERE ${storage.column_sql('session', 'userId')}=$1 ORDER BY ${storage.column_sql('session',
		'createdAt')},${storage.column_sql('session', 'id')}', [user_id])!
	return rows.map(decode_session(it)!)
}

pub fn (mut storage PostgresStorage) delete_session(id string) ! {
	storage.delete_row('session', id)!
}

pub fn (mut storage PostgresStorage) delete_sessions(user_id string, except_id string) ! {
	storage.connection.exec_param2('DELETE FROM ${storage.table('session')} WHERE ${storage.column_sql('session',
		'userId')}=$1 AND ${storage.column_sql('session', 'id')}::text<>$2', user_id, except_id)!
}

pub fn (mut storage PostgresStorage) create_verification(value Verification) ! {
	storage.create_row('verification', encode_verification(value))!
}

pub fn (mut storage PostgresStorage) verification(id string) !Lookup[Verification] {
	rows := storage.select_rows('verification',
		'WHERE ${storage.column_sql('verification', 'id')}::text=$1', [id])!
	return if rows.len > 0 {
		Lookup[Verification]{
			value: decode_verification_record(rows[0])!
		}
	} else {
		Lookup[Verification]{}
	}
}

pub fn (mut storage PostgresStorage) verifications() ![]Verification {
	rows := storage.select_rows('verification', 'ORDER BY ${storage.column_sql('verification',
		'createdAt')},${storage.column_sql('verification', 'id')}', [])!
	return rows.map(decode_verification_record(it)!)
}

pub fn (mut storage PostgresStorage) delete_verification(id string) ! {
	storage.delete_row('verification', id)!
}

pub fn (mut storage PostgresStorage) take_verification(id string, identifier string) !Lookup[Verification] {
	rows := storage.connection.exec_param2('DELETE FROM ${storage.table('verification')} t WHERE ${storage.column_sql('verification', 'id')}=$1 AND ${storage.column_sql('verification',
		'identifier')}=$2 RETURNING to_jsonb(t)::text', id, identifier)!
	if rows.len == 0 { return Lookup[Verification]{} }
	return Lookup[Verification]{
		value: decode_verification_record(storage.decode_row('verification', rows[0].val(0))!)!
	}
}

pub fn (mut storage PostgresStorage) jwks() ![]Jwk {
	rows := storage.select_rows('jwks',
		'ORDER BY ${storage.column_sql('jwks', 'createdAt')},${storage.column_sql('jwks', 'id')}', [])!
	return rows.map(json.decode(Jwk, it)!)
}

pub fn (mut storage PostgresStorage) create_jwk(key Jwk) ! {
	storage.create_row('jwks', json.encode(key))!
}
