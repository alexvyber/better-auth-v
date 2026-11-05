module better_auth

import encoding.base64
import encoding.hex
import json
import x.json2

pub struct MongoOptions {
pub:
	uri        string
	database   string
	uuid_ids   bool @[json: uuidIds]
	string_ids bool @[json: stringIds]
	tables     map[string]string
	fields     map[string]map[string]string
}

// A single client/session belongs to one serialized Auth instance. Separate Auth
// instances must open separate clients. Transactions require a replica set.
pub struct MongoStorage {
mut:
	client         &MongoClient
	options        MongoOptions
	model_fields   map[string]map[string]AdditionalField
	user_fields    map[string]AdditionalField
	session_fields map[string]AdditionalField
	snapshots      map[string]string
	transaction    bool
	managed        bool
}

fn mongo_name(value string) bool {
	return value != '' && !value.contains('\x00') && !value.contains('.') && !value.starts_with('$')
}

pub fn open_mongo(options MongoOptions) !MongoStorage {
	if !mongo_name(options.database) { return error('invalid MongoDB database') }
	for model, collection in options.tables {
		if model !in postgres_core_fields || !mongo_name(collection) {
			return error('invalid MongoDB collection mapping')
		}
	}
	for model, fields in options.fields {
		if model !in postgres_core_fields { return error('invalid MongoDB field mapping model') }
		for field, column in fields {
			if field == 'id' && column != '_id' { return error('MongoDB id must map to _id') }
			if !mongo_name(column) { return error('invalid MongoDB field mapping') }
		}
	}
	if options.uuid_ids && options.string_ids {
		return error('conflicting MongoDB ID configuration')
	}
	return MongoStorage{
		client:  open_mongo_client(options.uri)!
		options: options
	}
}

pub fn (mut storage MongoStorage) configure_fields(users map[string]AdditionalField, sessions map[string]AdditionalField) ! {
	storage.user_fields = users.clone()
	storage.session_fields = sessions.clone()
	for model, _ in postgres_core_fields {
		mut used := map[string]bool{}
		for field in storage.logical_fields(model) {
			column := storage.column(model, field)
			if !mongo_name(column) || column in used {
				return error('invalid or duplicate MongoDB field mapping')
			}
			used[column] = true
		}
	}
}

pub fn (_ MongoStorage) stores_plain_session_tokens() bool {
	return true
}

pub fn (storage MongoStorage) generate_storage_id(_ string) !string {
	if storage.options.uuid_ids { return generate_uuid() }
	if storage.options.string_ids { return generate_auth_id(32) }
	return mongo_object_id()
}

pub interface ConfigurableIDStorage {
mut:
	configure_ids(strategy string, custom bool) !
}

pub fn (mut storage MongoStorage) configure_ids(strategy string, custom bool) ! {
	storage.options = MongoOptions{
		...storage.options
		uuid_ids:   !custom && (strategy == 'uuid' || storage.options.uuid_ids)
		string_ids: custom || storage.options.string_ids
	}
	if storage.options.uuid_ids && storage.options.string_ids {
		return error('conflicting MongoDB ID configuration')
	}
}

pub interface StorageIDGenerator {
	generate_storage_id(model string) !string
}

fn (storage &MongoStorage) collection(model string) string {
	return storage.options.tables[model] or { model }
}

fn (storage &MongoStorage) additional(model string) map[string]AdditionalField {
	return if model == 'user' {
		storage.user_fields
	} else if model == 'session' {
		storage.session_fields
	} else {
		storage.model_fields[model] or {
			map[string]AdditionalField{}
		}
	}
}

fn (storage &MongoStorage) logical_fields(model string) []string {
	mut fields := postgres_core_fields[model].clone()
	for field, _ in storage.additional(model) {
		fields << field
	}
	return fields
}

fn (storage &MongoStorage) column(model string, field string) string {
	if field == 'id' { return '_id' }
	if mapping := storage.options.fields[model] {
		if column := mapping[field] { return column }
	}
	if extra := storage.additional(model)[field] {
		if extra.field_name != '' { return extra.field_name }
	}
	return field
}

fn (storage &MongoStorage) is_date(model string, field string) bool {
	return field in ['createdAt', 'updatedAt', 'expiresAt', 'accessTokenExpiresAt', 'refreshTokenExpiresAt', 'lockedUntil'] || (storage.additional(model)[field] or {
		AdditionalField{}
	}).field_type == 'date'
}

fn (storage &MongoStorage) id_value(id string) !BSONValue {
	if storage.options.uuid_ids && id.len == 36 {
		bytes := hex.decode(id.replace('-', '')) or { return BSONValue(id) }
		if bytes.len == 16 { return BSONBinary{
				subtype: 4
				data:    bytes
			} }
	}
	if !storage.options.string_ids && !storage.options.uuid_ids && id.len == 24 {
		bytes := hex.decode(id) or { return BSONValue(id) }
		if bytes.len == 12 { return BSONObjectID{
				hex: id
			} }
	}
	return BSONValue(id)
}

fn (storage &MongoStorage) physical(model string, logical map[string]json2.Any) !map[string]BSONValue {
	mut physical := map[string]BSONValue{}
	for field in storage.logical_fields(model) {
		if value := logical[field] {
			mut encoded := bson_from_json(value)!
			if value is string {
				if field in ['id', 'userId', 'organizationId', 'inviterId'] {
					encoded = storage.id_value(value)!
				} else if storage.is_date(model, field) && value != '' {
					encoded = BSONDate{
						millis: epoch_millis(value)!
					}
				}
			}
			physical[storage.column(model, field)] = encoded
		}
	}
	return physical
}

fn mongo_decode_id(value json2.Any) !string {
	if value is string { return value }
	fields := value.as_map()
	if oid := fields['$oid'] { return oid.str() }
	if binary := fields['$binary'] {
		data := binary.as_map()
		if (data['subType'] or { json2.Any('') }).str() == '04' {
			bytes := base64.decode((data['base64'] or { json2.Any('') }).str())
			if bytes.len != 16 { return error('invalid MongoDB UUID') }
			encoded := hex.encode(bytes)
			return encoded[..8] + '-' + encoded[8..12] + '-' + encoded[12..16] + '-' +
				encoded[16..20] + '-' + encoded[20..]
		}
	}
	return error('unsupported MongoDB identifier type')
}

fn mongo_decode_date(value json2.Any) !json2.Any {
	if value is json2.Null { return value }
	if value is string { return json2.Any(stamp_millis(epoch_millis(value)!)) }
	fields := value.as_map()
	date := fields['$date'] or { return error('invalid MongoDB date') }
	if date is string { return json2.Any(stamp_millis(epoch_millis(date)!)) }
	number := (date.as_map()['$numberLong'] or { return error('invalid MongoDB date') }).str().i64()
	return json2.Any(stamp_millis(number))
}

fn (mut storage MongoStorage) decode_row(model string, row map[string]json2.Any) !string {
	mut logical := map[string]json2.Any{}
	for field in storage.logical_fields(model) {
		key := json.encode(storage.column(model, field))
		if value := row[key[1..key.len - 1]] {
			mut decoded := value
			if value !is json2.Null {
				if field in ['id', 'userId', 'organizationId', 'inviterId'] {
					decoded = json2.Any(mongo_decode_id(value)!)
				} else if storage.is_date(model, field) {
					decoded = mongo_decode_date(value)!
				}
			}
			logical[field] = decoded
		}
	}
	result := json2.Any(logical).json_str()
	if id := logical['id'] { storage.snapshots[model + '|' + id.str()] = result }
	return result
}

fn (mut storage MongoStorage) command(command map[string]BSONValue, mode int) !map[string]json2.Any {
	return storage.client.command(storage.options.database, command, mode, true)
}

fn (mut storage MongoStorage) select_rows(model string, filter map[string]BSONValue) ![]string {
	reply := storage.command({
		'find':      BSONValue(storage.collection(model))
		'filter':    BSONValue(filter)
		'batchSize': BSONValue(100)
	}, 1)!
	mut cursor := (reply['cursor'] or { return error('missing MongoDB cursor') }).as_map()
	mut batch := (cursor['firstBatch'] or { json2.Any([]json2.Any{}) }).as_array()
	mut result := []string{}
	for {
		for row in batch {
			result << storage.decode_row(model, row.as_map())!
		}
		id := (cursor['id'] or { json2.Any(0) }).i64()
		if id == 0 { break
		 }
		next := storage.command({
			'getMore':    BSONValue(id)
			'collection': BSONValue(storage.collection(model))
			'batchSize':  BSONValue(100)
		}, 1)!
		cursor = (next['cursor'] or { return error('missing MongoDB cursor') }).as_map()
		batch = (cursor['nextBatch'] or { json2.Any([]json2.Any{}) }).as_array()
	}
	return result
}

fn (mut storage MongoStorage) create_row(model string, encoded string) ! {
	logical := json2.decode[map[string]json2.Any](encoded)!
	fields := storage.physical(model, logical)!
	if model == 'verification' {
		id := fields['_id'] or { return error('verification requires id') }
		reply := storage.command({
			'findAndModify': BSONValue(storage.collection(model))
			'query':         BSONValue({
				'_id': id
			})
			'update':        BSONValue({
				'$setOnInsert': BSONValue(fields)
			})
			'upsert':        BSONValue(true)
			'new':           BSONValue(false)
		}, 3)!
		if value := reply['value'] {
			if value !is json2.Null { return error('duplicate verification id') }
		}
	} else {
		storage.command({
			'insert':    BSONValue(storage.collection(model))
			'documents': BSONValue([BSONValue(fields)])
			'ordered':   BSONValue(true)
		}, 2)!
	}
	if id := logical['id'] { storage.snapshots[model + '|' + id.str()] = encoded }
}

fn (mut storage MongoStorage) update_row(model string, encoded string) ! {
	logical := json2.decode[map[string]json2.Any](encoded)!
	id := (logical['id'] or { return error('MongoDB update requires id') }).str()
	original := json2.decode[map[string]json2.Any](storage.snapshots[model + '|' + id] or { '{}' })!
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
	fields := storage.physical(model, patch)!
	if fields.len > 0 { storage.command({
			'update':  BSONValue(storage.collection(model))
			'updates': BSONValue([
				BSONValue({
					'q': BSONValue({
						'_id': storage.id_value(id)!
					})
					'u': BSONValue({
						'$set': BSONValue(fields)
					})
				}),
			])
		}, 2)! }
	storage.snapshots[model + '|' + id] = encoded
}

fn (mut storage MongoStorage) delete_rows(model string, filter map[string]BSONValue) ! {
	storage.command({
		'delete':  BSONValue(storage.collection(model))
		'deletes': BSONValue([
			BSONValue({
				'q':     BSONValue(filter)
				'limit': BSONValue(0)
			}),
		])
	}, 2)!
}

fn (mut storage MongoStorage) delete_row(model string, id string) ! {
	storage.delete_rows(model, {
		'_id': storage.id_value(id)!
	})!
	storage.snapshots.delete(model + '|' + id)
}

pub fn (mut storage MongoStorage) begin() ! {
	if storage.transaction { return error('MongoDB transaction already active') }
	if !storage.managed { storage.client.transaction(1)! }
	storage.transaction = true
	storage.snapshots.clear()
}

pub fn (mut storage MongoStorage) begin_read() ! {
	storage.begin()!
}

pub fn (mut storage MongoStorage) commit() ! {
	if storage.managed {
		return error('Explicit commit is not supported inside a managed MongoDB transaction')
	}
	if storage.transaction {
		storage.client.transaction(2)!
		storage.transaction = false
	}
	storage.snapshots.clear()
}

pub fn (mut storage MongoStorage) rollback() ! {
	if storage.transaction {
		if !storage.managed { storage.client.transaction(3)! }
		storage.transaction = false
	}
	storage.snapshots.clear()
}

pub fn (mut storage MongoStorage) transaction_stats() !map[string]json2.Any {
	return storage.client.transaction_stats()
}

pub fn (mut storage MongoStorage) close() ! {
	storage.rollback()!
	storage.client.close()!
}

pub fn (mut storage MongoStorage) user(id string) !Lookup[User] {
	rows := storage.select_rows('user', {
		'_id': storage.id_value(id)!
	})!
	if rows.len == 0 { return Lookup[User]{} }
	return Lookup[User]{
		value: decode_user(rows[0])!
	}
}

pub fn (mut storage MongoStorage) create_user(value User) ! {
	storage.create_row('user', encode_user(value))!
}

pub fn (mut storage MongoStorage) update_user(value User) ! {
	storage.update_row('user', encode_user(value))!
}

pub fn (mut storage MongoStorage) account_by_id(id string) !Lookup[Account] {
	rows := storage.select_rows('account', {
		'_id': storage.id_value(id)!
	})!
	if rows.len == 0 { return Lookup[Account]{} }
	return Lookup[Account]{
		value: decode_account(rows[0])!
	}
}

pub fn (mut storage MongoStorage) create_account(value Account) ! {
	storage.create_row('account', json.encode(value))!
}

pub fn (mut storage MongoStorage) delete_account(id string) ! {
	storage.delete_row('account', id)!
}

pub fn (mut storage MongoStorage) update_account(value Account) ! {
	storage.update_row('account', json.encode(value))!
}

pub fn (mut storage MongoStorage) session_by_id(id string) !Lookup[Session] {
	rows := storage.select_rows('session', {
		'_id': storage.id_value(id)!
	})!
	if rows.len == 0 { return Lookup[Session]{} }
	return Lookup[Session]{
		value: decode_session(rows[0])!
	}
}

pub fn (mut storage MongoStorage) create_session(value Session, _ string) ! {
	storage.create_row('session', encode_session(value))!
}

pub fn (mut storage MongoStorage) delete_session(id string) ! {
	storage.delete_row('session', id)!
}

pub fn (mut storage MongoStorage) update_session(value Session) ! {
	storage.update_row('session', encode_session(value))!
}

pub fn (mut storage MongoStorage) verification(id string) !Lookup[Verification] {
	rows := storage.select_rows('verification', {
		'_id': storage.id_value(id)!
	})!
	if rows.len == 0 { return Lookup[Verification]{} }
	return Lookup[Verification]{
		value: decode_verification_record(rows[0])!
	}
}

pub fn (mut storage MongoStorage) create_verification(value Verification) ! {
	storage.create_row('verification', encode_verification(value))!
}

pub fn (mut storage MongoStorage) delete_verification(id string) ! {
	storage.delete_row('verification', id)!
}

pub fn (mut storage MongoStorage) users() ![]User {
	rows := storage.select_rows('user', {})!
	return rows.map(decode_user(it)!)
}

pub fn (mut storage MongoStorage) user_by_email(email string) !Lookup[User] {
	rows := storage.select_rows('user', {
		storage.column('user', 'email'): BSONValue(email.to_lower())
	})!
	if rows.len == 0 { return Lookup[User]{} }
	return Lookup[User]{
		value: decode_user(rows[0])!
	}
}

pub fn (mut storage MongoStorage) update_user_returning(user User) !User {
	storage.update_user(user)!
	return (storage.user(user.id)!).value or { return error('updated MongoDB user disappeared') }
}

pub fn (mut storage MongoStorage) delete_user(id string) ! {
	for model in ['session', 'account', 'twoFactor', 'member'] {
		storage.delete_rows(model, {
			storage.column(model, 'userId'): storage.id_value(id)!
		})!
	}
	storage.delete_rows('invitation', {
		storage.column('invitation', 'inviterId'): storage.id_value(id)!
	})!
	storage.delete_row('user', id)!
}

pub fn (mut storage MongoStorage) accounts(user_id string) ![]Account {
	mut filter := map[string]BSONValue{}
	if user_id != '' { filter[storage.column('account', 'userId')] = storage.id_value(user_id)! }
	rows := storage.select_rows('account', filter)!
	return rows.map(decode_account(it)!)
}

pub fn (mut storage MongoStorage) account(user_id string, provider string) !Lookup[Account] {
	for account in storage.accounts(user_id)! {
		if account.provider_id == provider && (provider != 'credential' || account.account_id == user_id) { return Lookup[Account]{
				value: account
			} }
	}
	return Lookup[Account]{}
}

pub fn (mut storage MongoStorage) account_by_provider(provider string, account_id string) !Lookup[Account] {
	rows := storage.select_rows('account', {
		storage.column('account', 'providerId'): BSONValue(provider)
		storage.column('account', 'accountId'):  BSONValue(account_id)
	})!
	if rows.len == 0 { return Lookup[Account]{} }
	return Lookup[Account]{
		value: decode_account(rows[0])!
	}
}

pub fn (mut storage MongoStorage) set_password(user_id string, password string) ! {
	if account := (storage.account(user_id, 'credential')!).value { storage.update_account(Account{
			...account
			password: password
		})! }
}

pub fn (mut storage MongoStorage) sessions(user_id string) ![]Session {
	rows := storage.select_rows('session', {
		storage.column('session', 'userId'): storage.id_value(user_id)!
	})!
	return rows.map(decode_session(it)!)
}

pub interface TokenLookupStorage {
mut:
	session_by_token(token string) !Lookup[Session]
}

pub fn (mut storage MongoStorage) session_by_token(token string) !Lookup[Session] {
	rows := storage.select_rows('session', {
		storage.column('session', 'token'): BSONValue(token)
	})!
	if rows.len == 0 { return Lookup[Session]{} }
	return Lookup[Session]{
		value: decode_session(rows[0])!
	}
}

// The Storage hash-only compatibility method cannot use the plain-token index.
// Auth uses TokenLookupStorage above for every ordinary token lookup.
pub fn (mut storage MongoStorage) session(hash string) !Lookup[Session] {
	rows := storage.select_rows('session', {})!
	for row in rows {
		session := decode_session(row)!
		if digest(session.token) == hash { return Lookup[Session]{
				value: session
			} }
	}
	return Lookup[Session]{}
}

pub fn (mut storage MongoStorage) delete_sessions(user_id string, except_id string) ! {
	mut filter := {
		storage.column('session', 'userId'): storage.id_value(user_id)!
	}
	if except_id != '' { filter['_id'] = BSONValue({
			'$ne': storage.id_value(except_id)!
		}) }
	storage.delete_rows('session', filter)!
}

pub fn (mut storage MongoStorage) verifications() ![]Verification {
	rows := storage.select_rows('verification', {})!
	return rows.map(decode_verification_record(it)!)
}

pub fn (mut storage MongoStorage) take_verification(id string, identifier string) !Lookup[Verification] {
	reply := storage.command({
		'findAndModify': BSONValue(storage.collection('verification'))
		'query':         BSONValue({
			'_id':                                        storage.id_value(id)!
			storage.column('verification', 'identifier'): BSONValue(identifier)
		})
		'remove':        BSONValue(true)
	}, 3)!
	value := reply['value'] or { return Lookup[Verification]{} }
	if value is json2.Null { return Lookup[Verification]{} }
	return Lookup[Verification]{
		value: decode_verification_record(storage.decode_row('verification', value.as_map())!)!
	}
}

pub fn (mut storage MongoStorage) jwks() ![]Jwk {
	rows := storage.select_rows('jwks', {})!
	return rows.map(json.decode(Jwk, it)!)
}

pub fn (mut storage MongoStorage) create_jwk(key Jwk) ! {
	storage.create_row('jwks', json.encode(key))!
}

pub fn (mut storage MongoStorage) two_factors(user_id string) ![]TwoFactorRecord {
	mut filter := map[string]BSONValue{}
	if user_id != '' { filter[storage.column('twoFactor', 'userId')] = storage.id_value(user_id)! }
	rows := storage.select_rows('twoFactor', filter)!
	return rows.map(json.decode(TwoFactorRecord, it)!)
}

pub fn (mut storage MongoStorage) create_two_factor(record TwoFactorRecord) ! {
	storage.create_row('twoFactor', encode_two_factor(record))!
}

pub fn (mut storage MongoStorage) update_two_factor(record TwoFactorRecord) ! {
	storage.update_row('twoFactor', encode_two_factor(record))!
}

pub fn (mut storage MongoStorage) delete_two_factors(user_id string) ! {
	storage.delete_rows('twoFactor', {
		storage.column('twoFactor', 'userId'): storage.id_value(user_id)!
	})!
}
