module better_auth

import json
import x.json2

pub struct TwoFactorRecord {
pub:
	id                        string
	user_id                   string @[json: userId]
	secret                    string
	backup_codes              string @[json: backupCodes]
	verified                  ?bool
	failed_verification_count int     @[json: failedVerificationCount]
	locked_until              ?string @[json: lockedUntil]
}

pub fn encode_two_factor(record TwoFactorRecord) string {
	mut fields := json2.decode[map[string]json2.Any](json.encode(record)) or { return '{}' }
	if record.verified == none { fields['verified'] = json2.Null{} }
	if record.locked_until == none { fields['lockedUntil'] = json2.Null{} }
	return json2.Any(fields).json_str()
}

pub interface TwoFactorStorage {
mut:
	two_factors(user_id string) ![]TwoFactorRecord
	create_two_factor(record TwoFactorRecord) !
	update_two_factor(record TwoFactorRecord) !
	delete_two_factors(user_id string) !
}

pub fn (mut context EndpointContext) two_factors(user_id string) ![]TwoFactorRecord {
	mut storage := context.auth.storage
	if mut storage is TwoFactorStorage { return storage.two_factors(user_id) }
	return error('two-factor storage is not supported by this adapter')
}

fn (mut context EndpointContext) save_two_factor(record TwoFactorRecord, create bool) ! {
	mut storage := context.auth.storage
	if mut storage is TwoFactorStorage {
		if create {
			storage.create_two_factor(record)!
		} else {
			storage.update_two_factor(record)!
		}
		return
	}
	return error('two-factor storage is not supported by this adapter')
}

fn (mut context EndpointContext) delete_two_factors(user_id string) ! {
	mut storage := context.auth.storage
	if mut storage is TwoFactorStorage {
		storage.delete_two_factors(user_id)!
		return
	}
	return error('two-factor storage is not supported by this adapter')
}

pub fn (mut storage MemoryStorage) two_factors(user_id string) ![]TwoFactorRecord {
	storage.check_open()!
	return storage.records.two_factors.values().filter(user_id == '' || it.user_id == user_id)
}

pub fn (mut storage MemoryStorage) create_two_factor(record TwoFactorRecord) ! {
	storage.check_write()!
	if record.id in storage.records.two_factors { return error('duplicate two-factor id') }
	if (storage.user(record.user_id)!).value == none {
		return error('two-factor user does not exist')
	}
	storage.records.two_factors[record.id] = record
}

pub fn (mut storage MemoryStorage) update_two_factor(record TwoFactorRecord) ! {
	storage.check_write()!
	if record.id in storage.records.two_factors { storage.records.two_factors[record.id] = record }
}

pub fn (mut storage MemoryStorage) delete_two_factors(user_id string) ! {
	storage.check_write()!
	for record in storage.two_factors(user_id)! {
		storage.records.two_factors.delete(record.id)
	}
}

pub fn (mut storage SQLiteStorage) two_factors(user_id string) ![]TwoFactorRecord {
	rows := if user_id == '' {
		storage.db.exec('SELECT data FROM auth_two_factor ORDER BY rowid')!
	} else {
		storage.db.exec_param('SELECT data FROM auth_two_factor WHERE user_id=? ORDER BY rowid',
			user_id)!
	}
	mut records := []TwoFactorRecord{}
	for row in rows {
		records << json.decode(TwoFactorRecord, row.vals[0])!
	}
	return records
}

pub fn (mut storage SQLiteStorage) create_two_factor(record TwoFactorRecord) ! {
	storage.db.exec_param_many('INSERT INTO auth_two_factor(id,user_id,data) VALUES (?,?,?)', [
		record.id,
		record.user_id,
		json.encode(record),
	])!
}

pub fn (mut storage SQLiteStorage) update_two_factor(record TwoFactorRecord) ! {
	storage.db.exec_param2('UPDATE auth_two_factor SET data=? WHERE id=?', json.encode(record),
		record.id)!
}

pub fn (mut storage SQLiteStorage) delete_two_factors(user_id string) ! {
	storage.db.exec_param('DELETE FROM auth_two_factor WHERE user_id=?', user_id)!
}

pub fn (mut storage PostgresStorage) two_factors(user_id string) ![]TwoFactorRecord {
	where := if user_id == '' { '' } else { 'WHERE ${storage.column_sql('twoFactor', 'userId')}=$1' }
	parameters := if user_id == '' { []string{} } else { [user_id] }
	rows := storage.select_rows('twoFactor',
		'${where} ORDER BY ${storage.column_sql('twoFactor', 'id')} FOR UPDATE', parameters)!
	return rows.map(json.decode(TwoFactorRecord, it)!)
}

pub fn (mut storage PostgresStorage) create_two_factor(record TwoFactorRecord) ! {
	storage.create_row('twoFactor', encode_two_factor(record))!
}

pub fn (mut storage PostgresStorage) update_two_factor(record TwoFactorRecord) ! {
	storage.update_row('twoFactor', encode_two_factor(record))!
}

pub fn (mut storage PostgresStorage) delete_two_factors(user_id string) ! {
	storage.connection.exec_param('DELETE FROM ${storage.table('twoFactor')} WHERE ${storage.column_sql('twoFactor',
		'userId')}=$1', user_id)!
}
