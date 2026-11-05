module better_auth

import json

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
