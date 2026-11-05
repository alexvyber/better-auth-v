module better_auth

import json

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
