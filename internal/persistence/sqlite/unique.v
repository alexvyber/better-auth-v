module better_auth

import json

fn additional_index_name(model string, field string) string {
	return 'auth_unique_' + digest(model + '|' + field)[..24]
}

fn (mut storage SQLiteStorage) configured_unique_indexes(create bool) !bool {
	mut ready := true
	for model, fields in {
		'user':    storage.user_fields
		'session': storage.session_fields
	} {
		for name, field in fields {
			if !field.unique { continue
			 }
			index := additional_index_name(model, name)
			if create {
				path := ('$.' + json.encode(name)).replace("'", "''")
				storage.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${sql_identifier(index)} ON auth_${model} (json_extract(data,\'${path}\'))')!
			} else {
				rows := storage.db.exec_param("SELECT name FROM sqlite_master WHERE type='index' AND name=?",
					index)!
				if rows.len == 0 { ready = false }
			}
		}
	}
	return ready
}

pub fn (mut storage SQLiteStorage) configure_fields(users map[string]AdditionalField, sessions map[string]AdditionalField) ! {
	storage.user_fields = users.clone()
	storage.session_fields = sessions.clone()
	storage.unique_fields_ready = storage.configured_unique_indexes(false)!
}

fn (storage &SQLiteStorage) require_unique_indexes() ! {
	if !storage.unique_fields_ready {
		return error('run auth.migrate_storage() before writing configured unique fields')
	}
}
