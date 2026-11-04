module better_auth

import json
import x.json2

fn unique_field_equal(field AdditionalField, left json2.Any, right json2.Any) bool {
	if left is json2.Null || right is json2.Null { return false }
	if field.field_type == 'number' { return left.f64() == right.f64() }
	if field.field_type == 'date' {
		first := epoch_millis(left.str()) or { return left.json_str() == right.json_str() }
		second := epoch_millis(right.str()) or { return false }
		return first == second
	}
	return left.json_str() == right.json_str()
}

pub fn (mut storage MemoryStorage) configure_fields(users map[string]AdditionalField, sessions map[string]AdditionalField) ! {
	storage.user_fields = users.clone()
	storage.session_fields = sessions.clone()
}

fn (storage &MemoryStorage) unique_user_fields(user User) ! {
	for name, field in storage.user_fields {
		if !field.unique { continue
		 }
		value := user.additional_fields[name] or { continue }
		for _, existing in storage.records.users {
			if existing.id == user.id { continue
			 }
			if other := existing.additional_fields[name] {
				if unique_field_equal(field, value, other) {
					return error('duplicate unique user field')
				}
			}
		}
	}
}

fn (storage &MemoryStorage) unique_session_fields(session Session) ! {
	for name, field in storage.session_fields {
		if !field.unique { continue
		 }
		value := session.additional_fields[name] or { continue }
		for _, existing in storage.records.sessions {
			if existing.id == session.id { continue
			 }
			if other := existing.additional_fields[name] {
				if unique_field_equal(field, value, other) {
					return error('duplicate unique session field')
				}
			}
		}
	}
}

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
