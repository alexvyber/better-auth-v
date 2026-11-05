module better_auth

import json
import x.json2

fn sqlite_organization_table(model string) !string {
	organization_model(model)!
	return sql_identifier('auth_' +
		if model == 'organizationRole' { 'organization_role' } else { model })
}

pub fn (mut storage SQLiteStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
	storage.model_unique_ready = storage.organization_unique_indexes(false)!
}

fn (mut storage SQLiteStorage) organization_unique_indexes(create bool) !bool {
	mut ready := true
	for model, schema in storage.model_fields {
		for field, definition in schema {
			if !definition.unique { continue
			 }
			name := additional_index_name(model, field)
			if create {
				path := ('$.' + json.encode(field)).replace("'", "''")
				storage.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${sql_identifier(name)} ON ${sqlite_organization_table(model)!} (json_extract(data,\'${path}\'))')!
			} else {
				if (storage.db.exec_param("SELECT name FROM sqlite_master WHERE type='index' AND name=?",
					name)!).len == 0 {
					ready = false
				}
			}
		}
	}
	return ready
}

pub fn (mut storage SQLiteStorage) organization_rows(model string, filter map[string]string) ![]string {
	table := sqlite_organization_table(model)!
	mut where := []string{}
	mut parameters := []string{}
	for field, value in filter {
		where << 'CAST(json_extract(data,?) AS TEXT)=?'
		parameters << '$.' + json.encode(field)
		parameters << value
	}
	clause := if where.len > 0 { ' WHERE ' + where.join(' AND ') } else { '' }
	rows := storage.db.exec_param_many('SELECT data FROM ${table}${clause} ORDER BY rowid',
		parameters)!
	return rows.map(it.vals[0])
}

fn (mut storage SQLiteStorage) organization_write(model string, encoded string, creating bool) ! {
	if !storage.model_unique_ready {
		return error('run auth.migrate_storage() before writing configured unique model fields')
	}
	table := sqlite_organization_table(model)!
	fields := org_json_fields(encoded)!
	mut columns := ['id', 'data']
	mut values := [(fields['id'] or { return error('organization record requires id') }).str(),
		encoded]
	if model == 'organization' {
		columns << 'slug'
		values << (fields['slug'] or { json2.Any('') }).str()
	} else {
		columns << 'organization_id'
		values << (fields['organizationId'] or { json2.Any('') }).str()
	}
	if model == 'member' {
		columns << 'user_id'
		values << (fields['userId'] or { json2.Any('') }).str()
	}
	if model == 'invitation' {
		columns << 'inviter_id'
		values << (fields['inviterId'] or { json2.Any('') }).str()
	}
	if model == 'organizationRole' {
		columns << 'role'
		values << (fields['role'] or { json2.Any('') }).str()
	}
	if creating {
		placeholders := columns.map('?').join(',')
		storage.db.exec_param_many('INSERT INTO ${table} (${columns.map(sql_identifier(it)).join(',')}) VALUES (${placeholders})',
			values)!
	} else {
		assignments := columns[1..].map(sql_identifier(it) + '=?').join(',')
		mut parameters := values[1..].clone()
		parameters << values[0]
		storage.db.exec_param_many('UPDATE ${table} SET ${assignments} WHERE id=?', parameters)!
	}
}

pub fn (mut storage SQLiteStorage) organization_create(model string, encoded string) ! {
	storage.organization_write(model, encoded, true)!
}

pub fn (mut storage SQLiteStorage) organization_update(model string, encoded string) ! {
	storage.organization_write(model, encoded, false)!
}

pub fn (mut storage SQLiteStorage) organization_delete(model string, id string) ! {
	storage.db.exec_param('DELETE FROM ${sqlite_organization_table(model)!} WHERE id=?', id)!
}

pub fn (mut storage SQLiteStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	rows := storage.db.exec_param_many("UPDATE auth_invitation SET data=json_set(data,'$.status',?) WHERE id=? AND json_extract(data,'$.status')=? RETURNING id", [
		status,
		id,
		from_status,
	])!
	return rows.len == 1
}
