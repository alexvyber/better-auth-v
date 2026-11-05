module better_auth

import json
import x.json2

const organization_models = ['organization', 'member', 'invitation', 'organizationRole']

// Scoped persistence for organization models. This is not the general upstream
// adapter query language: filters are ANDed field equalities on a known schema.
pub interface OrganizationStorage {
mut:
	organization_rows(model string, filter map[string]string) ![]string
	organization_create(model string, encoded string) !
	organization_update(model string, encoded string) !
	organization_delete(model string, id string) !
	organization_claim_invitation(id string, from_status string, status string) !bool
}

pub interface ConfigurableModelStorage {
mut:
	configure_model_fields(fields map[string]map[string]AdditionalField) !
}

fn validate_organization_fields(fields map[string]map[string]AdditionalField) ! {
	for model, schema in fields {
		if model !in organization_models { return error('unsupported additional model schema') }
		for field, definition in schema {
			if field in postgres_core_fields[model]
				|| field in ['__proto__', 'constructor', 'prototype'] || field == ''
				|| field.contains('\x00') {
				return error('additional model field collides with a reserved name')
			}
			if definition.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
				'number[]'] {
				return error('unsupported additional model field type')
			}
		}
	}
}

fn organization_model(model string) ! {
	if model !in organization_models { return error('unsupported organization model') }
}

fn org_json_fields(encoded string) !map[string]json2.Any {
	return json2.decode[map[string]json2.Any](encoded)
}

fn organization_row_matches(row map[string]json2.Any, filter map[string]string) bool {
	for field, value in filter {
		actual := row[field] or { return false }
		if actual.str() != value { return false }
	}
	return true
}

pub fn (mut storage MemoryStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
}

pub fn (mut storage MemoryStorage) organization_rows(model string, filter map[string]string) ![]string {
	storage.check_open()!
	organization_model(model)!
	mut result := []string{}
	for key, encoded in storage.records.organizations {
		if key.starts_with(model + '|')
			&& organization_row_matches(org_json_fields(encoded)!, filter) {
			result << encoded
		}
	}
	return result
}

fn (mut storage MemoryStorage) check_organization_write(model string, encoded string, creating bool) !string {
	storage.check_write()!
	organization_model(model)!
	fields := org_json_fields(encoded)!
	id := (fields['id'] or { return error('organization record requires id') }).str()
	if creating && model + '|' + id in storage.records.organizations {
		return error('duplicate organization record id')
	}
	if model != 'organization' {
		org_id := (fields['organizationId'] or {
			return error('organization reference is required')
		}).str()
		if (storage.organization_rows('organization', {
			'id': org_id
		})!).len == 0 {
			return error('organization does not exist')
		}
	}
	if model == 'member' || model == 'invitation' {
		field := if model == 'member' { 'userId' } else { 'inviterId' }
		if (storage.user((fields[field] or { json2.Any('') }).str())!).value == none {
			return error('organization user does not exist')
		}
	}
	for other in storage.organization_rows(model, {})! {
		row := org_json_fields(other)!
		if (row['id'] or { json2.Any('') }).str() == id { continue
		 }
		if model == 'organization' && (row['slug'] or { json2.Any('') }).str() == (fields['slug'] or {
			json2.Any('')
		}).str() {
			return error('duplicate organization slug')
		}
		if model in ['member', 'organizationRole'] && (row['organizationId'] or { json2.Any('') }).str() == (fields['organizationId'] or {
			json2.Any('')
		}).str() {
			field := if model == 'member' { 'userId' } else { 'role' }
			if (row[field] or { json2.Any('') }).str() == (fields[field] or { json2.Any('') }).str() {
				return error('duplicate organization association')
			}
		}
		for field, definition in storage.model_fields[model] or {
			map[string]AdditionalField{}
		} {
			if !definition.unique { continue
			 }
			value := fields[field] or { continue }
			if value is json2.Null { continue
			 }
			if previous := row[field] {
				if previous.json_str() == value.json_str() {
					return error('duplicate unique organization field')
				}
			}
		}
	}
	return id
}

pub fn (mut storage MemoryStorage) organization_create(model string, encoded string) ! {
	id := storage.check_organization_write(model, encoded, true)!
	storage.records.organizations[model + '|' + id] = encoded
}

pub fn (mut storage MemoryStorage) organization_update(model string, encoded string) ! {
	id := storage.check_organization_write(model, encoded, false)!
	if model + '|' + id in storage.records.organizations {
		storage.records.organizations[model + '|' + id] = encoded
	}
}

pub fn (mut storage MemoryStorage) organization_delete(model string, id string) ! {
	storage.check_write()!
	organization_model(model)!
	if model == 'organization' {
		for child in ['member', 'invitation', 'organizationRole'] {
			for row in storage.organization_rows(child, {
				'organizationId': id
			})! {
				fields := org_json_fields(row)!
				storage.records.organizations.delete(child + '|' + (fields['id'] or {
					json2.Any('')
				}).str())
			}
		}
	}
	storage.records.organizations.delete(model + '|' + id)
}

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

pub fn (mut storage PostgresStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
	storage.configure_fields(storage.user_fields, storage.session_fields)!
}

pub fn (mut storage PostgresStorage) organization_rows(model string, filter map[string]string) ![]string {
	organization_model(model)!
	mut clauses := []string{}
	mut parameters := []string{}
	for field, value in filter {
		if field !in storage.logical_fields(model) {
			return error('unknown organization filter field')
		}
		if storage.sql_type(model, field)! == 'uuid' && !postgres_uuid_identifier(value) {
			return []string{}
		}
		parameters << value
		clauses << storage.column_sql(model, field) + '=$' + parameters.len.str()
	}
	where := if clauses.len > 0 { 'WHERE ' + clauses.join(' AND ') } else { '' }
	return storage.select_rows(model, where, parameters)
}

pub fn (mut storage PostgresStorage) organization_create(model string, encoded string) ! {
	organization_model(model)!
	storage.create_row(model, encoded)!
}

pub fn (mut storage PostgresStorage) organization_update(model string, encoded string) ! {
	organization_model(model)!
	storage.update_row(model, encoded)!
}

pub fn (mut storage PostgresStorage) organization_delete(model string, id string) ! {
	organization_model(model)!
	storage.delete_row(model, id)!
}

pub fn (mut storage MongoStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
	storage.configure_fields(storage.user_fields, storage.session_fields)!
}

pub fn (mut storage MongoStorage) organization_rows(model string, filter map[string]string) ![]string {
	organization_model(model)!
	mut physical := map[string]BSONValue{}
	for field, value in filter {
		if field !in storage.logical_fields(model) {
			return error('unknown organization filter field')
		}
		physical[storage.column(model, field)] = if field in ['id', 'userId', 'organizationId',
			'inviterId'] {
			storage.id_value(value)!
		} else {
			BSONValue(value)
		}
	}
	return storage.select_rows(model, physical)
}

pub fn (mut storage MongoStorage) organization_create(model string, encoded string) ! {
	organization_model(model)!
	storage.create_row(model, encoded)!
}

pub fn (mut storage MongoStorage) organization_update(model string, encoded string) ! {
	organization_model(model)!
	storage.update_row(model, encoded)!
}

pub fn (mut storage MongoStorage) organization_delete(model string, id string) ! {
	organization_model(model)!
	if model == 'organization' {
		for child in ['member', 'invitation', 'organizationRole'] {
			storage.delete_rows(child, {
				storage.column(child, 'organizationId'): storage.id_value(id)!
			})!
		}
	}
	storage.delete_row(model, id)!
}

pub fn (mut storage MemoryStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	storage.check_write()!
	key := 'invitation|' + id
	encoded := storage.records.organizations[key] or { return false }
	mut row := org_json_fields(encoded)!
	if (row['status'] or { json2.Any('') }).str() != from_status { return false }
	row['status'] = status
	storage.records.organizations[key] = json2.Any(row).json_str()
	return true
}

pub fn (mut storage SQLiteStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	rows := storage.db.exec_param_many("UPDATE auth_invitation SET data=json_set(data,'$.status',?) WHERE id=? AND json_extract(data,'$.status')=? RETURNING id", [
		status,
		id,
		from_status,
	])!
	return rows.len == 1
}

pub fn (mut storage PostgresStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	if storage.sql_type('invitation', 'id')! == 'uuid' && !postgres_uuid_identifier(id) {
		return false
	}
	rows := storage.connection.exec_param_many('UPDATE ${storage.table('invitation')} SET ${storage.column_sql('invitation',
		'status')}=$1 WHERE ${storage.column_sql('invitation', 'id')}=$2 AND ${storage.column_sql('invitation',
		'status')}=$3 RETURNING ${storage.column_sql('invitation', 'id')}',
		[status, id, from_status])!
	return rows.len == 1
}

pub fn (mut storage MongoStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	reply := storage.command({
		'findAndModify': BSONValue(storage.collection('invitation'))
		'query':         BSONValue({
			storage.column('invitation', 'id'):     storage.id_value(id)!
			storage.column('invitation', 'status'): BSONValue(from_status)
		})
		'update':        BSONValue({
			'$set': BSONValue({
				storage.column('invitation', 'status'): BSONValue(status)
			})
		})
		'new':           BSONValue(true)
	}, 3)!
	value := reply['value'] or { return false }
	return value !is json2.Null
}
