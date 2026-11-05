module better_auth

import better_auth.schema as model_schema
import json
import x.json2

pub struct AdapterReference {
pub:
	model string
	field string = 'id'
}

pub struct AdapterModel {
pub:
	name   string @[json: modelName]
	fields map[string]AdditionalField
}

pub interface AdapterModelStorage {
mut:
	configure_adapter_models(models map[string]AdapterModel) !
	adapter_model_rows(string) ![]string
	adapter_model_write(string, string, bool) !
	adapter_model_delete(string, string) !
}

fn validate_adapter_models(models map[string]AdapterModel) ! {
	mut names := map[string]bool{}
	for model, definition in models {
		name := if definition.name == '' { model } else { definition.name }
		if model == '' || model_schema.is_core_model(model)
			|| model in ['__proto__', 'constructor', 'prototype'] || model.contains('\x00')
			|| model.contains('|') || name == '' || name.contains('\x00')
			|| name.to_lower() in names || model_schema.is_core_model(name) {
			return error('invalid or colliding adapter model name')
		}
		names[name.to_lower()] = true
		mut columns := {
			'id':  true
			'_id': true
		}
		for field, attribute in definition.fields {
			column := if attribute.field_name == '' { field } else { attribute.field_name }
			if field == '' || field in ['id', '__proto__', 'constructor', 'prototype']
				|| field.contains('\x00') || column == '' || column.contains('\x00')
				|| column in columns {
				return error('invalid or colliding adapter field')
			}
			columns[column] = true
			if attribute.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
				'number[]'] {
				return error('unsupported adapter field type')
			}
			if reference := attribute.references {
				if !model_schema.is_core_model(reference.model) && reference.model !in models {
					return error('unknown adapter reference model')
				}
				if reference.field != 'id' && reference.field !in model_schema.core_fields(reference.model) && reference.field !in (models[reference.model] or {
					AdapterModel{}
				}).fields {
					return error('unknown adapter reference field')
				}
			}
		}
	}
}

pub fn (mut s MemoryStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	s.adapter_models = models.clone()
}

pub fn (mut s SQLiteStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	s.adapter_models = models.clone()
}

pub fn (mut s PostgresStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	s.adapter_models = models.clone()
	mut names := map[string]bool{}
	mut all := model_schema.core_models()
	all << models.keys()
	for model in all {
		name := s.table(model)
		if name in names { return error('adapter table mapping collides with an existing model') }
		names[name] = true
	}
}

pub fn (mut s MongoStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	validate_mongo_adapter_columns(models)!
	s.adapter_models = models.clone()
	mut names := map[string]bool{}
	mut all := model_schema.core_models()
	all << models.keys()
	for model in all {
		name := s.collection(model)
		if name in names {
			return error('adapter collection mapping collides with an existing model')
		}
		names[name] = true
	}
}

fn validate_mongo_adapter_columns(models map[string]AdapterModel) ! {
	for _, definition in models {
		for field, attribute in definition.fields {
			column := if attribute.field_name == '' { field } else { attribute.field_name }
			if column.starts_with('$') || column.contains('.') {
				return error('MongoDB adapter fields require literal column names without dots or a leading dollar sign')
			}
		}
	}
}

fn require_adapter_model(models map[string]AdapterModel, model string) ! {
	if model !in models { return error('unknown adapter model') }
}

fn (storage &MongoStorage) identifier_field(model string, field string) bool {
	if reference := (storage.additional(model)[field] or { AdditionalField{} }).references {
		return reference.field == 'id'
	}
	return field == 'id'
		|| (model_schema.is_core_model(model) && field in ['userId', 'organizationId', 'inviterId'])
}

fn adapter_model_table(models map[string]AdapterModel, model string) !string {
	require_adapter_model(models, model)!
	definition := models[model] or { return error('unknown adapter model') }
	return sql_identifier('auth_adapter_' +
		if definition.name == '' { model } else { definition.name })
}

pub fn (mut s MemoryStorage) adapter_model_rows(model string) ![]string {
	s.check_open()!
	require_adapter_model(s.adapter_models, model)!
	mut rows := []string{}
	for key, row in s.records.organizations {
		if key.starts_with(model + '|') { rows << row }
	}
	return rows
}

pub fn (mut s MemoryStorage) adapter_model_write(model string, encoded string, creating bool) ! {
	s.check_write()!
	row := org_json_fields(encoded)!
	id := row['id'] or { return error('missing adapter id') }
	key := model + '|' + id.str()
	if creating && key in s.records.organizations { return error('duplicate adapter id') }
	for other in s.adapter_model_rows(model)! {
		stored := org_json_fields(other)!
		if (stored['id'] or { json2.Any('') }).str() == id.str() { continue
		 }
		for field, attribute in s.adapter_models[model].fields {
			if !attribute.unique { continue
			 }
			value := row[field] or { continue }
			if value is json2.Null { continue
			 }
			if previous := stored[field] {
				if adapter_equal(previous, value, false) {
					return error('duplicate unique adapter field')
				}
			}
		}
	}
	if creating || key in s.records.organizations { s.records.organizations[key] = encoded }
}

pub fn (mut s MemoryStorage) adapter_model_delete(model string, id string) ! {
	s.check_write()!
	require_adapter_model(s.adapter_models, model)!
	s.records.organizations.delete(model + '|' + id)
}

fn (mut s SQLiteStorage) migrate_adapter_models() ! {
	for model, definition in s.adapter_models {
		table := adapter_model_table(s.adapter_models, model)!
		s.db.exec('CREATE TABLE IF NOT EXISTS ${table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)')!
		for field, attribute in definition.fields {
			if !attribute.unique { continue
			 }
			path := ('$.' + json.encode(field)).replace("'", "''")
			s.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${sql_identifier('ba_adapter_' +
				digest(table + field)[..24])} ON ${table}(json_extract(data,\'${path}\'))')!
		}
	}
}

pub fn (mut s SQLiteStorage) adapter_model_rows(model string) ![]string {
	rows :=
		s.db.exec('SELECT data FROM ${adapter_model_table(s.adapter_models, model)!} ORDER BY rowid')!
	return rows.map(it.vals[0])
}

pub fn (mut s SQLiteStorage) adapter_model_write(model string, encoded string, creating bool) ! {
	table := adapter_model_table(s.adapter_models, model)!
	row := org_json_fields(encoded)!
	id := row['id'] or { return error('missing adapter id') }
	if creating {
		s.db.exec_param2('INSERT INTO ${table}(id,data) VALUES (?,?)', id.str(), encoded)!
	} else {
		s.db.exec_param2('UPDATE ${table} SET data=? WHERE id=?', encoded, id.str())!
	}
}

pub fn (mut s SQLiteStorage) adapter_model_delete(model string, id string) ! {
	s.db.exec_param('DELETE FROM ${adapter_model_table(s.adapter_models, model)!} WHERE id=?', id)!
}

pub fn (mut s PostgresStorage) adapter_model_rows(model string) ![]string {
	require_adapter_model(s.adapter_models, model)!
	return s.select_rows(model, '', [])
}

pub fn (mut s PostgresStorage) adapter_model_write(model string, encoded string, creating bool) ! {
	require_adapter_model(s.adapter_models, model)!
	if creating {
		s.create_row(model, encoded)!
	} else {
		s.update_row(model, encoded)!
	}
}

pub fn (mut s PostgresStorage) adapter_model_delete(model string, id string) ! {
	require_adapter_model(s.adapter_models, model)!
	s.delete_row(model, id)!
}

pub fn (mut s MongoStorage) adapter_model_rows(model string) ![]string {
	require_adapter_model(s.adapter_models, model)!
	return s.select_rows(model, {})
}

pub fn (mut s MongoStorage) adapter_model_write(model string, encoded string, creating bool) ! {
	require_adapter_model(s.adapter_models, model)!
	if creating {
		s.create_row(model, encoded)!
	} else {
		s.update_row(model, encoded)!
	}
}

pub fn (mut s MongoStorage) adapter_model_delete(model string, id string) ! {
	require_adapter_model(s.adapter_models, model)!
	s.delete_row(model, id)!
}
