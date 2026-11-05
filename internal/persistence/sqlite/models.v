module better_auth

import json

pub fn (mut s SQLiteStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	s.adapter_models = models.clone()
}

fn adapter_model_table(models map[string]AdapterModel, model string) !string {
	require_adapter_model(models, model)!
	definition := models[model] or { return error('unknown adapter model') }
	return sql_identifier('auth_adapter_' +
		if definition.name == '' { model } else { definition.name })
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
