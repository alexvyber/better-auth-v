module better_auth

import json
import x.json2

pub fn (mut s SQLiteStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	if model == 'user' { s.require_unique_indexes()! }
	table := if model == 'user' {
		sql_identifier('auth_user')
	} else {
		adapter_model_table(s.adapter_models, model)!
	}
	encoded := json2.Any(patch).json_str()
	mut setters := []string{}
	mut parameters := []string{}
	for field, _ in patch {
		path := '$.' + json.encode(field)
		setters << '?,json_extract(?,?)'
		parameters << [path, encoded, path]
	}
	mut assignment := 'data=json_set(data,' + setters.join(',') + ')'
	if model == 'user' && 'email' in patch {
		assignment += ',email=json_extract(?,?)'
		parameters << [encoded, '$.email']
	}
	parameters << id
	mut guard := ['id=?']
	snapshot := json2.Any(expected).json_str()
	for field, _ in expected {
		path := '$.' + json.encode(field)
		guard << 'json_extract(data,?) IS json_extract(?,?)'
		parameters << [path, snapshot, path]
	}
	rows := s.db.exec_param_many('UPDATE ${table} SET ${assignment} WHERE ${guard.join(' AND ')} RETURNING id',
		parameters)!
	return rows.len == 1
}
