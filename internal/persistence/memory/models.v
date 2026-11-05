module better_auth

import x.json2

pub fn (mut s MemoryStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	s.adapter_models = models.clone()
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
