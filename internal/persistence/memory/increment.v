module better_auth

import x.json2

pub fn (mut s MemoryStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	s.check_write()!
	encoded := if model == 'user' {
		if user := (s.user(id)!).value { encode_user(user) } else { return false }
	} else {
		s.records.organizations[model + '|' + id] or { return false }
	}
	mut row := org_json_fields(encoded)!
	for field, value in expected {
		if !adapter_equal(row[field] or { json2.Any(json2.Null{}) }, value, false) { return false }
	}
	for field, value in patch {
		row[field] = value
	}
	if model == 'user' {
		s.update_user(decode_user(json2.Any(row).json_str())!)!
	} else {
		s.adapter_model_write(model, json2.Any(row).json_str(), false)!
	}
	return true
}
