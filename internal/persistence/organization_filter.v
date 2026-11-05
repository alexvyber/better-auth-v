module better_auth

import x.json2

fn organization_row_matches(row map[string]json2.Any, filter map[string]string) bool {
	for field, value in filter {
		actual := row[field] or { return false }
		if actual.str() != value { return false }
	}
	return true
}
