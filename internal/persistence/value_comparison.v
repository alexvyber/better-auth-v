module better_auth

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
