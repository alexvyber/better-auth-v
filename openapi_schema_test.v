module better_auth

import x.json2

fn test_openapi_intersection_conflicts_and_structural_equality() ! {
	// Equivalent definitions in different insertion orders still merge.
	left :=
		json2.decode[map[string]json2.Any]('{"type":["object","null"],"properties":{"name":{"type":"string","minLength":2}},"required":["name"]}')!
	right :=
		json2.decode[map[string]json2.Any]('{"type":"object","properties":{"name":{"minLength":2,"type":"string"},"active":{"type":"boolean"}},"required":["name","active"]}')!
	merged := openapi_merge_objects(left, right) or { return error('expected compatible merge') }
	assert merged['type']!.str() == 'object'
	assert merged['required']!.as_array().map(it.str()) == ['name', 'active']
	assert merged['properties']!.as_map().len == 2
	conflict :=
		json2.decode[map[string]json2.Any]('{"type":"object","properties":{"name":{"type":"number"}}}')!
	if _ := openapi_merge_objects(left, conflict) { assert false
	 }
	closed := json2.decode[map[string]json2.Any]('{"type":"object","additionalProperties":false}')!
	open :=
		json2.decode[map[string]json2.Any]('{"type":"object","additionalProperties":{"type":"string"}}')!
	if _ := openapi_merge_objects(closed, open) { assert false
	 }
}

fn test_openapi_declarative_schema_rejects_unknown_and_excessively_deep_nodes() ! {
	for encoded in ['{"kind":"callback"}', '{"kind":"optional"}', '[]'] {
		node := json2.decode[json2.Any](encoded)!
		if _ := openapi_project(node, 0) { assert false
		 }
	}
	mut encoded := '{"kind":"string"}'
	for _ in 0 .. 66 {
		encoded = '{"kind":"optional","inner":' + encoded + '}'
	}
	node := json2.decode[json2.Any](encoded)!
	if _ := openapi_project(node, 0) { assert false
	 }
	if _ := openapi_accepts_undefined(node, 65) { assert false
	 }
}
