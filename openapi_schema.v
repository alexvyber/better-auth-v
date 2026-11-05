module better_auth

import x.json2

// Endpoint input-schema IR is configuration, not executable validation code.
// It preserves wrappers so documentation can distinguish whole-body acceptance
// of undefined from property optionality without executing default factories.
fn openapi_node(value json2.Any, depth int) !map[string]json2.Any {
	if depth > 64 { return error('Endpoint schema nesting exceeds 64') }
	if value !is map[string]json2.Any { return error('Expected endpoint schema node') }
	return value.as_map()
}

fn openapi_node_child(node map[string]json2.Any, key string) !json2.Any {
	return node[key] or { return error('Missing endpoint schema child: ${key}') }
}

fn openapi_pipe_child(node map[string]json2.Any) !json2.Any {
	input := openapi_node_child(node, 'input')!
	input_node := openapi_node(input, 0)!
	if (input_node['kind'] or { json2.Any('') }).str() == 'transform' {
		return openapi_node_child(node, 'output')!
	}
	return input
}

fn openapi_accepts_undefined(value json2.Any, depth int) !bool {
	node := openapi_node(value, depth)!
	kind := (node['kind'] or { json2.Any('') }).str()
	match kind {
		'optional', 'default', 'prefault', 'catch', 'any', 'unknown', 'undefined', 'void' {
			return true
		}
		'nonoptional' {
			return false
		}
		'nullable', 'readonly' {
			return openapi_accepts_undefined(openapi_node_child(node, 'inner')!, depth + 1)
		}
		'pipe' {
			return openapi_accepts_undefined(openapi_pipe_child(node)!, depth + 1)
		}
		'union' {
			for option in (node['options'] or { json2.Any([]json2.Any{}) }).as_array() {
				if openapi_accepts_undefined(option, depth + 1)! { return true }
			}
			return false
		}
		'intersection' {
			left := openapi_accepts_undefined(openapi_node_child(node, 'left')!, depth + 1)!
			right := openapi_accepts_undefined(openapi_node_child(node, 'right')!, depth + 1)!
			return left && right
		}
		else {
			return false
		}
	}
}

fn openapi_property_optional(value json2.Any, depth int) !bool {
	node := openapi_node(value, depth)!
	kind := (node['kind'] or { json2.Any('') }).str()
	if kind == 'catch' {
		return openapi_property_optional(openapi_node_child(node, 'inner')!, depth + 1)
	}
	if kind == 'pipe' {
		input := openapi_node(openapi_node_child(node, 'input')!, depth + 1)!
		if (input['kind'] or { json2.Any('') }).str() == 'transform' {
			return openapi_property_optional(openapi_node_child(node, 'output')!, depth + 1)
		}
	}
	return (node['optional'] or { json2.Any(false) }).bool()
}

fn openapi_schema_is_object(schema map[string]json2.Any) bool {
	if '$ref' in schema || 'allOf' in schema || 'anyOf' in schema || 'oneOf' in schema {
		return false
	}
	type_value := schema['type'] or { return false }
	return type_value.str() == 'object'
		|| (type_value is []json2.Any && type_value.as_array().any(it.str() == 'object'))
}

fn openapi_schema_nullable(schema map[string]json2.Any) bool {
	type_value := schema['type'] or { return false }
	return type_value is []json2.Any && type_value.as_array().any(it.str() == 'null')
}

fn openapi_schema_equal(left json2.Any, right json2.Any) bool {
	// JSON objects compare structurally, independently of definition insertion order.
	if left is map[string]json2.Any && right is map[string]json2.Any {
		l := left.clone()
		r := right.clone()
		if l.len != r.len { return false }
		for key, value in l {
			other := r[key] or { return false }
			if !openapi_schema_equal(value, other) { return false }
		}
		return true
	}
	if left is []json2.Any && right is []json2.Any {
		l := left.clone()
		r := right.clone()
		if l.len != r.len { return false }
		for i, value in l {
			if !openapi_schema_equal(value, r[i]) { return false }
		}
		return true
	}
	return left.json_str() == right.json_str()
}

fn openapi_merge_objects(left map[string]json2.Any, right map[string]json2.Any) ?map[string]json2.Any {
	if !openapi_schema_is_object(left) || !openapi_schema_is_object(right) { return none }
	mut properties := (left['properties'] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
	for key, value in (right['properties'] or { json2.Any(map[string]json2.Any{}) }).as_map() {
		if existing := properties[key] {
			if !openapi_schema_equal(existing, value) { return none }
		}
		properties[key] = value
	}
	mut result := map[string]json2.Any{}
	for key in ['additionalProperties', 'propertyNames'] {
		if key in left && key in right && !openapi_schema_equal(left[key] or { return none }, right[key] or {
			return none
		}) {
			return none
		}
		if value := left[key] {
			result[key] = value
		} else if value := right[key] {
			result[key] = value
		}
	}
	mut required := []json2.Any{}
	mut seen := map[string]bool{}
	for schema in [left, right] {
		for key in (schema['required'] or { json2.Any([]json2.Any{}) }).as_array() {
			if !seen[key.str()] {
				required << key
				seen[key.str()] = true
			}
		}
	}
	result['type'] = if openapi_schema_nullable(left) && openapi_schema_nullable(right) {
		json2.Any([json2.Any('object'), json2.Any('null')])
	} else {
		json2.Any('object')
	}
	if properties.len > 0 { result['properties'] = json2.Any(properties) }
	if required.len > 0 { result['required'] = json2.Any(required) }
	if description := left['description'] {
		result['description'] = description
	} else if description := right['description'] {
		result['description'] = description
	}
	return result
}

fn openapi_project(value json2.Any, depth int) !map[string]json2.Any {
	node := openapi_node(value, depth)!
	kind := (node['kind'] or { json2.Any('') }).str()
	mut schema := map[string]json2.Any{}
	match kind {
		'optional', 'default', 'prefault', 'nonoptional', 'catch', 'readonly' {
			schema = openapi_project(openapi_node_child(node, 'inner')!, depth + 1)!
		}
		'pipe' {
			schema = openapi_project(openapi_pipe_child(node)!, depth + 1)!
		}
		'nullable' {
			schema = openapi_project(openapi_node_child(node, 'inner')!, depth + 1)!
			if type_value := schema['type'] {
				mut types := if type_value is []json2.Any { type_value.clone() } else { [
						type_value,
					] }
				if !types.any(it.str() == 'null') { types << json2.Any('null') }
				schema['type'] = json2.Any(types)
			} else if schema.len > 0 {
				schema = {
					'anyOf': json2.Any([json2.Any(schema.clone()),
						json2.Any({
							'type': json2.Any('null')
						})])
				}
			}
		}
		'object' {
			mut properties := map[string]json2.Any{}
			mut required := []json2.Any{}
			for name, child in (node['properties'] or { json2.Any(map[string]json2.Any{}) }).as_map() {
				properties[name] = json2.Any(openapi_project(child, depth + 1)!)
				if !openapi_property_optional(child, depth + 1)! { required << json2.Any(name) }
			}
			schema['type'] = 'object'
			schema['properties'] = json2.Any(properties)
			if required.len > 0 { schema['required'] = json2.Any(required) }
		}
		'record' {
			schema['type'] = 'object'
			schema['propertyNames'] = json2.Any(openapi_project(openapi_node_child(node, 'key')!,

				depth + 1)!)
			schema['additionalProperties'] = json2.Any(openapi_project(openapi_node_child(node,
				'value')!, depth + 1)!)
		}
		'intersection' {
			left := openapi_project(openapi_node_child(node, 'left')!, depth + 1)!
			right := openapi_project(openapi_node_child(node, 'right')!, depth + 1)!
			schema = openapi_merge_objects(left, right) or {
				{
					'allOf': json2.Any([json2.Any(left), json2.Any(right)])
				}
			}
		}
		'union' {
			mut options := []json2.Any{}
			for child in (node['options'] or { json2.Any([]json2.Any{}) }).as_array() {
				child_node := openapi_node(child, depth + 1)!
				if (child_node['kind'] or { json2.Any('') }).str() in ['undefined', 'void'] { continue
				 }
				options << json2.Any(openapi_project(child, depth + 1)!)
			}
			if options.len == 1 {
				schema = options[0].as_map().clone()
			} else if options.len > 1 {
				key := if (node['inclusive'] or { json2.Any(true) }).bool() {
					'anyOf'
				} else {
					'oneOf'
				}
				schema[key] = json2.Any(options)
			}
		}
		'array' {
			schema['type'] = 'array'
			schema['items'] = json2.Any(openapi_project(openapi_node_child(node, 'element')!,

				depth + 1)!)
		}
		'literal', 'enum' {
			schema['enum'] = openapi_node_child(node, 'values')!
			if kind == 'enum' { schema['type'] = 'string' }
		}
		'any', 'unknown', 'undefined', 'void' {}
		'string', 'number', 'boolean', 'null' {
			schema['type'] = kind
			if kind == 'string' {
				for key in ['minLength', 'maxLength'] {
					if constraint := node[key] { schema[key] = constraint }
				}
			}
		}
		'date' {
			schema['type'] = 'string'
			schema['format'] = 'date-time'
		}
		else {
			return error('Unsupported endpoint schema kind: ${kind}')
		}
	}

	if description := node['description'] { schema['description'] = description }
	return schema
}

fn openapi_endpoint_input(mut operation map[string]json2.Any, endpoint Endpoint, metadata map[string]json2.Any) ! {
	if endpoint.body_schema != '' && 'requestBody' !in metadata {
		node := json2.decode[json2.Any](endpoint.body_schema)!
		schema := openapi_project(node, 0)!
		required := !openapi_accepts_undefined(node, 0)!
		operation['requestBody'] = json2.Any({
			'required': json2.Any(required)
			'content':  json2.Any({
				'application/json': json2.Any({
					'schema': json2.Any(schema)
				})
			})
		})
	}
	if endpoint.query_schema != '' && 'parameters' !in metadata {
		node := json2.decode[json2.Any](endpoint.query_schema)!
		definition := openapi_node(node, 0)!
		if (definition['kind'] or { json2.Any('') }).str() != 'object' {
			return error('Endpoint query schema must be an object')
		}
		mut parameters := []json2.Any{}
		for name, child in (definition['properties'] or { json2.Any(map[string]json2.Any{}) }).as_map() {
			parameters << json2.Any({
				'name':   json2.Any(name)
				'in':     json2.Any('query')
				'schema': json2.Any(openapi_project(child, 1)!)
			})
		}
		operation['parameters'] = json2.Any(parameters)
	}
}
