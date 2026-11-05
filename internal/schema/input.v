module better_auth

import x.json2

// Standard Schema adapters describe their result; V owns error and precedence rules.
pub struct FieldInputResult {
pub:
	value           json2.Any
	invalid         bool
	message         string
	asynchronous    bool
	undefined_value bool @[json: undefinedValue]
}

fn passthrough_field_input(value json2.Any) !FieldInputResult {
	return FieldInputResult{
		value: value
	}
}

fn parse_field_value(field AdditionalField, input json2.Any) !FieldInputResult {
	mut result := FieldInputResult{
		value: input
	}
	if field.validate_input != passthrough_field_input {
		result = field.validate_input(input)!
	} else if field.transform_input != passthrough_field_input {
		result = field.transform_input(input)!
	}
	if result.asynchronous {
		return fail(500, 'ASYNC_VALIDATION_NOT_SUPPORTED', 'Async validation is not supported')
	}
	if result.invalid { return fail(400, 'VALIDATION_ERROR', if result.message != '' {
			result.message
		} else {
			'Validation Error'
		})
	 }
	if !result.undefined_value { validate_field(field, result.value)! }
	return result
}

fn no_field_default() !FieldInputResult {
	return FieldInputResult{
		undefined_value: true
	}
}

fn (field AdditionalField) has_default() bool {
	return field.default_value != none || field.default_factory != no_field_default
}

fn (field AdditionalField) resolve_default() !Lookup[json2.Any] {
	if value := field.default_value { return Lookup[json2.Any]{
			value: value
		} }
	if field.default_factory == no_field_default { return Lookup[json2.Any]{} }
	result := field.default_factory()!
	if result.asynchronous { return error('asynchronous field defaults are not supported') }
	if result.invalid { return error('invalid field default') }
	if result.undefined_value { return Lookup[json2.Any]{} }
	validate_field(field, result.value)!
	return Lookup[json2.Any]{
		value: result.value
	}
}

fn fill_field_defaults(schema map[string]AdditionalField, input map[string]json2.Any) !map[string]json2.Any {
	mut result := input.clone()
	for name, field in schema {
		if value := result[name] {
			if !field.required || value !is json2.Null { continue
			 }
		}
		if fallback := (field.resolve_default()!).value {
			validate_field(field, fallback)!
			result[name] = fallback
		}
	}
	return result
}
