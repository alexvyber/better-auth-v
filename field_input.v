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
