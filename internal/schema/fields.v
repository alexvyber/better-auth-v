module better_auth

import time
import x.json2

const core_user_fields = ['id', 'name', 'email', 'emailVerified', 'image', 'createdAt', 'updatedAt']

const sign_up_reserved_fields = ['name', 'email', 'password', 'image', 'callbackURL', 'rememberMe']

const core_session_fields = ['id', 'userId', 'token', 'expiresAt', 'createdAt', 'updatedAt',
	'ipAddress', 'userAgent', 'persistent', 'encrypted_token', 'additional_fields', '$vSession']

fn validate_field(field AdditionalField, value json2.Any) ! {
	if value is json2.Null {
		if field.required { return fail(400, 'VALIDATION_ERROR', 'Required field cannot be null') }
		return
	}
	valid := match field.field_type {
		'string' {
			value is string
		}
		'number' {
			value is int || value is i64 || value is f64 || value is u64
		}
		'boolean' {
			value is bool
		}
		'date' {
			if value is string {
				time.parse_rfc3339(value) or {
					return fail(400, 'VALIDATION_ERROR', 'Invalid date')
				}
				true
			} else {
				false
			}
		}
		'json' {
			true
		}
		'string[]', 'number[]' {
			if value is []json2.Any {
				for element in value {
					if field.field_type == 'string[]' && element !is string {
						return fail(400, 'VALIDATION_ERROR', 'Invalid array element')
					}
					if field.field_type == 'number[]' && !(element is int
						|| element is i64 || element is f64 || element is u64) {
						return fail(400, 'VALIDATION_ERROR', 'Invalid array element')
					}
				}
				true
			} else {
				false
			}
		}
		else {
			false
		}
	}

	if !valid { return fail(400, 'VALIDATION_ERROR', 'Invalid additional field type') }
}

fn (a &Auth) parse_user_fields(input map[string]json2.Any, existing map[string]json2.Any, creating bool) !map[string]json2.Any {
	return parse_fields(a.config.user_fields, input, existing, creating)
}

fn parse_fields(schema map[string]AdditionalField, input map[string]json2.Any, existing map[string]json2.Any, creating bool) !map[string]json2.Any {
	mut result := existing.clone()
	for key, field in schema {
		if value := input[key] {
			if !field.input {
				if creating {
					if fallback := (field.resolve_default()!).value {
						result[key] = fallback
						continue
					}
				}
				if js_truthy(value) {
					return fail(400, 'FIELD_NOT_ALLOWED', '${key} is not allowed to be set')
				}
				continue
			}
			parsed := parse_field_value(field, value)!
			if !parsed.undefined_value { result[key] = parsed.value }
		} else if creating {
			if value := (field.resolve_default()!).value {
				validate_field(field, value)!
				result[key] = value
			} else if field.required {
				return fail(400, 'MISSING_FIELD', '${key} is required')
			}
		}
	}
	return result
}

fn js_truthy(value json2.Any) bool {
	return match value {
		json2.Null { false }
		bool { value }
		string { value != '' }
		f64 { value != 0 }
		int { value != 0 }
		i64 { value != 0 }
		u64 { value != 0 }
		else { true }
	}
}
