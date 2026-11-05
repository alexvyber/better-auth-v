module better_auth

import x.json2

fn native_generated_field_default() !FieldInputResult {
	return FieldInputResult{
		value: generate_auth_id(32)!
	}
}

fn native_failing_field_default() !FieldInputResult {
	return error('default must not execute while documenting configuration')
}

fn test_native_field_defaults_are_per_creation_and_updates_preserve_existing_values() ! {
	schema := {
		'nonce': AdditionalField{
			field_type:      'string'
			required:        true
			input:           false
			default_factory: native_generated_field_default
		}
	}
	first := parse_fields(schema, {}, {}, true)!
	second := parse_fields(schema, {}, {}, true)!
	assert (first['nonce'] or { json2.Any('') }).str().len == 32
	assert (first['nonce'] or { json2.Any('') }).str() != (second['nonce'] or { json2.Any('') }).str()
	updated := parse_fields(schema, {}, first, false)!
	assert (updated['nonce'] or { json2.Any('') }).str() == (first['nonce'] or { json2.Any('') }).str()
	protected := parse_fields(schema, {
		'nonce': json2.Any('untrusted')
	}, {}, true)!
	assert (protected['nonce'] or { json2.Any('') }).str() != 'untrusted'
}

fn test_schema_generation_does_not_evaluate_native_default_factories() ! {
	mut storage := open_memory()
	mut auth := new(Config{
		secret:      '01234567890123456789012345678901'
		plugins:     [Plugin(OpenAPIPlugin{})]
		user_fields: {
			'generated': AdditionalField{
				field_type:      'string'
				required:        true
				default_factory: native_failing_field_default
			}
		}
	}, storage)!
	schema := org_json_fields(auth.generate_openapi_schema()!)!
	assert (schema['openapi'] or { json2.Any('') }).str() == '3.1.1'
	if _ := auth.sign_up(SignUpInput{ name: 'Fail', email: 'fail@example.com', password: 'password' }, RequestContext{}) {
		assert false
	} else {
		assert err.msg().contains('default must not execute')
	}
	assert (storage.users()!).len == 0
}
