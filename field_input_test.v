module better_auth

import x.json2

fn native_field_validator(value json2.Any) !FieldInputResult {
	if value !is string { return FieldInputResult{
			invalid: true
			message: 'Expected a string'
		} }
	if !value.str().starts_with('valid') { return FieldInputResult{
			invalid: true
			message: 'Invalid name'
		} }
	return FieldInputResult{
		value: value.str().to_lower()
	}
}

fn reject_field_transform(_ json2.Any) !FieldInputResult {
	return error('validator must take precedence')
}

fn test_native_field_validation_precedence_and_protected_input() ! {
	schema := {
		'username':  AdditionalField{
			field_type:      'string'
			validate_input:  native_field_validator
			transform_input: reject_field_transform
		}
		'authority': AdditionalField{
			field_type:      'boolean'
			input:           false
			default_value:   json2.Any(false)
			transform_input: reject_field_transform
		}
	}
	parsed := parse_fields(schema, {
		'username':  json2.Any('validNAME')
		'authority': json2.Any(true)
	}, map[string]json2.Any{}, true)!
	assert parsed['username']!.str() == 'validname'
	assert parsed['authority']!.bool() == false
	parse_fields(schema, {
		'username': json2.Any('other')
	}, map[string]json2.Any{}, true) or {
		assert err is APIError
		if err is APIError {
			assert err.status == 400
			assert err.code == 'VALIDATION_ERROR'
			assert err.message == 'Invalid name'
		}
		return
	}
	assert false
}

fn test_native_field_async_validation_is_rejected() ! {
	schema := {
		'username': AdditionalField{
			field_type:     'string'
			validate_input: fn (_ json2.Any) !FieldInputResult {
				return FieldInputResult{
					asynchronous: true
				}
			}
		}
	}
	parse_fields(schema, {
		'username': json2.Any('name')
	}, map[string]json2.Any{}, true) or {
		assert err is APIError
		if err is APIError {
			assert err.status == 500
			assert err.code == 'ASYNC_VALIDATION_NOT_SUPPORTED'
		}
		return
	}
	assert false
}

fn test_sqlite_unique_field_migrations_are_explicit_idempotent_and_transactional() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	storage.migrate()!
	storage.configure_fields({
		'username': AdditionalField{ field_type: 'string', unique: true }
	}, map[string]AdditionalField{})!
	proposed := User{
		id:                'one'
		email:             'one@example.com'
		name:              'One'
		created_at:        '2026-01-01T00:00:00.000Z'
		updated_at:        '2026-01-01T00:00:00.000Z'
		additional_fields: {
			'username': json2.Any('unique')
		}
	}
	mut blocked := false
	storage.create_user(proposed) or { blocked = err.msg().contains('migrate_storage') }
	assert blocked
	storage.migrate()!
	storage.migrate()!
	storage.create_user(proposed)!
	mut duplicate := false
	storage.create_user(User{ ...proposed, id: 'two', email: 'two@example.com' }) or {
		duplicate = true
	}
	assert duplicate
	assert storage.users()!.len == 1
}

fn test_memory_unique_fields_roll_back_with_user_data() ! {
	mut storage := open_memory()
	storage.configure_fields({
		'username': AdditionalField{ field_type: 'string', unique: true }
	}, map[string]AdditionalField{})!
	first := User{
		id:                'one'
		email:             'one@example.com'
		additional_fields: {
			'username': json2.Any('unique')
		}
	}
	storage.create_user(first)!
	storage.begin()!
	storage.update_user(User{
		...first
		additional_fields: {
			'username': json2.Any('changed')
		}
	})!
	storage.rollback()!
	mut duplicate := false
	storage.create_user(User{ ...first, id: 'two', email: 'two@example.com' }) or {
		duplicate = true
	}
	assert duplicate
	found := storage.user('one')!
	actual := found.value or { return error('missing user') }
	assert actual.additional_fields['username']!.str() == 'unique'
	storage.close()!
}
