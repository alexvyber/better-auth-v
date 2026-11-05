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

fn test_sqlite_missing_configured_fields_read_as_null_without_running_defaults_or_rewriting_rows() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	storage.migrate()!
	storage.create_user(User{
		id:                'legacy'
		name:              'Legacy'
		email:             'legacy@example.com'
		created_at:        '2025-01-01T00:00:00Z'
		updated_at:        '2025-01-01T00:00:00Z'
		additional_fields: {
			'unmodeled': json2.Any(true)
		}
	})!
	storage.create_session(Session{
		id:         'session'
		user_id:    'legacy'
		token:      'token'
		expires_at: '2030-01-01T00:00:00Z'
		created_at: '2025-01-01T00:00:00Z'
		updated_at: '2025-01-01T00:00:00Z'
	}, 'hash')!
	before := (storage.db.exec_param('SELECT data FROM auth_user WHERE id=?', 'legacy')!)[0].vals[0]
	storage.configure_fields({
		'password': AdditionalField{ field_type: 'string' }
		'optional': AdditionalField{
			field_type:      'string'
			default_factory: native_failing_field_default
		}
	}, {
		'note': AdditionalField{
			field_type:      'string'
			default_factory: native_failing_field_default
		}
	})!
	user := (storage.user('legacy')!).value or { return error('missing legacy user') }
	assert (user.additional_fields['optional'] or { return error('missing NULL') }) is json2.Null
	assert 'password' !in user.additional_fields
	assert (user.additional_fields['unmodeled'] or { json2.Any(false) }).bool()
	by_email := (storage.user_by_email('legacy@example.com')!).value or {
		return error('missing email user')
	}

	assert (by_email.additional_fields['optional'] or { return error('missing NULL') }) is json2.Null
	assert ((storage.users()!)[0].additional_fields['optional'] or { return error('missing NULL') }) is json2.Null
	session := (storage.session('hash')!).value or { return error('missing session') }
	assert (session.additional_fields['note'] or { return error('missing NULL') }) is json2.Null
	by_id := (storage.session_by_id('session')!).value or { return error('missing id session') }
	assert (by_id.additional_fields['note'] or { return error('missing NULL') }) is json2.Null
	assert ((storage.sessions('legacy')!)[0].additional_fields['note'] or {
		return error('missing NULL')
	}) is json2.Null
	assert (storage.db.exec_param('SELECT data FROM auth_user WHERE id=?', 'legacy')!)[0].vals[0] == before
}
