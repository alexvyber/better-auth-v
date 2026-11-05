module better_auth

fn organization_test_user() User {
	return User{
		id:         'owner'
		name:       'Owner'
		email:      'owner@example.com'
		created_at: '2025-01-01T00:00:00.000Z'
		updated_at: '2025-01-01T00:00:00.000Z'
	}
}

fn test_organization_memory_snapshot_and_unique_membership_constraints() ! {
	mut storage := open_memory()
	storage.create_user(organization_test_user())!
	storage.begin()!
	storage.organization_create('organization',
		'{"id":"org","name":"Organization","slug":"organization","createdAt":"2025-01-01T00:00:00.000Z"}')!
	storage.organization_create('member',
		'{"id":"member","organizationId":"org","userId":"owner","role":"owner","createdAt":"2025-01-01T00:00:00.000Z"}')!
	if _ := storage.organization_create('member', '{"id":"duplicate","organizationId":"org","userId":"owner","role":"admin"}') { assert false
	 }
	storage.rollback()!
	assert (storage.organization_rows('organization', {})!).len == 0
	assert (storage.organization_rows('member', {})!).len == 0
	assert (storage.user('owner')!).value != none
}

fn test_organization_sqlite_version_six_upgrade_preserves_core_records_and_cascades() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	storage.migrate()!
	storage.create_user(organization_test_user())!
	storage.create_session(Session{
		id:         'session'
		user_id:    'owner'
		token:      ''
		expires_at: '2030-01-01T00:00:00.000Z'
		created_at: '2025-01-01T00:00:00.000Z'
		updated_at: '2025-01-01T00:00:00.000Z'
	}, 'hash')!
	for table in ['auth_organization_role', 'auth_invitation', 'auth_member', 'auth_organization'] {
		storage.db.exec('DROP TABLE ' + table)!
	}
	storage.db.exec('DELETE FROM auth_migration WHERE version=7')!
	storage.migrate()!
	storage.migrate()!
	assert storage.db.q_int('SELECT max(version) FROM auth_migration')! == 7
	assert (storage.session('hash')!).value != none
	storage.organization_create('organization',
		'{"id":"org","name":"Organization","slug":"organization","createdAt":"2025-01-01T00:00:00.000Z"}')!
	storage.organization_create('member',
		'{"id":"member","organizationId":"org","userId":"owner","role":"owner","createdAt":"2025-01-01T00:00:00.000Z"}')!
	storage.organization_create('invitation',
		'{"id":"invitation","organizationId":"org","inviterId":"owner","email":"invitee@example.com","role":"member","status":"pending","createdAt":"2025-01-01T00:00:00.000Z","expiresAt":"2030-01-01T00:00:00.000Z"}')!
	storage.organization_create('organizationRole',
		'{"id":"role","organizationId":"org","role":"custom","permission":"{}","createdAt":"2025-01-01T00:00:00.000Z"}')!
	storage.organization_delete('organization', 'org')!
	for model in ['member', 'invitation', 'organizationRole'] {
		assert (storage.organization_rows(model, {})!).len == 0
	}
	assert (storage.session('hash')!).value != none
	assert (storage.user('owner')!).value != none
}

fn test_organization_unique_additional_fields_fail_closed_until_migration() ! {
	mut storage := open_sqlite(':memory:')!
	defer { storage.close() or {} }
	storage.migrate()!
	storage.configure_model_fields({
		'organization': {
			'external': AdditionalField{ field_type: 'string', unique: true }
		}
	})!
	encoded := '{"id":"org","name":"Organization","slug":"organization","external":"unique","createdAt":"2025-01-01T00:00:00.000Z"}'
	storage.organization_create('organization', encoded) or {
		assert err.msg().contains('migrate_storage')
	}
	assert (storage.organization_rows('organization', {})!).len == 0
	storage.migrate()!
	storage.organization_create('organization', encoded)!
	if _ := storage.organization_create('organization', '{"id":"second","name":"Second","slug":"second","external":"unique","createdAt":"2025-01-01T00:00:00.000Z"}') { assert false
	 }
	assert (storage.organization_rows('organization', {})!).len == 1
	// Protected model fields cannot replace the core identity schema.
	if _ := storage.configure_model_fields({
		'organization': {
			'id': AdditionalField{ field_type: 'string' }
		}
	})
	{
		assert false
	}
}
