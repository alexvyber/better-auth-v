module better_auth

fn test_native_session_bulk_delete_preserves_other_users_and_reports_count() ! {
	mut storage := open_memory()
	for id in ['one', 'two'] {
		storage.create_user(User{ id: id, email: id + '@example.com', name: id })!
	}
	for id in ['a', 'b', 'c'] {
		storage.create_session(Session{
			id:      id
			user_id: if id == 'c' { 'two' } else { 'one' }
			token:   id
		}, digest(id))!
	}
	mut auth := new(Config{ secret: 'test-secret-at-least-thirty-two-bytes' }, storage)!
	defer { auth.close() or {} }
	deleted := auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterDeleteSessions', '["one"]')
	})!
	assert deleted == '2'
	assert storage.sessions('one')!.len == 0
	assert storage.sessions('two')!.len == 1
	assert auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterDeleteSessions', '["one"]')
	})! == '0'
	assert auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterDeleteSessions', '[""]')
	})! == '0'
	assert storage.sessions('two')!.len == 1
}

fn test_body_limit_is_opt_in_and_enforced_at_exact_byte_boundary() ! {
	mut unlimited := new(Config{ secret: 'test-secret-at-least-thirty-two-bytes' }, open_memory())!
	defer { unlimited.close() or {} }
	assert unlimited.handle(Request{
		url:  'http://localhost:3000/api/auth/ok'
		body: 'x'.repeat(70000)
	}).status == 200
	mut bounded := new(Config{ secret: 'test-secret-at-least-thirty-two-bytes', max_body_bytes: 64 },
		open_memory())!
	defer { bounded.close() or {} }
	assert bounded.handle(Request{ url: 'http://localhost:3000/api/auth/ok', body: 'x'.repeat(64) }).status == 200
	assert bounded.handle(Request{ url: 'http://localhost:3000/api/auth/ok', body: 'x'.repeat(65) }).status == 413
}
