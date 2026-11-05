module better_auth

import x.json2

fn test_malformed_adapter_predicates_cannot_turn_into_unfiltered_deletes() ! {
	mut auth :=
		new(Config{ secret: 'adapter-query-test-secret-with-at-least-32-bytes' }, MemoryStorage{})!
	defer { auth.close() or {} }
	auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery',
			'["create",{"model":"user","data":{"name":"Retained","email":"retained@example.com"}}]')
	})!
	for query in [
		'["deleteMany",{"model":"user","where":"invalid"}]',
		'["deleteMany",{"model":"user","where":[{"field":"name","value":"Retained","operator":"typo"}]}]',
		'["deleteMany",{"model":"user","where":[{"field":"name","value":"Retained","operator":"in"}]}]',
		'["deleteMany",{"model":"user","where":[{"field":"name","value":"Retained","connector":"typo"}]}]',
	] {
		mut rejected := false
		auth.with_internal(fn [query] (mut context EndpointContext) !string {
			return context.invoke_internal('adapterQuery', query)
		}) or { rejected = true }
		assert rejected
	}
	assert auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery', '["count",{"model":"user"}]')
	})! == '1'
	for query in [
		'["findMany",{"model":"user","where":[{"field":"id","value":"absent"}],"select":"name"}]',
		'["findMany",{"model":"user","where":[{"field":"id","value":"absent"}],"join":{"session":{"limit":-1}}}]',
		'["findMany",{"model":"user","where":[{"field":"id","value":"absent"}],"sortBy":{"field":"unknown"}}]',
	] {
		mut rejected := false
		auth.with_internal(fn [query] (mut context EndpointContext) !string {
			return context.invoke_internal('adapterQuery', query)
		}) or { rejected = true }
		assert rejected
	}
}

fn test_adapter_projection_keeps_join_identity_private_and_scopes_related_rows() ! {
	mut auth :=
		new(Config{ secret: 'adapter-query-test-secret-with-at-least-32-bytes' }, MemoryStorage{})!
	defer { auth.close() or {} }
	for query in [
		'["create",{"model":"user","forceAllowId":true,"data":{"id":"a","name":"Owner","email":"a@example.com","createdAt":"2020-01-01T03:00:00.000+03:00"}}]',
		'["create",{"model":"user","forceAllowId":true,"data":{"id":"b","name":"Other","email":"b@example.com"}}]',
		'["create",{"model":"session","data":{"userId":"a","token":"owner-token","expiresAt":"2030-01-01T00:00:00.000Z"}}]',
		'["create",{"model":"session","data":{"userId":"b","token":"other-token","expiresAt":"2030-01-01T00:00:00.000Z"}}]',
	] {
		auth.with_internal(fn [query] (mut context EndpointContext) !string {
			return context.invoke_internal('adapterQuery', query)
		})!
	}
	encoded := auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery',
			'["findOne",{"model":"user","where":[{"field":"id","value":"a"}],"select":["email"],"join":{"session":true}}]')
	})!
	row := json2.decode[map[string]json2.Any](encoded)!
	assert 'id' !in row && 'name' !in row
	assert row['email']!.str() == 'a@example.com'
	sessions := row['session']!.as_array()
	assert sessions.len == 1
	assert sessions[0].as_map()['token']!.str() == 'owner-token'
	unchanged := auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery',
			'["findOne",{"model":"user","where":[{"field":"id","value":"a"}]}]')
	})!
	assert json2.decode[map[string]json2.Any](unchanged)!['name']!.str() == 'Owner'
	by_date := auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery',
			'["findMany",{"model":"user","where":[{"field":"createdAt","value":"2020-01-01T00:00:00.000Z"}]}]')
	})!
	assert json2.decode[[]json2.Any](by_date)!.len == 1
}

fn test_token_lookup_and_user_join_do_not_decrypt_unrelated_sessions() ! {
	mut storage := MemoryStorage{}
	storage.create_user(User{ id: 'other', email: 'other@example.com', name: 'Other' })!
	storage.create_session(Session{
		id:              'unreadable'
		user_id:         'other'
		encrypted_token: 'retired-secret-row'
	}, digest('unreadable-token'))!
	mut auth := new(Config{ secret: 'adapter-query-test-secret-with-at-least-32-bytes' }, storage)!
	defer { auth.close() or {} }
	for query in [
		'["create",{"model":"user","forceAllowId":true,"data":{"id":"current","name":"Current","email":"current@example.com"}}]',
		'["create",{"model":"session","data":{"userId":"current","token":"current-token","expiresAt":"2030-01-01T00:00:00.000Z"}}]',
	] {
		auth.with_internal(fn [query] (mut context EndpointContext) !string {
			return context.invoke_internal('adapterQuery', query)
		})!
	}
	for query in [
		'["findOne",{"model":"session","where":[{"field":"token","value":"current-token"}],"join":{"user":true}}]',
		'["findOne",{"model":"user","where":[{"field":"id","value":"current"}],"join":{"session":true}}]',
	] {
		result := auth.with_internal(fn [query] (mut context EndpointContext) !string {
			return context.invoke_internal('adapterQuery', query)
		})!
		assert result.contains('current-token')
		assert !result.contains('unreadable-token')
	}
}
