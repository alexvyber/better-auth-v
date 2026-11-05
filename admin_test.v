module better_auth

import x.json2

fn test_admin_permissions_require_a_single_sufficient_role_and_nonempty_actions() {
	options := AdminOptions{
		roles: {
			'editor':         {
				'user': ['update']
			}
			'moderator':      {
				'user': ['ban']
			}
			'platform-admin': {
				'user': ['update', 'ban']
			}
		}
	}
	multiple := User{
		additional_fields: {
			'role': json2.Any('editor,moderator')
		}
	}
	assert options.has_permission(multiple, {
		'user': ['update']
	})
	assert !options.has_permission(multiple, {
		'user': ['update', 'ban']
	})
	assert !options.has_permission(multiple, {
		'user': []string{}
	})
	assert !options.has_permission(multiple, {
		'unknown': ['read']
	})
	assert options.has_permission(User{
		additional_fields: {
			'role': json2.Any('platform-admin')
		}
	}, {
		'user': ['update', 'ban']
	})
}

fn test_admin_validates_explicit_role_configuration_and_protects_schema_inputs() ! {
	plugin := AdminPlugin{
		options: AdminOptions{
			admin_roles:      ['platform-admin']
			roles:            {
				'platform-admin': {
					'user': ['get']
				}
				'curator':        {
					'user': []string{}
				}
			}
			user_field_names: {
				'banReason': 'ban_reason'
			}
		}
	}
	plugin.validate()!
	assert plugin.schema().user['banReason'].field_name == 'ban_reason'
	assert !plugin.schema().user['role'].input
	assert !plugin.schema().session['impersonatedBy'].input
	invalid := AdminPlugin{
		options: AdminOptions{
			admin_roles: ['missing']
		}
	}
	if _ := invalid.validate() { assert false
	 }
}

struct AdminNativeHasher {}

fn (_ AdminNativeHasher) hash(password string) !string {
	return 'test:' + password
}

fn (_ AdminNativeHasher) verify(password string, hash string) !bool {
	return hash == 'test:' + password
}

fn test_admin_bans_apply_to_internal_session_creation_and_expired_bans_clear() ! {
	mut auth := new(Config{
		secret:          'native-admin-test-secret-at-least-32-bytes'
		password_hasher: AdminNativeHasher{}
		plugins:         [Plugin(AdminPlugin{})]
		rate_limit_max:  0
	}, open_memory())!
	defer { auth.close() or {} }
	encoded := auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('createUser',
			'[{"email":"banned@example.com","name":"Banned","banned":true,"banReason":"Policy"}]')
	})!
	id := decode_user(encoded)!.id
	auth.with_internal(fn [id] (mut context EndpointContext) !string {
		context.create_session(id, RequestContext{}, true)!
		return 'unexpected'
	}) or {
		assert err is APIError
		if err is APIError {
			assert err.code == 'BANNED_USER'
			assert err.status == 403
		}
	}
	assert (auth.with_internal(fn [id] (mut context EndpointContext) !string {
		return context.invoke_internal('listSessions', '["' + id + '"]')
	})!) == '[]'
	auth.with_internal(fn [id] (mut context EndpointContext) !string {
		context.invoke_internal('updateUser', '["' + id +
			'",{"banExpires":"2000-01-01T00:00:00.000Z"}]')!
		context.create_session(id, RequestContext{}, true)!
		user := (context.user(id)!).value or { return error('missing user') }
		assert !(user.additional_fields['banned'] or { return error('missing banned flag') }).bool()
		assert (user.additional_fields['banReason'] or { return error('missing ban reason') }) is json2.Null
		assert (user.additional_fields['banExpires'] or { return error('missing ban expiry') }) is json2.Null
		return 'ok'
	})!
}
