module better_auth

import x.json2
import net.urllib

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

struct AdminSessionHookLog {
mut:
	seen bool
}

struct AdminSessionHook {
	log &AdminSessionHookLog
}

fn (hook AdminSessionHook) run(mut _ EndpointContext, event DatabaseEvent) !HookResult {
	if event.model == 'session' && event.operation == 'create' && event.phase == 'before' {
		mut log := hook.log
		log.seen = true
		session := decode_session(event.data_json)!
		assert session.id != 'ignored-session-id'
		assert session.expires_at == '2025-01-01T00:15:00.000Z'
		assert (session.additional_fields['impersonatedBy'] or {
			return error('missing impersonation owner')
		}).str() == 'operator'
	}
	return HookResult{}
}

fn test_admin_impersonation_overrides_are_visible_to_creation_hooks_and_cannot_reuse_ids() ! {
	mut log := &AdminSessionHookLog{}
	mut auth := new(Config{
		secret:         'native-admin-test-secret-at-least-32-bytes'
		plugins:        [Plugin(AdminPlugin{})]
		clock_millis:   fn () i64 {
			return 1735689600000
		}
		database_hooks: [DatabaseHook(AdminSessionHook{
			log: log
		})]
	}, open_memory())!
	defer { auth.close() or {} }
	user := decode_user(auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('createUser',
			'[{"email":"target@example.com","name":"Target"}]')
	})!)!
	id := user.id
	encoded := auth.with_internal(fn [id] (mut context EndpointContext) !string {
		return context.invoke_internal('createSession', '["' + id +
			'",true,{"id":"ignored-session-id","expiresAt":"2025-01-01T00:15:00.000Z","impersonatedBy":"operator"},true]')
	})!
	assert log.seen
	session := decode_session(encoded)!
	assert session.id != 'ignored-session-id'
	assert !session.persistent
	assert session.user_id == user.id
}

struct AdminBannedOAuthProvider {}

fn (_ AdminBannedOAuthProvider) id() string {
	return 'google'
}

fn (_ AdminBannedOAuthProvider) authorization_url(state string, _ string, _ string) !string {
	return 'https://provider.example.com/authorize?state=' + state
}

fn (_ AdminBannedOAuthProvider) exchange(_ string, _ string, _ string) !OAuthIdentity {
	return OAuthIdentity{
		id:             'banned-subject'
		email:          'banned@example.com'
		email_verified: true
		name:           'Banned'
	}
}

fn test_admin_banned_oauth_rolls_back_binding_and_preserves_error_query_and_fragment() ! {
	mut auth := new(Config{
		secret:                    'native-admin-test-secret-at-least-32-bytes'
		plugins:                   [
			Plugin(AdminPlugin{
				options: AdminOptions{
					banned_user_message: 'Policy blocked'
				}
			}),
		]
		social_providers:          [OAuthProvider(AdminBannedOAuthProvider{})]
		account_linking_enabled:   true
		trusted_linking_providers: [
			'google',
		]
		trusted_origins:           ['https://frontend.example.com']
		rate_limit_max:            0
	}, open_memory())!
	defer { auth.close() or {} }
	user := decode_user(auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('createUser',
			'[{"email":"banned@example.com","name":"Banned","emailVerified":true,"banned":true}]')
	})!)!
	start := auth.handle(Request{
		method:  'POST'
		url:     'http://localhost:3000/api/auth/sign-in/social'
		headers: {
			'content-type': 'application/json'
		}
		body:    '{"provider":"google","errorCallbackURL":"https://frontend.example.com/error?from=login#details"}'
	})
	assert start.status == 200
	state := urllib.parse((json2.decode[map[string]json2.Any](start.body)!['url'] or {
		return error('missing authorization URL')
	}).str())!.query().get('state') or { return error('missing state') }
	cookies :=
		start.headers.filter(it.name == 'set-cookie').map(it.value.all_before(';')).join('; ')
	request := Request{
		url:     'http://localhost:3000/api/auth/callback/google?code=code&state=' + state
		headers: {
			'cookie': cookies
		}
	}
	response := auth.handle(request)
	assert response.status == 302
	location := response.headers.filter(it.name == 'location')[0].value
	url := urllib.parse(location)!
	assert url.fragment == 'details'
	assert (url.query().get('from') or { '' }) == 'login'
	assert (url.query().get('error') or { '' }) == 'BANNED_USER'
	assert (url.query().get('error_description') or { '' }) == 'Policy blocked'
	id := user.id
	assert auth.with_internal(fn [id] (mut context EndpointContext) !string {
		return context.invoke_internal('findAccounts', '["' + id + '"]')
	})! == '[]'
	assert auth.with_internal(fn [id] (mut context EndpointContext) !string {
		return context.invoke_internal('listSessions', '["' + id + '"]')
	})! == '[]'
	assert auth.handle(request).status == 400
}
