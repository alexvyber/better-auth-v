module better_auth

import net.urllib
import x.json2

fn admin_impersonate(mut context EndpointContext, actor SessionResult, fields map[string]json2.Any, options AdminOptions) !Response {
	context.admin_require(actor.user, 'user', 'impersonate',
		'YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS', 'You are not allowed to impersonate users')!
	target := context.admin_user((fields['userId'] or { json2.Any('') }).str())!
	admin_roles := (options.admin_roles or { ['admin'] }).map(it.trim_space())
	roles :=
		(target.additional_fields['role'] or { json2.Any(options.default_role) }).str().split(',')
	is_admin := roles.any(it in admin_roles) || target.id in options.admin_user_ids
	if is_admin && !options.allow_impersonating_admins && !options.has_permission(actor.user, {
		'user': ['impersonate-admins']
	}) {
		return fail(403, 'YOU_CANNOT_IMPERSONATE_ADMINS', 'You cannot impersonate admins')
	}
	duration := if options.impersonation_session_duration == 0 {
		f64(3600)
	} else {
		options.impersonation_session_duration
	}
	expires := stamp_millis(i64(f64(context.auth.clock_millis()) + duration * 1000))
	session := context.auth.make_session_overridden(target.id, context.auth.request_context, false, {
		'impersonatedBy': json2.Any(actor.user.id)
		'expiresAt':      json2.Any(expires)
	}, true)!
	marker := (context.auth.verify_signed_value(cookie_values(context.auth.request_context)[context.auth.cookie_name_for('dont_remember')]) or {
		''
	})
	factory := context.auth.auth_cookie_factory()
	descriptor := factory.create_cookie('admin_session', {})
	attributes := factory.get_cookies()['sessionToken'].attributes
	value := urllib.query_escape(context.auth.sign_cookie(actor.session.token + ':' + marker))
	mut response := context.auth.clear_cookie(Response{
		headers: [
			Header{'content-type', 'application/json'},
		]
		body:    '{"session":' + context.auth.session_json(session) + ',"user":' +
			context.auth.user_json(target) + '}'
	})
	response = with_header(response, 'set-cookie', serialize_auth_cookie(descriptor.name, value,
		attributes))
	return context.auth.set_session_cookies(response, SessionResult{ session: session, user: target })
}

fn admin_stop_impersonating(mut context EndpointContext) !Response {
	current := (context.auth.current_session(context.auth.request_context)!).value or {
		return fail(401, 'UNAUTHORIZED', 'Unauthorized')
	}

	value := current.session.additional_fields['impersonatedBy'] or { json2.Any(json2.Null{}) }
	id := if js_truthy(value) { value.str() } else { '' }
	if id == '' { return fail(400, 'BAD_REQUEST', 'You are not impersonating anyone') }
	original_user := (context.auth.storage.user(id)!).value or {
		return fail(500, 'INTERNAL_SERVER_ERROR', 'Failed to find user')
	}

	factory := context.auth.auth_cookie_factory()
	descriptor := factory.create_cookie('admin_session', {})
	raw := cookie_values(context.auth.request_context)[descriptor.name]
	original := context.auth.verify_signed_value(raw) or {
		return fail(500, 'INTERNAL_SERVER_ERROR', 'Failed to find admin session')
	}
	token, marker := original.split_once(':') or {
		return fail(500, 'INTERNAL_SERVER_ERROR', 'Failed to find admin session')
	}
	previous := (context.auth.find_session_record(token)!).value or {
		return fail(500, 'INTERNAL_SERVER_ERROR', 'Failed to find admin session')
	}

	if previous.session.user_id != id
		|| epoch_millis(previous.session.expires_at)! <= context.auth.clock_millis() {
		return fail(500, 'INTERNAL_SERVER_ERROR', 'Failed to find admin session')
	}
	context.auth.remove_session(current.session.token)!
	restored := SessionResult{
		...previous
		user:    original_user
		session: Session{
			...previous.session
			persistent: marker == ''
		}
	}
	response := context.auth.set_session_cookies(Response{
		headers: [
			Header{'content-type', 'application/json'},
		]
		body:    '{"session":' + context.auth.session_json(restored.session) + ',"user":' +
			context.auth.user_json(restored.user) + '}'
	}, restored)!
	mut attributes := descriptor.attributes.clone()
	attributes['maxAge'] = 0
	return with_header(response, 'set-cookie', serialize_auth_cookie(descriptor.name, '',
		attributes))
}
