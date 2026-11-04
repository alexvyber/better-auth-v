module better_auth

import json
import x.json2

pub struct AnonymousOptions {
pub:
	email_domain_name             string @[json: emailDomainName]
	disable_delete_anonymous_user bool   @[json: disableDeleteAnonymousUser]
	generate_name                 fn (mut EndpointContext) !string                         = default_anonymous_name                         @[skip]
	generate_email                fn () !string                                            = default_anonymous_email                                            @[skip]
	on_link_account               fn (mut EndpointContext, SessionResult, SessionResult) ! = discard_anonymous_link @[skip]
}

fn default_anonymous_name(mut _ EndpointContext) !string {
	return 'Anonymous'
}

fn default_anonymous_email() !string {
	return ''
}

fn discard_anonymous_link(mut _ EndpointContext, _ SessionResult, _ SessionResult) ! {}

pub struct AnonymousPlugin {
pub:
	options AnonymousOptions
}

pub fn (_ AnonymousPlugin) id() string {
	return 'anonymous'
}

pub fn (_ AnonymousPlugin) schema() PluginFields {
	return PluginFields{
		user: {
			'isAnonymous': AdditionalField{
				field_type:    'boolean'
				input:         false
				default_value: json2.Any(false)
			}
		}
	}
}

pub fn (_ AnonymousPlugin) endpoints() []Endpoint {
	return [Endpoint{ path: '/sign-in/anonymous', handler: sign_in_anonymous },
		Endpoint{
			path:            '/delete-anonymous-user'
			require_session: true
			handler:         delete_anonymous_user
		}]
}

fn (a &Auth) anonymous_options() !AnonymousOptions {
	for plugin in a.config.plugins {
		if plugin is AnonymousPlugin { return plugin.options }
	}
	return error('anonymous plugin is not configured')
}

fn is_anonymous(user User) bool {
	return (user.additional_fields['isAnonymous'] or { json2.Any(false) }).bool()
}

fn sign_in_anonymous(mut context EndpointContext, _ Request) !Response {
	options := context.auth.anonymous_options()!
	if current := (context.auth.current_session(context.auth.request_context)!).value {
		if is_anonymous(current.user) {
			return fail(400, 'ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY',
				'Anonymous users cannot sign in again anonymously')
		}
	}
	custom := options.generate_email()!
	mut email := custom
	if email == '' {
		id := generate_auth_id(32)!
		email = if options.email_domain_name != '' {
			'temp-' + id + '@' + options.email_domain_name
		} else {
			id + '@anonymous.placeholder.invalid'
		}
	} else {
		normalize_email(email) or {
			return fail(400, 'INVALID_EMAIL_FORMAT', 'Email was not generated in a valid format')
		}
		if email != email.trim_space() {
			return fail(400, 'INVALID_EMAIL_FORMAT', 'Email was not generated in a valid format')
		}
	}
	generated_name := options.generate_name(mut context)!
	now := stamp_millis(context.auth.clock_millis())
	mut additional := context.auth.parse_user_fields(map[string]json2.Any{},
		map[string]json2.Any{}, true)!
	additional['isAnonymous'] = true
	proposed := User{
		id:                context.auth.new_id('user')!
		email:             email
		name:              if generated_name == '' { 'Anonymous' } else { generated_name }
		additional_fields: additional
		created_at:        now
		updated_at:        now
	}
	decision :=
		context.auth.config.validate_user_info(proposed, UserInfoSource{ method: 'anonymous' })!
	if decision.error != '' { return fail(403, decision.error, if decision.error_description != '' {
			decision.error_description
		} else {
			decision.error
		})
	 }
	user := context.auth.persist_user(proposed)!
	session := context.auth.make_session(user.id, context.auth.request_context, true)!
	return context.auth.set_session_cookies(Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"token":${json.encode(session.token)},"user":${context.auth.user_json(user)}}'
	}, SessionResult{
		user:    user
		session: session
	})
}

fn delete_anonymous_user(mut context EndpointContext, _ Request) !Response {
	options := context.auth.anonymous_options()!
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	if options.disable_delete_anonymous_user {
		return fail(400, 'DELETE_ANONYMOUS_USER_DISABLED', 'Deleting anonymous users is disabled')
	}
	if !is_anonymous(current.user) {
		return fail(403, 'USER_IS_NOT_ANONYMOUS', 'User is not anonymous')
	}
	context.auth.remove_user_sessions(current.user.id, '') or {
		return fail(500, 'FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS',
			'Failed to delete anonymous user sessions')
	}
	context.auth.remove_user(current.user.id) or {
		return fail(500, 'FAILED_TO_DELETE_ANONYMOUS_USER', 'Failed to delete anonymous user')
	}
	return context.auth.clear_cookie(json_response({
		'success': true
	}))
}

fn anonymous_link_path(path string) bool {
	for prefix in ['/sign-in', '/sign-up', '/callback', '/magic-link/verify',
		'/email-otp/verify-email', '/one-tap/callback', '/passkey/verify-authentication',
		'/phone-number/verify', '/verify-email'] {
		if path.starts_with(prefix) { return true }
	}
	return false
}

fn (mut a Auth) anonymous_before_request(path string) ! {
	a.anonymous_link_session = none
	a.anonymous_options() or { return }
	if !anonymous_link_path(path) { return }
	if current := (a.current_session(a.request_context)!).value {
		if is_anonymous(current.user) { a.anonymous_link_session = current }
	}
}

fn (mut a Auth) anonymous_after_response(path string, response Response) ! {
	options := a.anonymous_options() or { return }
	if !anonymous_link_path(path) || response.status >= 400 { return }
	previous := a.anonymous_link_session or { return }
	next := a.new_session or { return }
	mut context := EndpointContext{
		auth:    a
		session: next
	}
	options.on_link_account(mut context, previous, next)!
	if options.disable_delete_anonymous_user || previous.user.id == next.user.id
		|| is_anonymous(next.user) {
		return
	}
	a.remove_user(previous.user.id) or {
		a.config.log('error', 'Failed to clean up anonymous user during post-link cleanup')
	}
}

fn (mut a Auth) restore_anonymous_oauth_source(user_id string) ! {
	if a.anonymous_link_session != none || user_id == '' { return }
	a.anonymous_options() or { return }
	user := (a.storage.user(user_id)!).value or { return }
	if !is_anonymous(user) { return }
	for session in a.user_sessions(user_id)! {
		if epoch_millis(session.expires_at)! >= a.clock_millis() {
			a.anonymous_link_session = SessionResult{
				user:    user
				session: session
			}
			return
		}
	}
}
