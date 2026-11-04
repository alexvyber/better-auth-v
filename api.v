module better_auth

import json
import x.json2

fn (mut a Auth) invoke(method string, path string, body string, ctx RequestContext) !Response {
	origin := if a.config.base_url == '' && ctx.origin != '' { ctx.origin } else { a.base_url() }
	r := a.call(Request{
		method:  method
		url:     origin.trim_right('/') + a.config.base_path + path
		headers: ctx.headers
		body:    body
	})
	if r.status >= 400 {
		fields := json.decode(map[string]string, r.body)!
		return fail(r.status, fields['code'], fields['message'])
	}
	return r
}

pub fn (mut a Auth) sign_up_email(input SignUpInput, ctx RequestContext) !AuthResult {
	for key, _ in input.additional_fields {
		if key !in a.config.user_fields || key in sign_up_reserved_fields {
			return fail(400, 'FIELD_NOT_ALLOWED', '${key} is not an additional user field')
		}
	}
	r := a.invoke('POST', '/sign-up/email', merge_fields(json.encode(input),
		input.additional_fields), ctx)!
	return decode_auth_result(r.body)!
}

pub fn (mut a Auth) sign_in_email(input SignInInput, ctx RequestContext) !AuthResult {
	r := a.invoke('POST', '/sign-in/email', json.encode(input), ctx)!
	return decode_auth_result(r.body)!
}

pub fn (mut a Auth) get_session(ctx RequestContext) !Lookup[SessionResult] {
	r := a.invoke('GET', '/get-session', '', ctx)!
	if r.body == 'null' { return Lookup[SessionResult]{} }
	return Lookup[SessionResult]{
		value: decode_session_result(r.body)!
	}
}

pub fn (mut a Auth) sign_out(ctx RequestContext) ! {
	a.invoke('POST', '/sign-out', '{}', ctx)!
}

pub fn (mut a Auth) list_sessions(ctx RequestContext) ![]Session {
	r := a.invoke('GET', '/list-sessions', '', ctx)!
	values := json2.decode[[]json2.Any](r.body)!
	mut sessions := []Session{}
	for value in values {
		sessions << decode_session(value.json_str())!
	}
	return sessions
}

pub fn (mut a Auth) update_session(fields map[string]json2.Any, ctx RequestContext) !Session {
	r := a.invoke('POST', '/update-session', json2.Any(fields).json_str(), ctx)!
	result := json2.decode[map[string]json2.Any](r.body)!
	return decode_session((result['session'] or { return error('missing session') }).json_str())
}

pub fn (mut a Auth) revoke_session(token string, ctx RequestContext) ! {
	a.invoke('POST', '/revoke-session', json.encode({
		'token': token
	}), ctx)!
}

pub fn (mut a Auth) revoke_sessions(ctx RequestContext) ! {
	a.invoke('POST', '/revoke-sessions', '{}', ctx)!
}

pub fn (mut a Auth) revoke_other_sessions(ctx RequestContext) ! {
	a.invoke('POST', '/revoke-other-sessions', '{}', ctx)!
}

pub struct ChangePasswordInput {
pub:
	current_password      string @[json: 'currentPassword']
	new_password          string @[json: 'newPassword']
	revoke_other_sessions bool   @[json: 'revokeOtherSessions']
}

pub fn (mut a Auth) change_password(input ChangePasswordInput, ctx RequestContext) ! {
	a.invoke('POST', '/change-password', json.encode(input), ctx)!
}

pub fn (mut a Auth) request_password_reset(email string, redirect_to string) ! {
	a.invoke('POST', '/request-password-reset', json.encode({
		'email':      email
		'redirectTo': redirect_to
	}), RequestContext{})!
}

pub fn (mut a Auth) reset_password(token string, new_password string) ! {
	a.invoke('POST', '/reset-password', json.encode({
		'token':       token
		'newPassword': new_password
	}), RequestContext{})!
}

pub fn (mut a Auth) verify_password(password string, ctx RequestContext) !bool {
	a.invoke('POST', '/verify-password', json.encode({
		'password': password
	}), ctx)!
	return true
}

pub fn (mut a Auth) generate_one_time_token(ctx RequestContext) !string {
	response := a.invoke('GET', '/one-time-token/generate', '', ctx)!
	fields := json.decode(map[string]string, response.body)!
	return fields['token']
}

pub fn (mut a Auth) verify_one_time_token(token string, ctx RequestContext) !SessionResult {
	response := a.invoke('POST', '/one-time-token/verify', json.encode({
		'token': token
	}), ctx)!
	return decode_session_result(response.body)
}
