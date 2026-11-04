module better_auth

import crypto.hmac
import crypto.sha256
import net.urllib
import time
import x.json2

pub fn sign_hmac_jwt(payload_json string, secret string, expires_in i64, now i64) !string {
	mut payload := json2.decode[map[string]json2.Any](payload_json)!
	payload['iat'] = now
	payload['exp'] = now + expires_in
	input := base64url('{"alg":"HS256"}'.bytes()) + '.' +
		base64url(js_json(json2.Any(payload)).bytes())
	return input + '.' +
		base64url(hmac.new(secret.bytes(), input.bytes(), sha256.sum, sha256.block_size))
}

pub fn verify_hmac_jwt(token string, secret string, now i64) !string {
	parts := token.split('.')
	if parts.len != 3 { return fail(401, 'INVALID_TOKEN', 'Invalid token') }
	header := json2.decode[map[string]json2.Any](decode_base64url(parts[0])!.bytestr())!
	if (header['alg'] or { json2.Any('') }).str() != 'HS256' || 'crit' in header {
		return fail(401, 'INVALID_TOKEN', 'Invalid token')
	}
	actual := decode_base64url(parts[2])!
	expected := hmac.new(secret.bytes(), (parts[0] + '.' + parts[1]).bytes(), sha256.sum,
		sha256.block_size)
	if !hmac.equal(actual, expected) { return fail(401, 'INVALID_TOKEN', 'Invalid token') }
	payload := decode_base64url(parts[1])!.bytestr()
	claims := json2.decode[map[string]json2.Any](payload)!
	if 'exp' in claims && numeric_field(claims, 'exp')! <= now {
		return fail(401, 'TOKEN_EXPIRED', 'Token expired')
	}
	if 'nbf' in claims && numeric_field(claims, 'nbf')! > now {
		return fail(401, 'INVALID_TOKEN', 'Invalid token')
	}
	return payload
}

fn (a &Auth) can_send_verification() bool {
	return a.config.verification_delivery_enabled or { a.config.send_email != discard_email }
}

fn (a &Auth) verification_token(email string, update_to string, request_type string) !string {
	mut fields := {
		'email': json2.Any(email.to_lower())
	}
	if update_to != '' { fields['updateTo'] = update_to.to_lower() }
	if request_type != '' { fields['requestType'] = request_type }
	return sign_hmac_jwt(json2.Any(fields).json_str(), a.config.secret,
		a.config.verification_expires_in, a.config.clock())
}

fn (a &Auth) verification_message(user User, callback string, target string, request_type string) !EmailMessage {
	token := a.verification_token(user.email, target, request_type)!
	mut delivered_user := user
	if target != '' && request_type != 'change-email-confirmation' { delivered_user = User{
			...user
			email: target
		} }
	url := a.base_url().trim_right('/') + a.config.base_path + '/verify-email?token=' + token +
		'&callbackURL=' + urllib.query_escape(if callback == '' { '/' } else { callback })
	return EmailMessage{
		kind:      'verify-email'
		user:      delivered_user
		token:     token
		url:       url
		new_email: target
		request:   a.request_context.request
	}
}

fn (mut a Auth) send_verification(p Payload, ctx RequestContext) !Response {
	if !a.can_send_verification() {
		return fail(400, 'VERIFICATION_EMAIL_NOT_ENABLED', "Verification email isn't enabled")
	}
	email := normalize_email(p.email)!
	current := (a.current_session(ctx)!).value
	if session := current {
		if session.user.email.to_lower() != email {
			return fail(400, 'EMAIL_MISMATCH', 'Email mismatch')
		}
		if session.user.email_verified {
			return fail(400, 'EMAIL_ALREADY_VERIFIED', 'Email already verified')
		}
		a.config.send_email(a.verification_message(session.user, p.callback_url, '', '')!)!
	} else {
		start := time.sys_mono_now()
		defer {
			elapsed := i64(time.sys_mono_now() - start)
			remaining := i64(500 * time.millisecond) - elapsed
			if remaining > 0 { time.sleep(time.Duration(remaining)) }
		}
		if user := (a.find_user_by_email(email)!).value {
			if !user.email_verified {
				a.config.send_email(a.verification_message(user, p.callback_url, '', '')!)!
			}
		} else {
			a.verification_token(email, '', '')!
		}
	}
	return json_response({
		'status': true
	})
}

fn (a &Auth) verification_error(callback string, err IError) !Response {
	if callback != '' {
		code := if err is APIError { err.code } else { 'INVALID_TOKEN' }
		separator := if callback.contains('?') { '&' } else { '?' }
		return Response{
			status:  302
			headers: [Header{'location', callback + separator + 'error=' + code}]
		}
	}
	return err
}

fn verification_success(callback string, user_json string) Response {
	if callback != '' { return Response{
			status:  302
			headers: [Header{'location', callback}]
		} }
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"status":true,"user":' + user_json + '}'
	}
}

fn (mut a Auth) verify_email_request(req Request, ctx RequestContext) !Response {
	u := urllib.parse(req.url)!
	callback := u.query().get('callbackURL') or { '' }
	token := u.query().get('token') or { '' }
	mut email := ''
	mut target := ''
	mut request_type := ''
	if token.len == 64 && !token.contains('.') {
		// Keep pre-JWT native links readable until their original expiration.
		legacy := a.consume_token(token, 'verify-email') or {
			return a.verification_error(callback, err)
		}
		email = legacy.email
	} else {
		encoded := verify_hmac_jwt(token, a.config.secret, a.config.clock()) or {
			if err is APIError { return a.verification_error(callback, err) }
			return a.verification_error(callback, fail(401, 'INVALID_TOKEN', 'Invalid token'))
		}
		claims := json2.decode[map[string]json2.Any](encoded)!
		email = normalize_email((claims['email'] or { json2.Any('') }).str())!
		target = (claims['updateTo'] or { json2.Any('') }).str()
		request_type = (claims['requestType'] or { json2.Any('') }).str()
	}
	user := (a.find_user_by_email(email)!).value or {
		return a.verification_error(callback, fail(401, 'USER_NOT_FOUND', 'User not found'))
	}

	mut active := (a.current_session(ctx)!).value
	if target != '' {
		target = normalize_email(target)!
		if current := active {
			if current.user.id != user.id {
				return a.verification_error(callback, fail(401, 'INVALID_USER', 'Invalid user'))
			}
		}
		if request_type == 'change-email-confirmation' {
			if a.can_send_verification() {
				a.config.send_email(a.verification_message(user, callback, target,
					'change-email-verification')!)!
			}
			return verification_success(callback, 'null')
		}
		if request_type != 'change-email-verification' {
			return a.verification_error(callback, fail(401, 'INVALID_TOKEN', 'Invalid token'))
		}
		updated := a.update_user_record(User{
			...user
			email:          target
			email_verified: true
			updated_at:     stamp_millis(a.clock_millis())
		})!
		a.config.after_email_verification(updated, a.request_context)!
		if active == none { active = SessionResult{
				user:    updated
				session: a.make_session(user.id, ctx, true)!
			} }
		current := active or { return error('missing verified session') }
		return a.set_session_cookies(verification_success(callback, a.user_json(updated)), SessionResult{
			...current
			user: updated
		})
	}
	if user.email_verified { return verification_success(callback, 'null') }
	a.config.before_email_verification(user, a.request_context)!
	updated := a.update_user_record(User{
		...user
		email_verified: true
		updated_at:     stamp_millis(a.clock_millis())
	})!
	a.config.after_email_verification(updated, a.request_context)!
	mut result := verification_success(callback, 'null')
	if a.config.auto_sign_in_after_verification {
		if current := active {
			if current.user.id != user.id { active = none }
		}
		if active == none { active = SessionResult{
				user:    updated
				session: a.make_session(user.id, ctx, true)!
			} }
		current := active or { return error('missing verified session') }
		result = a.set_session_cookies(result, SessionResult{ ...current, user: updated })!
	}
	return result
}

fn (mut a Auth) change_email_request(p Payload, ctx RequestContext) !Response {
	if !a.config.change_email_enabled {
		return fail(400, 'CHANGE_EMAIL_DISABLED', 'Change email is disabled')
	}
	current := a.require_session(ctx, false)!
	target := normalize_email(p.new_email)!
	if target == current.user.email { return fail(400, 'EMAIL_IS_THE_SAME', 'Email is the same') }
	can_update := !current.user.email_verified && a.config.update_email_without_verification
	can_send := a.can_send_verification()
	can_confirm := can_send && current.user.email_verified
		&& a.config.send_change_email_confirmation != discard_email
	if !can_update && !can_send {
		return fail(400, 'VERIFICATION_EMAIL_NOT_ENABLED', "Verification email isn't enabled")
	}
	if (a.find_user_by_email(target)!).value != none {
		a.verification_token(current.user.email, target, '')!
		return json_response({
			'status': true
		})
	}
	if can_update {
		updated := a.update_user_record(User{
			...current.user
			email:      target
			updated_at: stamp_millis(a.clock_millis())
		})!
		if can_send {
			a.config.send_email(a.verification_message(updated, p.callback_url, '', '')!)!
		}
		return a.set_session_cookies(json_response({
			'status': true
		}), SessionResult{ ...current, user: updated })
	}
	if can_confirm {
		a.config.send_change_email_confirmation(a.verification_message(current.user,
			p.callback_url, target, 'change-email-confirmation')!)!
	} else {
		a.config.send_email(a.verification_message(current.user, p.callback_url, target,
			'change-email-verification')!)!
	}
	return json_response({
		'status': true
	})
}
