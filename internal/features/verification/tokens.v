module better_auth

import net.urllib

fn (mut a Auth) issue_email(kind string, user User, callback string) ! {
	if kind == 'verify-email' {
		if a.email_otp_verification_override() {
			a.send_email_otp_verification(user)!
			return
		}
		if !a.can_send_verification() { return }
		a.config.send_email(a.verification_message(user, callback, '', '')!)!
		return
	}
	token := if kind == 'reset-password' { generate_auth_id(24)! } else { random_token()! }
	a.persist_opaque_verification(token, Verification{
		id:                digest(token)
		identifier:        kind
		value:             user.id
		expires_at:        a.config.clock() +
			if kind == 'reset-password' { a.config.password_reset_expires_in } else { a.config.verification_expires_in }
		expires_at_millis: a.clock_millis() +
			1000 * if kind == 'reset-password' { a.config.password_reset_expires_in } else { a.config.verification_expires_in }
	})!
	path := if kind == 'reset-password' {
		'/reset-password/' + token
	} else {
		'/verify-email?token=' + token
	}
	mut url := a.base_url().trim_right('/') + a.config.base_path + path
	if callback != '' {
		a.check_redirect(callback, 'callbackURL')!
		url += if url.contains('?') { '&' } else { '?' }
		url += 'callbackURL=' + urllib.query_escape(callback)
	}
	a.config.send_email(EmailMessage{
		kind:    kind
		user:    user
		token:   token
		url:     url
		request: a.operation.request.request
	})!
}

fn (mut a Auth) token_user(token string, kind string) !User {
	if token == '' || token.len > 4096 { return fail(400, 'INVALID_TOKEN', 'Invalid token') }
	record := (a.find_opaque_verification(token, kind)!).value or {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}

	if record.identifier != kind || verification_expiry_millis(record) < a.clock_millis() {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}
	user := (a.storage.user(record.value)!).value or {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}

	return user
}

fn (mut a Auth) consume_token(token string, kind string) !User {
	user := a.token_user(token, kind)!
	consumed := (a.consume_opaque_verification(token, kind)!).value or {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}

	if consumed.value != user.id || verification_expiry_millis(consumed) < a.clock_millis() {
		return fail(400, 'INVALID_TOKEN', 'Invalid token')
	}
	return user
}

// An omitted base URL is resolved only for the current request. Direct server
// calls without a request keep it unresolved, as in the pinned upstream API.
