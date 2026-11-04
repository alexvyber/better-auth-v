module better_auth

import crypto.rand
import json
import net.urllib

fn deletion_token() !string {
	alphabet := '0123456789abcdefghijklmnopqrstuvwxyz'
	mut result := []u8{cap: 32}
	for result.len < 32 {
		for value in rand.bytes(32)! {
			if value < 252 { result << alphabet[int(value) % 36] }
			if result.len == 32 { break
			 }
		}
	}
	return result.bytestr()
}

fn (mut a Auth) finish_user_deletion(current SessionResult, ctx RequestContext) !Response {
	a.config.before_delete(current.user, ctx)!
	a.remove_user(current.user.id)!
	// Deletion is durable before the after callback, as in the upstream route.
	a.commit_transaction()!
	a.config.after_delete(current.user, ctx)!
	return a.clear_cookie(Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"success":true,"message":"User deleted"}'
	})
}

fn (mut a Auth) delete_user_callback(p Payload, ctx RequestContext) !Response {
	if !a.config.delete_user_enabled { return fail(404, 'NOT_FOUND', 'Not found') }
	current := a.require_session(ctx, false) or {
		return fail(404, 'FAILED_TO_GET_USER_INFO', 'Failed to get user info')
	}
	if p.callback_url != '' { a.check_redirect(p.callback_url, 'callbackURL')! }
	consumed := a.consume_opaque_verification(p.token, 'delete-account-' + p.token)!
	// Persist missing/expired consumption too, before ownership or callback checks.
	a.commit_transaction()!
	a.begin_transaction(false)!
	verification := consumed.value or { return fail(404, 'INVALID_TOKEN', 'Invalid token') }
	if verification.identifier != 'delete-account-' + p.token {
		return fail(404, 'INVALID_TOKEN', 'Invalid token')
	}
	// A wrong-owner or expired token remains consumed after this response commits.
	if verification.value != current.user.id
		|| verification_expiry_millis(verification) < a.clock_millis() {
		return error_response(fail(404, 'INVALID_TOKEN', 'Invalid token'))
	}
	result := a.finish_user_deletion(current, ctx)!
	if p.callback_url != '' {
		return with_header(Response{ ...result, status: 302 }, 'location', p.callback_url)
	}
	return result
}

fn (mut a Auth) delete_user_request(p Payload, ctx RequestContext) !Response {
	current := a.require_session(ctx, false)!
	if !a.config.delete_user_enabled { return fail(404, 'NOT_FOUND', 'Not found') }
	if p.password != '' {
		a.check_password_max(p.password)!
		account := (a.storage.account(current.user.id, 'credential')!).value or {
			return fail(400, 'CREDENTIAL_ACCOUNT_NOT_FOUND', 'Credential account not found')
		}

		if account.password == '' {
			return fail(400, 'CREDENTIAL_ACCOUNT_NOT_FOUND', 'Credential account not found')
		}
		if !a.config.password_hasher.verify(p.password, account.password)! {
			return fail(400, 'INVALID_PASSWORD', 'Invalid password')
		}
	}
	if p.token != '' { return a.delete_user_callback(Payload{ token: p.token }, ctx)! }
	if a.config.send_delete_verification != discard_email {
		if p.callback_url != '' { a.check_redirect(p.callback_url, 'callbackURL')! }
		token := deletion_token()!
		ttl := if a.config.delete_token_expires_in == 0 {
			i64(86400)
		} else {
			a.config.delete_token_expires_in
		}
		a.persist_opaque_verification(token, Verification{
			id:                digest(token)
			identifier:        'delete-account-' + token
			value:             current.user.id
			expires_at:        a.config.clock() + ttl
			expires_at_millis: a.clock_millis() + ttl * 1000
		})!
		url := a.base_url().trim_right('/') + a.config.base_path + '/delete-user/callback?token=' +
			token + '&callbackURL=' +
			urllib.query_escape(if p.callback_url == '' { '/' } else { p.callback_url })
		a.config.send_delete_verification(EmailMessage{
			kind:    'delete-account'
			user:    current.user
			token:   token
			url:     url
			request: ctx.request
		})!
		return Response{
			headers: [Header{'content-type', 'application/json'}]
			body:    '{"success":true,"message":"Verification email sent"}'
		}
	}
	if p.password == '' && a.config.session_fresh_age != 0
		&& a.clock_millis() - epoch_millis(current.session.created_at)! >= a.config.session_fresh_age * 1000 {
		return fail(400, 'SESSION_EXPIRED', 'Session expired')
	}
	return a.finish_user_deletion(current, ctx)
}

// Trusted server-only operation. No HTTP route is registered for this API.
pub fn (mut c EndpointContext) set_password(password string, ctx RequestContext) ! {
	current := c.auth.require_session(ctx, false)!
	c.auth.check_password(password)!
	hash := c.auth.config.password_hasher.hash(password)!
	if account := (c.auth.storage.account(current.user.id, 'credential')!).value {
		if account.password != '' {
			return fail(400, 'PASSWORD_ALREADY_SET', 'User already has a password')
		}
		c.auth.update_account_record(account, '{"password":${json.encode(hash)}}')!
	} else {
		c.auth.persist_account(Account{
			id:          c.auth.new_id('account')!
			user_id:     current.user.id
			provider_id: 'credential'
			account_id:  current.user.id
			password:    hash
		})!
	}
}
