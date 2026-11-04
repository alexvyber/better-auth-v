module better_auth

import json
import x.json2

fn email_otp_send(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	if options.send_otp == no_email_otp_sender {
		return fail(400, 'BAD_REQUEST', 'send email verification is not implemented')
	}
	fields := email_otp_body(request)!
	email := email_otp_email(fields, 'email', true)!
	kind := email_otp_kind(fields)!
	if kind == 'change-email' { return fail(400, 'BAD_REQUEST', 'Invalid OTP type') }
	otp := context.resolve_email_otp(options, email, kind)!
	if (context.auth.storage.user_by_email(email)!).value == none && !(kind == 'sign-in'
		&& !options.disable_sign_up) {
		context.delete_verification_by_identifier(email_otp_identifier(kind, email))!
		return json_response({
			'success': true
		})
	}
	options.send_otp(mut context, EmailOTPMessage{ email: email, otp: otp, kind: kind })!
	return json_response({
		'success': true
	})
}

fn email_otp_check(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	fields := email_otp_body(request)!
	email := email_otp_email(fields, 'email', true)!
	otp := email_otp_string(fields, 'otp')!
	identifier := email_otp_identifier(email_otp_kind(fields)!, email)
	record := (context.find_verification_value(identifier)!).value or {
		return fail(400, 'INVALID_OTP', 'Invalid OTP')
	}

	if verification_expiry_millis(record) < context.auth.clock_millis() {
		context.delete_verification_by_identifier(identifier)!
		context.commit_email_otp_gate()!
		return fail(400, 'OTP_EXPIRED', 'OTP expired')
	}
	stored, attempts := split_email_otp(record.value)
	if f64(attempts) >= email_otp_limit(options) {
		context.delete_verification_by_identifier(identifier)!
		context.commit_email_otp_gate()!
		return fail(403, 'TOO_MANY_ATTEMPTS', 'Too many attempts')
	}
	if !context.matches_email_otp(options, stored, otp)! {
		context.update_verification_by_identifier(identifier, json.encode({
			'value': stored + ':' + (attempts + 1).str()
		}))!
		context.commit_email_otp_gate()!
		return fail(400, 'INVALID_OTP', 'Invalid OTP')
	}
	if (context.auth.storage.user_by_email(email)!).value == none {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}
	return json_response({
		'success': true
	})
}

fn email_otp_verify_email(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	fields := email_otp_body(request)!
	email := email_otp_email(fields, 'email', true)!
	context.verify_email_otp_atomic(options, email_otp_identifier('email-verification', email), email_otp_string(fields,
		'otp')!, true)!
	user := (context.auth.storage.user_by_email(email)!).value or {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}

	context.auth.config.before_email_verification(user, context.auth.request_context)!
	updated := context.auth.update_user_record(User{
		...user
		email:          email
		email_verified: true
		updated_at:     stamp_millis(context.auth.clock_millis())
	})!
	context.auth.config.after_email_verification(updated, context.auth.request_context)!
	if context.auth.config.auto_sign_in_after_verification {
		session := context.auth.make_session(user.id, context.auth.request_context, true)!
		return context.auth.set_session_cookies(Response{
			headers: [Header{'content-type', 'application/json'}]
			body:    '{"status":true,"token":${json.encode(session.token)},"user":${context.auth.user_json(updated)}}'
		}, SessionResult{
			session: session
			user:    updated
		})
	}
	mut response := Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"status":true,"token":null,"user":${context.auth.user_json(updated)}}'
	}
	if current := (context.auth.current_session(context.auth.request_context)!).value {
		if current.user.id == updated.id { response = context.auth.set_cache_cookie(response, SessionResult{
				...current
				user: updated
			})! }
	}
	return response
}

fn email_otp_sign_in(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	fields := email_otp_body(request)!
	email := email_otp_email(fields, 'email', false)!
	context.verify_email_otp_atomic(options, email_otp_identifier('sign-in', email), email_otp_string(fields,
		'otp')!, true)!
	mut user := User{}
	if existing := (context.auth.storage.user_by_email(email)!).value {
		user = existing
		if !user.email_verified {
			user = (context.revoke_unproven_account_access(user.id)!).value or {
				return fail(400, 'INVALID_OTP', 'Invalid OTP')
			}
		}
	} else {
		if options.disable_sign_up { return fail(400, 'INVALID_OTP', 'Invalid OTP') }
		mut input := fields.clone()
		for reserved in ['email', 'otp', 'name', 'image'] {
			input.delete(reserved)
		}
		for name, field in context.auth.config.user_fields {
			if !field.input { input.delete(name) }
		}
		additional := context.auth.parse_user_fields(input, map[string]json2.Any{}, true)!
		now := stamp_millis(context.auth.clock_millis())
		name := if 'name' in fields { email_otp_string(fields, 'name')! } else { '' }
		image := if 'image' in fields { ?string(email_otp_string(fields, 'image')!) } else { none }
		proposed := User{
			id:                context.auth.new_id('user')!
			email:             email
			email_verified:    true
			name:              name
			image:             image
			additional_fields: additional
			created_at:        now
			updated_at:        now
		}
		decision := context.auth.config.validate_user_info(proposed, UserInfoSource{
			method: 'email-otp'
		})!
		if decision.error != '' { return fail(403, decision.error, if decision.error_description != '' {
				decision.error_description
			} else {
				decision.error
			})
		 }
		user = context.auth.persist_user(proposed)!
	}
	session := context.auth.make_session(user.id, context.auth.request_context, true)!
	return context.auth.set_session_cookies(Response{
		headers: [
			Header{'content-type', 'application/json'},
		]
		body:    '{"token":${json.encode(session.token)},"user":${context.auth.user_json(user)}}'
	}, SessionResult{
		session: session
		user:    user
	})
}

fn email_otp_request_reset(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	fields := email_otp_body(request)!
	email := email_otp_email(fields, 'email', false)!
	otp := context.resolve_email_otp(options, email, 'forget-password')!
	if (context.auth.storage.user_by_email(email)!).value == none {
		context.delete_verification_by_identifier(email_otp_identifier('forget-password', email))!
		return json_response({
			'success': true
		})
	}
	options.send_otp(mut context, EmailOTPMessage{ email: email, otp: otp, kind: 'forget-password' })!
	return json_response({
		'success': true
	})
}

fn email_otp_reset_password(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	fields := email_otp_body(request)!
	email := email_otp_email(fields, 'email', false)!
	otp := email_otp_string(fields, 'otp')!
	password := email_otp_string(fields, 'password')!
	context.auth.check_password(password)!
	identifier := email_otp_identifier('forget-password', email)
	mut usable := false
	if record := (context.find_verification_value(identifier)!).value {
		stored, attempts := split_email_otp(record.value)
		if verification_expiry_millis(record) >= context.auth.clock_millis()
			&& f64(attempts) < email_otp_limit(options) {
			usable = context.matches_email_otp(options, stored, otp)!
		}
	}
	if !usable { context.verify_email_otp_atomic(options, identifier, otp, true)! }
	user := (context.auth.storage.user_by_email(email)!).value or {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}

	hash := context.auth.config.password_hasher.hash(password)!
	if usable { context.verify_email_otp_atomic(options, identifier, otp, false)! }
	if (context.auth.storage.account(user.id, 'credential')!).value != none {
		context.auth.update_password(user.id, hash)!
	} else {
		context.auth.persist_account(Account{
			id:          context.auth.new_id('account')!
			user_id:     user.id
			provider_id: 'credential'
			account_id:  user.id
			password:    hash
			created_at:  stamp_millis(context.auth.clock_millis())
			updated_at:  stamp_millis(context.auth.clock_millis())
		})!
	}
	if context.auth.config.revoke_sessions_on_password_reset {
		context.auth.remove_user_sessions(user.id, '')!
	}
	context.auth.commit_transaction()!
	context.auth.config.on_password_reset(user)!
	context.auth.begin_transaction(false)!
	if !user.email_verified { context.auth.update_user_record(User{
			...user
			email_verified: true
			updated_at:     stamp_millis(context.auth.clock_millis())
		})! }
	return json_response({
		'success': true
	})
}

fn email_otp_request_change(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	if !options.change_email.enabled {
		return fail(400, 'BAD_REQUEST', 'Change email with OTP is disabled')
	}
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	fields := email_otp_body(request)!
	email := current.user.email.to_lower()
	new_email := email_otp_email(fields, 'newEmail', true)!
	if new_email == email { return fail(400, 'BAD_REQUEST', 'Email is the same') }
	if options.change_email.verify_current_email {
		previous := if 'otp' in fields { email_otp_string(fields, 'otp')! } else { '' }
		if previous == '' {
			return fail(400, 'BAD_REQUEST', 'OTP is required to verify current email')
		}
		context.verify_email_otp_atomic(options, email_otp_identifier('email-verification', email),
			previous, true)!
	} else if 'otp' in fields {
		if email_otp_string(fields, 'otp')! != '' {
			context.auth.config.log('warn',
				'OTP provided but not required for verifying current email. If you want to require OTP verification for current email, please set the changeEmail.verifyCurrentEmail option to true in the configuration')
		}
	}
	otp := context.new_email_otp(options, new_email, 'change-email')!
	identifier := email_otp_identifier('change-email', '${email}-${new_email}')
	context.create_email_otp_record(options, identifier, otp)!
	if (context.auth.storage.user_by_email(new_email)!).value != none {
		context.delete_verification_by_identifier(identifier)!
		return json_response({
			'success': true
		})
	}
	options.send_otp(mut context, EmailOTPMessage{ email: new_email, otp: otp, kind: 'change-email' })!
	return json_response({
		'success': true
	})
}

fn email_otp_change(mut context EndpointContext, request Request) !Response {
	options := context.auth.email_otp_options()!
	if !options.change_email.enabled {
		return fail(400, 'BAD_REQUEST', 'Change email with OTP is disabled')
	}
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	fields := email_otp_body(request)!
	email := current.user.email.to_lower()
	new_email := email_otp_email(fields, 'newEmail', true)!
	if new_email == email { return fail(400, 'BAD_REQUEST', 'Email is the same') }
	context.verify_email_otp_atomic(options, email_otp_identifier('change-email',
		'${email}-${new_email}'), email_otp_string(fields, 'otp')!, true)!
	user := (context.auth.storage.user_by_email(email)!).value or {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}

	if (context.auth.storage.user_by_email(new_email)!).value != none {
		return fail(400, 'BAD_REQUEST', 'Email already in use')
	}
	context.auth.config.before_email_verification(user, context.auth.request_context)!
	updated := context.auth.update_user_record(User{
		...user
		email:          new_email
		email_verified: true
		updated_at:     stamp_millis(context.auth.clock_millis())
	})!
	context.auth.config.after_email_verification(updated, context.auth.request_context)!
	return context.auth.set_session_cookies(json_response({
		'success': true
	}), SessionResult{ session: current.session, user: updated })
}
