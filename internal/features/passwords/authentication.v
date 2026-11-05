module better_auth

import x.json2

fn normalize_email(value string) !string {
	email := value.trim_space().to_lower()
	parts := email.split('@')
	if email.len > 254 || parts.len != 2 || parts[0] == '' || parts[1] == ''
		|| !parts[1].contains('.') || email.contains_any(' \t\r\n\x00') {
		return fail(400, 'INVALID_EMAIL', 'Invalid email')
	}
	return email
}

fn (a &Auth) check_password(password string) ! {
	if utf16_length(password) < a.config.min_password_length {
		a.config.log('warn', 'Password is too short')
		return fail(400, 'PASSWORD_TOO_SHORT', 'Password too short')
	}
	a.check_password_max(password)!
}

fn utf16_length(value string) int {
	mut length := 0
	for codepoint in value.runes() {
		length += if u32(codepoint) > 0xffff { 2 } else { 1 }
	}
	return length
}

fn (a &Auth) check_password_max(password string) ! {
	if utf16_length(password) > a.config.max_password_length {
		a.config.log('warn', 'Password is too long')
		return fail(400, 'PASSWORD_TOO_LONG', 'Password too long')
	}
}

fn (mut a Auth) sign_up(input SignUpInput, ctx RequestContext) !AuthResult {
	if !a.config.email_and_password || a.config.disable_email_sign_up {
		return fail(400, 'EMAIL_PASSWORD_SIGN_UP_DISABLED',
			'Email and password sign up is not enabled')
	}
	email := normalize_email(input.email)!
	a.check_password(input.password)!
	additional := a.parse_user_fields(input.additional_fields, map[string]json2.Any{}, true)!
	now := stamp_millis(a.clock_millis())
	mut user := User{
		additional_fields: additional
		id:                a.new_id('user')!
		name:              input.name
		email:             email
		image:             input.image
		created_at:        now
		updated_at:        now
	}
	generic_duplicate := a.config.require_email_verification || !a.config.auto_sign_in
	if existing := (a.storage.user_by_email(email)!).value {
		if generic_duplicate {
			a.config.password_hasher.hash(input.password)!
			a.config.on_existing_user_sign_up(existing)!
			return AuthResult{
				user: a.synthetic_user(user)!
			}
		}
		return fail(422, 'USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL',
			'User already exists. Use another email.')
	}
	hash := a.config.password_hasher.hash(input.password)!
	decision := a.config.validate_user_info(user, UserInfoSource{ method: 'email-password' })!
	if decision.error != '' {
		if generic_duplicate { return AuthResult{
				user: a.synthetic_user(user)!
			} }
		return fail(403, decision.error, if decision.error_description != '' {
			decision.error_description
		} else {
			decision.error
		})
	}
	user = a.persist_user(user)!
	a.persist_account(Account{
		id:          a.new_id('account')!
		user_id:     user.id
		provider_id: 'credential'
		account_id:  user.id
		password:    hash
	})!
	if (a.config.send_verification_on_sign_up or { a.config.require_email_verification })
		&& a.can_send_verification() {
		a.issue_email('verify-email', user, '')!
	}
	if !a.config.auto_sign_in || a.config.require_email_verification { return AuthResult{
			user: user
		} }
	session := a.make_session(user.id, ctx, true)!
	return AuthResult{
		user:    user
		token:   session.token
		session: session
	}
}

fn (mut a Auth) sign_in(input SignInInput, ctx RequestContext) !AuthResult {
	if !a.config.email_and_password {
		return fail(400, 'EMAIL_PASSWORD_DISABLED', 'Email and password sign in is not enabled')
	}
	email := normalize_email(input.email)!
	a.check_password_max(input.password)!
	if input.password.len > 4096 {
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}
	user := (a.find_user_by_email(email)!).value or {
		a.config.log('warn', 'User not found')
		a.config.password_hasher.hash(input.password)!
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}

	account := (a.storage.account(user.id, 'credential')!).value or {
		a.config.password_hasher.hash(input.password)!
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}

	if account.password == '' {
		a.config.password_hasher.hash(input.password)!
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}
	if !a.config.password_hasher.verify(input.password, account.password)! {
		a.config.log('warn', 'Invalid password')
		return fail(401, 'INVALID_EMAIL_OR_PASSWORD', 'Invalid email or password')
	}
	if a.config.require_email_verification && !user.email_verified {
		if a.config.send_verification_on_sign_in && a.can_send_verification() {
			a.issue_email('verify-email', user, '')!
		}
		return fail(403, 'EMAIL_NOT_VERIFIED', 'Email not verified')
	}
	session := a.make_session(user.id, ctx, input.remember_me)!
	return AuthResult{
		user:    user
		token:   session.token
		session: session
	}
}
