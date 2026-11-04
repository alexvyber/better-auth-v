module better_auth

pub struct TwoFactorOTPOptions {
pub:
	period           f64    = 3
	digits           int    = 6
	allowed_attempts int    = 5    @[json: allowedAttempts]
	store_otp        string = 'plain' @[json: storeOTP]
	has_sender       bool   @[json: hasSender]
	send             fn (mut EndpointContext, User, string) ! = no_two_factor_sender @[skip]
	hash             fn (mut EndpointContext, string) !string = no_email_otp_codec @[skip]
	encrypt          fn (mut EndpointContext, string) !string = no_email_otp_codec @[skip]
	decrypt          fn (mut EndpointContext, string) !string = no_email_otp_codec @[skip]
}

fn (options TwoFactorOTPOptions) configured() bool {
	return options.has_sender || options.send != no_two_factor_sender
}

fn no_two_factor_sender(mut _ EndpointContext, _ User, _ string) ! {
	return error('two-factor sender not configured')
}

fn (options TwoFactorOTPOptions) codec() EmailOTPOptions {
	return EmailOTPOptions{
		otp_length:  options.digits
		store_otp:   options.store_otp
		hash_otp:    options.hash
		encrypt_otp: options.encrypt
		decrypt_otp: options.decrypt
	}
}

fn send_two_factor_otp(mut context EndpointContext, _ Request) !Response {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).otp_options
	if !options.configured() { return fail(400, 'OTP_NOT_CONFIGURED', "otp isn't configured") }
	challenge := context.two_factor_challenge()!
	code := context.new_email_otp(options.codec(), challenge.user.email, 'two-factor')!
	stored := context.store_email_otp(options.codec(), code)!
	// Rotation cannot depend on distinct millisecond creation timestamps.
	context.delete_verification_by_identifier('2fa-otp-' + challenge.key)!
	context.create_verification_value(Verification{
		identifier:        '2fa-otp-' + challenge.key
		value:             stored + ':0'
		expires_at_millis: context.auth.clock_millis() + i64(options.period * 60000)
	})!
	options.send(mut context, challenge.user, code)!
	return json_response({
		'status': true
	})
}

fn (mut context EndpointContext) two_factor_check_lock(mut record TwoFactorRecord) ! {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).account_lockout
	if !options.enabled { return }
	if locked := record.locked_until {
		if epoch_millis(locked)! > context.auth.clock_millis() {
			return fail(429, 'ACCOUNT_TEMPORARILY_LOCKED',
				'Too many failed verification attempts. Your account is temporarily locked. Please try again later.')
		}
		record = TwoFactorRecord{
			...record
			failed_verification_count: 0
			locked_until:              none
		}
		context.save_two_factor(record, false)!
	}
}

fn (mut context EndpointContext) two_factor_record_failure(record TwoFactorRecord) ! {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).account_lockout
	if !options.enabled { return }
	failed := record.failed_verification_count + 1
	context.save_two_factor(TwoFactorRecord{
		...record
		failed_verification_count: failed
		locked_until:              if failed >= options.max_failed_attempts {
			?string(stamp_millis(context.auth.clock_millis() + options.duration_seconds * 1000))
		} else {
			none
		}
	}, false)!
}

fn verify_two_factor_otp(mut context EndpointContext, request Request) !Response {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).otp_options
	fields := email_otp_body(request)!
	code := email_otp_string(fields, 'code')!
	mut challenge := context.two_factor_challenge()!
	mut record := ?TwoFactorRecord(none)
	if challenge.session == none {
		records := context.two_factors(challenge.user.id)!
		if records.len > 0 {
			mut current := records[0]
			context.two_factor_check_lock(mut current)!
			record = current
		}
	}
	consumed := context.consume_verification_value('2fa-otp-' + challenge.key)!
	proof := consumed.value or {
		context.commit_email_otp_gate()!
		return fail(400, 'OTP_HAS_EXPIRED', 'OTP has expired')
	}

	stored, count := split_email_otp(proof.value)
	if count >= options.allowed_attempts {
		context.commit_email_otp_gate()!
		return fail(400, 'TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE',
			'Too many attempts. Please request a new code.')
	}
	valid := context.matches_email_otp(options.codec(), stored, code) or {
		// Restore the exact row on a server-side codec error without spending a guess.
		context.create_verification_value(proof)!
		context.commit_email_otp_gate()!
		return err
	}
	if !valid {
		context.create_verification_value(Verification{
			...proof
			id:    ''
			value: stored + ':' + (count + 1).str()
		})!
		if current := record { context.two_factor_record_failure(current)! }
		context.commit_email_otp_gate()!
		return fail(401, 'INVALID_CODE', 'Invalid code')
	}
	if current := record { context.save_two_factor(TwoFactorRecord{
			...current
			failed_verification_count: 0
			locked_until:              none
		}, false)! }
	context.commit_email_otp_gate()!
	if !enabled_two_factor(challenge.user) {
		current := SessionResult{
			user:    challenge.user
			session: challenge.session or {
				return fail(400, 'FAILED_TO_CREATE_SESSION', 'Failed to create session')
			}
		}
		updated := context.set_two_factor_enabled(current, true)!
		challenge = TwoFactorChallenge{
			...challenge
			user:               updated.user
			session:            updated.session
			set_session_cookie: true
		}
	}
	return context.complete_two_factor(challenge, fields)
}
