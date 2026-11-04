module better_auth

import crypto.hmac
import crypto.rand
import json
import x.json2

pub struct EmailOTPMessage {
pub:
	email string
	otp   string
	kind  string @[json: type]
}

pub struct EmailOTPChangeEmailOptions {
pub:
	enabled              bool
	verify_current_email bool @[json: verifyCurrentEmail]
}

pub struct EmailOTPRateLimit {
pub:
	window i64 = 60
	max    int = 3
}

pub struct EmailOTPOptions {
pub:
	rate_limit                          EmailOTPRateLimit                                 @[json: rateLimit]
	expires_in                          f64    = 300                                               @[json: expiresIn]
	otp_length                          int    = 6                                               @[json: otpLength]
	allowed_attempts                    f64    = 3                                               @[json: allowedAttempts]
	store_otp                           string = 'plain'                                            @[json: storeOTP]
	resend_strategy                     string = 'rotate'                                            @[json: resendStrategy]
	disable_sign_up                     bool                                              @[json: disableSignUp]
	send_verification_on_sign_up        bool                                              @[json: sendVerificationOnSignUp]
	override_default_email_verification bool                                              @[json: overrideDefaultEmailVerification]
	change_email                        EmailOTPChangeEmailOptions                        @[json: changeEmail]
	generate_otp                        fn (mut EndpointContext, EmailOTPMessage) !string = no_email_otp_generator @[skip]
	send_otp                            fn (mut EndpointContext, EmailOTPMessage) !       = no_email_otp_sender       @[skip]
	hash_otp                            fn (mut EndpointContext, string) !string          = no_email_otp_codec          @[skip]
	encrypt_otp                         fn (mut EndpointContext, string) !string          = no_email_otp_codec          @[skip]
	decrypt_otp                         fn (mut EndpointContext, string) !string          = no_email_otp_codec          @[skip]
}

fn no_email_otp_generator(mut _ EndpointContext, _ EmailOTPMessage) !string {
	return ''
}

fn no_email_otp_sender(mut _ EndpointContext, _ EmailOTPMessage) ! {
	return error('send email verification is not implemented')
}

fn no_email_otp_codec(mut _ EndpointContext, _ string) !string {
	return error('email OTP codec is not configured')
}

pub struct EmailOTPPlugin {
pub:
	options EmailOTPOptions
}

pub fn (_ EmailOTPPlugin) id() string {
	return 'email-otp'
}

pub fn (_ EmailOTPPlugin) endpoints() []Endpoint {
	return [
		Endpoint{
			path:    '/email-otp/send-verification-otp'
			handler: email_otp_send
		},
		Endpoint{
			path:    '/email-otp/check-verification-otp'
			handler: email_otp_check
		},
		Endpoint{
			path:    '/email-otp/verify-email'
			handler: email_otp_verify_email
		},
		Endpoint{
			path:    '/sign-in/email-otp'
			handler: email_otp_sign_in
		},
		Endpoint{
			path:    '/email-otp/request-password-reset'
			handler: email_otp_request_reset
		},
		Endpoint{
			path:    '/forget-password/email-otp'
			handler: email_otp_request_reset
		},
		Endpoint{
			path:    '/email-otp/reset-password'
			handler: email_otp_reset_password
		},
		Endpoint{
			path:            '/email-otp/request-email-change'
			require_session: true
			handler:         email_otp_request_change
		},
		Endpoint{
			path:            '/email-otp/change-email'
			require_session: true
			handler:         email_otp_change
		},
	]
}

fn (a &Auth) email_otp_options() !EmailOTPOptions {
	for plugin in a.config.plugins {
		if plugin is EmailOTPPlugin { return plugin.options }
	}
	return error('email-otp plugin is not configured')
}

fn email_otp_identifier(kind string, email string) string {
	return '${kind}-otp-${email}'
}

fn email_otp_limit(options EmailOTPOptions) f64 {
	return if options.allowed_attempts == 0 { f64(3) } else { options.allowed_attempts }
}

fn email_otp_body(request Request) !map[string]json2.Any {
	return json2.decode[map[string]json2.Any](request.body) or {
		return fail(400, 'VALIDATION_ERROR', 'Body must be an object')
	}
}

fn email_otp_string(fields map[string]json2.Any, key string) !string {
	value := fields[key] or { return fail(400, 'VALIDATION_ERROR', '${key} is required') }
	if value !is string { return fail(400, 'VALIDATION_ERROR', '${key} must be a string') }
	return value.str()
}

fn email_otp_email(fields map[string]json2.Any, key string, validate bool) !string {
	value := email_otp_string(fields, key)!.to_lower()
	if validate {
		if value != value.trim_space() { return fail(400, 'INVALID_EMAIL', 'Invalid email') }
		normalize_email(value)!
	}
	return value
}

fn email_otp_kind(fields map[string]json2.Any) !string {
	kind := email_otp_string(fields, 'type')!
	if kind !in ['email-verification', 'sign-in', 'forget-password', 'change-email'] {
		return fail(400, 'VALIDATION_ERROR', 'Invalid OTP type')
	}
	return kind
}

fn split_email_otp(value string) (string, int) {
	position := value.last_index(':') or { return value, 0 }
	return value[..position], value[position + 1..].int()
}

fn (mut context EndpointContext) new_email_otp(options EmailOTPOptions, email string, kind string) !string {
	custom := options.generate_otp(mut context, EmailOTPMessage{ email: email, kind: kind })!
	if custom != '' { return custom }
	mut result := []u8{}
	for result.len < options.otp_length {
		for byte in rand.bytes(32)! {
			if byte < 250 { result << u8(`0` + byte % 10) }
			if result.len == options.otp_length { break
			 }
		}
	}
	return result.bytestr()
}

fn (mut context EndpointContext) store_email_otp(options EmailOTPOptions, otp string) !string {
	return match options.store_otp {
		'encrypted' { symmetric_encrypt(context.auth.secret_config, otp)! }
		'hashed' { default_one_time_token_hasher(otp)! }
		'custom-hash' { options.hash_otp(mut context, otp)! }
		'custom-encryption' { options.encrypt_otp(mut context, otp)! }
		else { otp }
	}
}

fn (mut context EndpointContext) retrieve_email_otp(options EmailOTPOptions, stored string) !Lookup[string] {
	return match options.store_otp {
		'hashed', 'custom-hash' {
			Lookup[string]{}
		}
		'encrypted' {
			Lookup[string]{
				value: symmetric_decrypt(context.auth.secret_config, stored)!
			}
		}
		'custom-encryption' {
			Lookup[string]{
				value: options.decrypt_otp(mut context, stored)!
			}
		}
		else {
			Lookup[string]{
				value: stored
			}
		}
	}
}

fn (mut context EndpointContext) matches_email_otp(options EmailOTPOptions, stored string, otp string) !bool {
	if options.store_otp in ['hashed', 'custom-hash'] {
		candidate := context.store_email_otp(options, otp)!
		return hmac.equal(candidate.bytes(), stored.bytes())
	}
	clear := (context.retrieve_email_otp(options, stored)!).value or { return false }
	return hmac.equal(clear.bytes(), otp.bytes())
}

fn (mut context EndpointContext) create_email_otp_record(options EmailOTPOptions, identifier string, otp string) ! {
	stored := context.store_email_otp(options, otp)!
	expires := i64(f64(context.auth.clock_millis()) + options.expires_in * 1000)
	context.create_verification_value(Verification{
		identifier:        identifier
		value:             stored + ':0'
		expires_at:        expires / 1000
		expires_at_millis: expires
	})!
}

fn (mut context EndpointContext) resolve_email_otp(options EmailOTPOptions, email string, kind string) !string {
	identifier := email_otp_identifier(kind, email)
	if options.resend_strategy == 'reuse' {
		if existing := (context.find_verification_value(identifier)!).value {
			stored, attempts := split_email_otp(existing.value)
			if verification_expiry_millis(existing) >= context.auth.clock_millis()
				&& f64(attempts) < email_otp_limit(options) {
				if clear := (context.retrieve_email_otp(options, stored)!).value {
					if clear != '' {
						expires := i64(f64(context.auth.clock_millis()) + options.expires_in * 1000)
						context.update_verification_by_identifier(identifier,
							'{"expiresAt":${json.encode(stamp_millis(expires))}}')!
						return clear
					}
				}
			}
		}
	}
	otp := context.new_email_otp(options, email, kind)!
	context.create_email_otp_record(options, identifier, otp)!
	return otp
}

fn (mut context EndpointContext) commit_email_otp_gate() ! {
	context.auth.commit_transaction()!
	context.auth.begin_transaction(false)!
}

fn (mut context EndpointContext) verify_email_otp_atomic(options EmailOTPOptions, identifier string, otp string, commit_success bool) ! {
	if previous := (context.find_verification_value(identifier)!).value {
		if verification_expiry_millis(previous) < context.auth.clock_millis() {
			context.delete_verification_by_identifier(identifier)!
			context.commit_email_otp_gate()!
			return fail(400, 'OTP_EXPIRED', 'OTP expired')
		}
	}
	consumed := context.consume_verification_value(identifier)!
	record := consumed.value or { return fail(400, 'INVALID_OTP', 'Invalid OTP') }
	stored, attempts := split_email_otp(record.value)
	if f64(attempts) >= email_otp_limit(options) {
		context.commit_email_otp_gate()!
		return fail(403, 'TOO_MANY_ATTEMPTS', 'Too many attempts')
	}
	verified := context.matches_email_otp(options, stored, otp) or {
		if commit_success { context.commit_email_otp_gate()! }
		return err
	}
	if !verified {
		context.create_verification_value(Verification{
			identifier:        identifier
			value:             stored + ':' + (attempts + 1).str()
			expires_at:        record.expires_at
			expires_at_millis: record.expires_at_millis
		})!
		context.commit_email_otp_gate()!
		return fail(400, 'INVALID_OTP', 'Invalid OTP')
	}
	if commit_success { context.commit_email_otp_gate()! }
}

pub fn split_otp_value(value string) (string, string) {
	position := value.last_index(':') or { return value, '' }
	return value[..position], value[position + 1..]
}

fn (mut context EndpointContext) email_otp_internal(name string, arguments string) !string {
	options := context.auth.email_otp_options()!
	input := json2.decode[map[string]json2.Any](arguments)!
	email := email_otp_email(input, 'email', false)!
	kind := email_otp_kind(input)!
	if name == 'createVerificationOTP' {
		otp := context.new_email_otp(options, email, kind)!
		context.create_email_otp_record(options, email_otp_identifier(kind, email), otp)!
		return json.encode(otp)
	}
	record := (context.find_verification_value(email_otp_identifier(kind, email))!).value or {
		return '{"otp":null}'
	}

	if verification_expiry_millis(record) < context.auth.clock_millis() { return '{"otp":null}' }
	if options.store_otp in ['hashed', 'custom-hash'] {
		return fail(400, 'BAD_REQUEST', 'OTP is hashed, cannot return the plain text OTP')
	}
	stored, _ := split_email_otp(record.value)
	clear := (context.retrieve_email_otp(options, stored)!).value or { return '{"otp":null}' }
	return json.encode({
		'otp': clear
	})
}

fn (a &Auth) email_otp_verification_override() bool {
	options := a.email_otp_options() or { return false }
	return options.override_default_email_verification
}

fn (mut a Auth) send_email_otp_verification(user User) ! {
	options := a.email_otp_options()!
	mut context := EndpointContext{
		auth: a
	}
	otp := context.resolve_email_otp(options, user.email, 'email-verification')!
	options.send_otp(mut context, EmailOTPMessage{
		email: user.email
		otp:   otp
		kind:  'email-verification'
	})!
}

fn (mut a Auth) email_otp_after_signup(user User) ! {
	options := a.email_otp_options() or { return }
	if !options.send_verification_on_sign_up || options.override_default_email_verification {
		return
	}
	mut context := EndpointContext{
		auth: a
	}
	otp := context.new_email_otp(options, user.email, 'email-verification')!
	context.create_email_otp_record(options,
		email_otp_identifier('email-verification', user.email), otp)!
	options.send_otp(mut context, EmailOTPMessage{
		email: user.email
		otp:   otp
		kind:  'email-verification'
	})!
}
