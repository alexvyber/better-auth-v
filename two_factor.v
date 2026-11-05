module better_auth

import crypto.hmac
import crypto.sha1
import crypto.sha256
import encoding.base32
import json
import net.urllib
import strconv
import x.json2

pub struct TOTPOptions {
pub:
	digits             int = 6
	period             int = 30
	disable            bool
	allow_passwordless ?bool @[json: allowPasswordless]
}

pub struct BackupCodeOptions {
pub:
	amount             int    = 10
	length             int    = 10
	store_backup_codes string = 'encrypted' @[json: storeBackupCodes]
	allow_passwordless ?bool  @[json: allowPasswordless]
	generate           fn (mut EndpointContext) ![]string       = default_backup_codes       @[skip]
	encrypt            fn (mut EndpointContext, string) !string = no_email_otp_codec @[skip]
	decrypt            fn (mut EndpointContext, string) !string = no_email_otp_codec @[skip]
}

pub struct TwoFactorLockout {
pub:
	enabled             bool = true
	max_failed_attempts int  = 10 @[json: maxFailedAttempts]
	duration_seconds    int  = 900 @[json: durationSeconds]
}

pub struct TwoFactorOptions {
pub:
	otp_options                 TwoFactorOTPOptions @[json: otpOptions]
	issuer                      string
	totp_options                TOTPOptions       @[json: totpOptions]
	backup_code_options         BackupCodeOptions @[json: backupCodeOptions]
	skip_verification_on_enable bool              @[json: skipVerificationOnEnable]
	allow_passwordless          bool              @[json: allowPasswordless]
	two_factor_cookie_max_age   i64 = 600               @[json: twoFactorCookieMaxAge]
	trust_device_max_age        i64 = 2592000               @[json: trustDeviceMaxAge]
	account_lockout             TwoFactorLockout  @[json: accountLockout]
}

pub struct TwoFactorPlugin {
pub:
	options TwoFactorOptions
}

pub fn (_ TwoFactorPlugin) id() string {
	return 'two-factor'
}

pub fn (_ TwoFactorPlugin) schema() PluginFields {
	return PluginFields{
		user: {
			'twoFactorEnabled': AdditionalField{
				field_type:    'boolean'
				input:         false
				default_value: json2.Any(false)
			}
		}
	}
}

pub fn (_ TwoFactorPlugin) endpoints() []Endpoint {
	return [Endpoint{ path: '/two-factor/send-otp', handler: send_two_factor_otp },
		Endpoint{ path: '/two-factor/verify-otp', handler: verify_two_factor_otp },
		Endpoint{
			path:            '/two-factor/enable'
			require_session: true
			handler:         enable_two_factor
		}, Endpoint{
			path:            '/two-factor/disable'
			require_session: true
			handler:         disable_two_factor
		}, Endpoint{
			path:            '/two-factor/get-totp-uri'
			require_session: true
			handler:         get_totp_uri
		}, Endpoint{
			path:    '/two-factor/verify-totp'
			handler: verify_totp
		}, Endpoint{
			path:            '/two-factor/generate-backup-codes'
			require_session: true
			handler:         generate_backup_codes
		}, Endpoint{
			path:    '/two-factor/verify-backup-code'
			handler: verify_backup_code
		}, Endpoint{
			path:    '/internal/two-factor/generate-totp'
			handler: generate_totp_endpoint
		}, Endpoint{
			path:    '/internal/two-factor/view-backup-codes'
			handler: view_backup_codes
		}]
}

fn (a &Auth) two_factor_options() ?TwoFactorOptions {
	for plugin in a.config.plugins {
		if plugin is TwoFactorPlugin { return plugin.options }
	}
	return none
}

fn enabled_two_factor(user User) bool {
	return (user.additional_fields['twoFactorEnabled'] or { json2.Any(false) }).bool()
}

// RFC 4226 dynamic truncation; strings are UTF-8 bytes, matching upstream createOTP.
pub fn hotp(secret []u8, counter u64, digits int) !string {
	if digits < 1 || digits > 8 { return error('Digits must be between 1 and 8') }
	mut input := []u8{len: 8}
	for i in 0 .. 8 {
		input[7 - i] = u8(counter >> (i * 8))
	}
	signature := hmac.new(secret, input, sha1.sum, sha1.block_size)
	offset := int(signature.last() & 15)
	value := (u32(signature[offset] & 127) << 24) | (u32(signature[offset + 1]) << 16) | (u32(signature[
		offset + 2]) << 8) | u32(signature[offset + 3])
	mut divisor := u32(1)
	for _ in 0 .. digits {
		divisor *= 10
	}
	code := (value % divisor).str()
	return '0'.repeat(digits - code.len) + code
}

fn totp_secret(secret string) ![]u8 {
	if secret.starts_with('base32:') {
		encoding := base32.new_std_encoding_with_padding(base32.no_padding)
		return encoding.decode_string(secret[7..].to_upper().trim_right('='))
	}
	return secret.bytes()
}

fn totp_code(secret string, now i64, options TOTPOptions) !string {
	if options.period < 1 { return error('TOTP period must be positive') }
	return hotp(totp_secret(secret)!, u64(now / 1000 / options.period), options.digits)
}

fn verify_totp_code(secret string, code string, now i64, options TOTPOptions) !bool {
	mut valid := false
	for offset in [-1, 0, 1] {
		expected := totp_code(secret, now + i64(offset) * options.period * 1000, options)!
		matched := hmac.equal(code.bytes(), expected.bytes())
		valid = matched || valid
	}
	return valid
}

fn totp_uri(secret string, issuer string, email string, options TOTPOptions) !string {
	encoding := base32.new_std_encoding_with_padding(base32.no_padding)
	encoded := encoding.encode_to_string(totp_secret(secret)!)
	// URLSearchParams uses '+' for spaces, while the label uses encodeURIComponent.
	label := urllib.query_escape(issuer).replace('+', '%20') + ':' +
		urllib.query_escape(email).replace('+', '%20')
	return 'otpauth://totp/${label}?secret=${encoded}&issuer=${urllib.query_escape(issuer)}&digits=${options.digits}&period=${options.period}'
}

fn default_backup_codes(mut context EndpointContext) ![]string {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).backup_code_options
	if options.amount < 1 || options.amount > 1000 || options.length < 1 || options.length > 1024 {
		return error('invalid backup code size')
	}
	mut codes := []string{}
	for _ in 0 .. options.amount {
		code := generate_auth_id(options.length)!
		split := if code.len < 5 { code.len } else { 5 }
		codes << code[..split] + '-' + code[split..]
	}
	return codes
}

fn (mut context EndpointContext) encode_backup_codes(codes []string) !string {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).backup_code_options
	encoded := json.encode(codes)
	return match options.store_backup_codes {
		'plain' { encoded }
		'encrypted' { symmetric_encrypt(context.auth.secret_config, encoded)! }
		'custom' { options.encrypt(mut context, encoded)! }
		else { return error('unsupported backup code storage') }
	}
}

fn (mut context EndpointContext) decode_backup_codes(stored string) ![]string {
	options := (context.auth.two_factor_options() or { return error('two-factor not configured') }).backup_code_options
	encoded := match options.store_backup_codes {
		'plain' { stored }
		'encrypted' { symmetric_decrypt(context.auth.secret_config, stored)! }
		'custom' { options.decrypt(mut context, stored)! }
		else { return error('unsupported backup code storage') }
	}

	return json.decode([]string, encoded)
}

fn (mut context EndpointContext) two_factor_password(user User, fields map[string]json2.Any, allow_passwordless bool) ! {
	password := (fields['password'] or { json2.Any('') }).str()
	account := (context.auth.storage.account(user.id, 'credential')!).value
	if account == none && allow_passwordless { return }
	context.auth.check_password_max(password)!
	if credential := account {
		if password != '' {
			if context.auth.config.password_hasher.verify(password, credential.password)! { return }
		}
	}
	return fail(400, 'INVALID_PASSWORD', 'Invalid password')
}

fn (mut context EndpointContext) set_two_factor_enabled(current SessionResult, enabled bool) !SessionResult {
	mut fields := current.user.additional_fields.clone()
	fields['twoFactorEnabled'] = enabled
	user := context.auth.update_user_record(User{
		...current.user
		additional_fields: fields
		updated_at:        stamp_millis(context.auth.clock_millis())
	})!
	session := context.auth.make_session(user.id, context.auth.operation.request,
		current.session.persistent)!
	context.auth.remove_session(current.session.token)!
	return SessionResult{
		session: session
		user:    user
	}
}

fn enable_two_factor(mut context EndpointContext, request Request) !Response {
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	fields := email_otp_body(request)!
	context.two_factor_password(current.user, fields, options.allow_passwordless)!
	method := (fields['method'] or { json2.Any('totp') }).str()
	if method == 'otp' {
		if !options.otp_options.configured() {
			return fail(400, 'OTP_NOT_CONFIGURED', 'OTP is not available')
		}
		updated := context.set_two_factor_enabled(current, true)!
		return context.auth.set_session_cookies(Response{
			headers: [
				Header{'content-type', 'application/json'},
			]
			body:    '{"method":"otp"}'
		}, updated)
	}
	if method != 'totp' { return fail(400, 'VALIDATION_ERROR', 'Invalid two-factor method') }
	if options.totp_options.disable {
		return fail(400, 'TOTP_NOT_CONFIGURED', 'TOTP is not available')
	}
	records := context.two_factors(current.user.id)!
	if records.len > 0 {
		verified := records[0].verified or { true }
		if verified {
			return fail(400, 'TOTP_ALREADY_ENABLED', 'TOTP is already enabled')
		}
	}
	secret := generate_auth_id(32)!
	codes := options.backup_code_options.generate(mut context)!
	record := TwoFactorRecord{
		id:           if records.len > 0 { records[0].id } else { context.auth.new_id('twoFactor')! }
		user_id:      current.user.id
		secret:       symmetric_encrypt(context.auth.secret_config, secret)!
		backup_codes: context.encode_backup_codes(codes)!
		verified:     options.skip_verification_on_enable
	}
	context.save_two_factor(record, records.len == 0)!
	issuer := (fields['issuer'] or {
		json2.Any(if options.issuer != '' { options.issuer } else { context.auth.config.app_name })
	}).str()
	uri := totp_uri(secret, issuer, current.user.email, options.totp_options)!
	response := Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"method":"totp","totpURI":${json.encode(uri)},"backupCodes":${json.encode(codes)}}'
	}
	if options.skip_verification_on_enable {
		return context.auth.set_session_cookies(response, context.set_two_factor_enabled(current,
			true)!)
	}
	return response
}

fn get_totp_uri(mut context EndpointContext, request Request) !Response {
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	if options.totp_options.disable {
		return fail(400, 'TOTP_NOT_CONFIGURED', 'TOTP is not available')
	}
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	records := context.two_factors(current.user.id)!
	if records.len == 0 { return fail(400, 'TOTP_NOT_ENABLED', 'TOTP not enabled') }
	context.two_factor_password(current.user, email_otp_body(request)!, options.totp_options.allow_passwordless or {
		options.allow_passwordless
	})!
	secret := symmetric_decrypt(context.auth.secret_config, records[0].secret)!
	uri := totp_uri(secret, if options.issuer != '' {
		options.issuer
	} else {
		context.auth.config.app_name
	}, current.user.email, options.totp_options)!
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"totpURI":${json.encode(uri)}}'
	}
}

fn generate_totp_endpoint(mut context EndpointContext, request Request) !Response {
	if context.auth.operation.request.request != none { return fail(404, 'NOT_FOUND', 'Not found') }
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	if options.totp_options.disable {
		return fail(400, 'TOTP_NOT_CONFIGURED', "totp isn't configured")
	}
	code := totp_code(email_otp_string(email_otp_body(request)!, 'secret')!,
		context.auth.clock_millis(), options.totp_options)!
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"code":${json.encode(code)}}'
	}
}

fn generate_backup_codes(mut context EndpointContext, request Request) !Response {
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	if !enabled_two_factor(current.user) {
		return fail(400, 'TWO_FACTOR_NOT_ENABLED', "Two factor isn't enabled")
	}
	context.two_factor_password(current.user, email_otp_body(request)!, options.backup_code_options.allow_passwordless or {
		options.allow_passwordless
	})!
	records := context.two_factors(current.user.id)!
	if records.len == 0 {
		return fail(400, 'BACKUP_CODES_NOT_ENABLED', "Backup codes aren't enabled")
	}
	codes := options.backup_code_options.generate(mut context)!
	context.save_two_factor(TwoFactorRecord{
		...records[0]
		backup_codes: context.encode_backup_codes(codes)!
	}, false)!
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"status":true,"backupCodes":${json.encode(codes)}}'
	}
}

fn view_backup_codes(mut context EndpointContext, request Request) !Response {
	if context.auth.operation.request.request != none { return fail(404, 'NOT_FOUND', 'Not found') }
	records := context.two_factors(email_otp_string(email_otp_body(request)!, 'userId')!)!
	if records.len == 0 {
		return fail(400, 'BACKUP_CODES_NOT_ENABLED', "Backup codes aren't enabled")
	}
	codes := context.decode_backup_codes(records[0].backup_codes)!
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"status":true,"backupCodes":${json.encode(codes)}}'
	}
}

fn disable_two_factor(mut context EndpointContext, request Request) !Response {
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	current := context.session or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	context.two_factor_password(current.user, email_otp_body(request)!, options.allow_passwordless)!
	context.delete_two_factors(current.user.id)!
	updated := context.set_two_factor_enabled(current, false)!
	mut response := context.auth.set_session_cookies(json_response({
		'status': true
	}), updated)!
	if trust := context.two_factor_cookie('trust_device') {
		parts := trust.split('!')
		if parts.len == 2 { context.delete_verification_by_identifier(parts[1])! }
	}
	response = context.two_factor_set_cookie(response, 'trust_device', '', 0)
	return response
}

struct TwoFactorChallenge {
	set_session_cookie bool
	user               User
	session            ?Session
	key                string
	expires            i64
}

fn (context &EndpointContext) two_factor_cookie(name string) ?string {
	value := cookie_values(context.auth.operation.request)[context.auth.cookie_name_for(name)] or {
		return none
	}
	return context.auth.verify_signed_value(value)
}

fn (context &EndpointContext) two_factor_set_cookie(response Response, name string, value string, age i64) Response {
	return with_header(response, 'set-cookie', context.auth.cache_cookie_header(context.auth.cookie_name_for(name), if value == '' {
		''
	} else {
		urllib.query_escape(context.auth.sign_cookie(value))
	}, age))
}

fn (mut context EndpointContext) two_factor_challenge() !TwoFactorChallenge {
	if current := (context.auth.current_session(context.auth.operation.request)!).value {
		return TwoFactorChallenge{
			user:    current.user
			session: current.session
			key:     current.user.id + '!' + current.session.id
		}
	}
	key := context.two_factor_cookie('two_factor') or {
		return fail(401, 'INVALID_TWO_FACTOR_COOKIE', 'Invalid two factor cookie')
	}
	proof := (context.find_verification_value(key)!).value or {
		return fail(401, 'INVALID_TWO_FACTOR_COOKIE', 'Invalid two factor cookie')
	}

	user := (context.auth.storage.user(proof.value)!).value or {
		return fail(401, 'INVALID_TWO_FACTOR_COOKIE', 'Invalid two factor cookie')
	}

	return TwoFactorChallenge{
		user:    user
		key:     key
		expires: verification_expiry_millis(proof)
	}
}

fn (mut context EndpointContext) issue_trust_device(response Response, user_id string) !Response {
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	identifier := 'trust-device-' + generate_auth_id(32)!
	context.create_verification_value(Verification{
		identifier:        identifier
		value:             user_id
		expires_at_millis: context.auth.clock_millis() + options.trust_device_max_age * 1000
	})!
	token := base64url(hmac.new(context.auth.config.secret.bytes(),
		(user_id + '!' + identifier).bytes(), sha256.sum, sha256.block_size))
	return context.two_factor_set_cookie(response, 'trust_device', token + '!' + identifier,
		options.trust_device_max_age)
}

fn (mut a Auth) two_factor_sign_in(result AuthResult) !Lookup[Response] {
	options := a.two_factor_options() or { return Lookup[Response]{} }
	if !enabled_two_factor(result.user) { return Lookup[Response]{} }
	mut context := EndpointContext{
		auth: a
	}
	mut expired_trust := false
	if trust := context.two_factor_cookie('trust_device') {
		parts := trust.split('!')
		if parts.len == 2 {
			expected := base64url(hmac.new(a.config.secret.bytes(),
				(result.user.id + '!' + parts[1]).bytes(), sha256.sum, sha256.block_size))
			if hmac.equal(expected.bytes(), parts[0].bytes()) {
				if proof := (context.consume_verification_value(parts[1])!).value {
					if proof.value == result.user.id {
						session := result.session or { return error('missing sign-in session') }
						response := a.set_session_cookies(Response{
							headers: [Header{'content-type', 'application/json'}]
							body:    '{"redirect":false,"token":${json.encode(session.token)},"user":${a.user_json(result.user)}}'
						}, SessionResult{
							session: session
							user:    result.user
						})!
						return Lookup[Response]{
							value: context.issue_trust_device(response, result.user.id)!
						}
					}
				}
			}
		}
		expired_trust = true
	}
	if session := result.session { a.remove_session(session.token)! }
	a.operation.attempt.new_session = none
	identifier := '2fa-' + generate_auth_id(20)!
	expires := a.clock_millis() + options.two_factor_cookie_max_age * 1000
	context.create_verification_value(Verification{
		identifier:        identifier
		value:             result.user.id
		expires_at_millis: expires
	})!
	context.create_verification_value(Verification{
		identifier:        '2fa-attempts-' + identifier
		value:             '0'
		expires_at_millis: expires
	})!
	mut methods := []string{}
	records := context.two_factors(result.user.id)!
	if !options.totp_options.disable && records.len > 0 && (records[0].verified or { true }) {
		methods << 'totp'
	}
	if options.otp_options.configured() { methods << 'otp' }
	mut response := a.clear_cookie(Response{
		headers: [
			Header{'content-type', 'application/json'},
		]
		body:    '{"twoFactorRedirect":true,"twoFactorMethods":${json.encode(methods)}}'
	})
	if session := result.session {
		if !session.persistent {
			response = with_header(response, 'set-cookie', a.cache_cookie_header(a.cookie_name_for('dont_remember'),
				urllib.query_escape(a.sign_cookie('true')), none))
		}
	}
	response = with_header(response, 'set-cookie', a.cache_cookie_header(a.cache_cookie_name(), '',
		i64(0)))
	response = context.two_factor_set_cookie(response, 'two_factor', identifier,
		options.two_factor_cookie_max_age)
	if expired_trust { response = context.two_factor_set_cookie(response, 'trust_device', '', 0) }
	return Lookup[Response]{
		value: response
	}
}

fn (mut context EndpointContext) complete_two_factor(challenge TwoFactorChallenge, fields map[string]json2.Any) !Response {
	mut session := challenge.session
	if session == none {
		proof := (context.consume_verification_value(challenge.key)!).value or {
			return fail(401, 'INVALID_TWO_FACTOR_COOKIE', 'Invalid two factor cookie')
		}

		if proof.value != challenge.user.id {
			return fail(401, 'INVALID_TWO_FACTOR_COOKIE', 'Invalid two factor cookie')
		}
		// Burn before session creation; failures must never reopen the challenge.
		context.commit_email_otp_gate()!
		remember := (context.two_factor_cookie('dont_remember') or { '' }) != 'true'
		session = context.auth.make_session(challenge.user.id, context.auth.operation.request,
			remember)!
	}
	actual := session or { return error('missing two-factor session') }
	user := (context.auth.storage.user(challenge.user.id)!).value or {
		return error('two-factor user disappeared')
	}

	mut response := Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"token":${json.encode(actual.token)},"user":${context.auth.user_json(user)}}'
	}
	if challenge.session == none || challenge.set_session_cookie {
		response = context.auth.set_session_cookies(response, SessionResult{
			session: actual
			user:    user
		})!
	}
	if challenge.session == none {
		response = context.two_factor_set_cookie(response, 'two_factor', '', 0)
		if (fields['trustDevice'] or { json2.Any(false) }).bool() {
			response = context.issue_trust_device(response, user.id)!
		}
	}
	return response
}

fn (mut context EndpointContext) check_two_factor_attempt(challenge TwoFactorChallenge) !int {
	if challenge.session != none { return 0 }
	consumed := (context.consume_verification_value('2fa-attempts-' + challenge.key)!).value or {
		return fail(401, 'INVALID_TWO_FACTOR_COOKIE', 'Invalid two factor cookie')
	}

	count := strconv.atoi(consumed.value) or { 5 }
	if count < 0 || count >= 5 {
		context.consume_verification_value(challenge.key)!
		context.commit_email_otp_gate()!
		return fail(400, 'TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE',
			'Too many attempts. Please request a new code.')
	}
	return count
}

fn (mut context EndpointContext) failed_two_factor(challenge TwoFactorChallenge, record TwoFactorRecord, count int, code string, message string) !Response {
	if challenge.session == none {
		context.create_verification_value(Verification{
			identifier:        '2fa-attempts-' + challenge.key
			value:             (count + 1).str()
			expires_at_millis: challenge.expires
		})!
		context.two_factor_record_failure(record)!
		context.commit_email_otp_gate()!
	}
	return fail(401, code, message)
}

fn verify_totp(mut context EndpointContext, request Request) !Response {
	options := context.auth.two_factor_options() or { return error('two-factor not configured') }
	if options.totp_options.disable {
		return fail(400, 'TOTP_NOT_CONFIGURED', 'TOTP is not available')
	}
	fields := email_otp_body(request)!
	code := email_otp_string(fields, 'code')!
	challenge := context.two_factor_challenge()!
	records := context.two_factors(challenge.user.id)!
	if records.len == 0 { return fail(400, 'TOTP_NOT_ENABLED', 'TOTP not enabled') }
	mut record := records[0]
	if challenge.session == none {
		if !(record.verified or { true }) {
			return fail(400, 'TOTP_NOT_ENABLED', 'TOTP not enabled')
		}
	}
	if challenge.session == none { context.two_factor_check_lock(mut record)! }
	// Decryption/configuration errors do not consume the attempt counter.
	secret := symmetric_decrypt(context.auth.secret_config, record.secret)!
	valid := verify_totp_code(secret, code, context.auth.clock_millis(), options.totp_options)!
	count := context.check_two_factor_attempt(challenge)!
	if !valid {
		return context.failed_two_factor(challenge, record, count, 'INVALID_CODE', 'Invalid code')
	}
	if !(record.verified or { false }) {
		if !enabled_two_factor(challenge.user) {
			current := SessionResult{
				session: challenge.session or { return error('enrollment requires session') }
				user:    challenge.user
			}
			updated := context.set_two_factor_enabled(current, true)!
			context.save_two_factor(TwoFactorRecord{ ...record, verified: true }, false)!
			return context.complete_two_factor(TwoFactorChallenge{
				...challenge
				user:               updated.user
				session:            updated.session
				set_session_cookie: true
			}, fields)
		}
	}
	context.save_two_factor(TwoFactorRecord{
		...record
		verified:                  true
		failed_verification_count: if challenge.session == none {
			0
		} else {
			record.failed_verification_count
		}
		locked_until:              if challenge.session == none { none } else { record.locked_until }
	}, false)!
	return context.complete_two_factor(challenge, fields)
}

fn verify_backup_code(mut context EndpointContext, request Request) !Response {
	fields := email_otp_body(request)!
	code := email_otp_string(fields, 'code')!
	challenge := context.two_factor_challenge()!
	records := context.two_factors(challenge.user.id)!
	if records.len == 0 {
		return fail(400, 'BACKUP_CODES_NOT_ENABLED', "Backup codes aren't enabled")
	}
	mut record := records[0]
	if challenge.session == none { context.two_factor_check_lock(mut record)! }
	codes := context.decode_backup_codes(record.backup_codes)!
	count := context.check_two_factor_attempt(challenge)!
	if code !in codes {
		return context.failed_two_factor(challenge, record, count, 'INVALID_BACKUP_CODE',
			'Invalid backup code')
	}
	context.save_two_factor(TwoFactorRecord{
		...record
		backup_codes:              context.encode_backup_codes(codes.filter(it != code))!
		failed_verification_count: if challenge.session == none {
			0
		} else {
			record.failed_verification_count
		}
		locked_until:              if challenge.session == none { none } else { record.locked_until }
	}, false)!
	context.commit_email_otp_gate()!
	return context.complete_two_factor(challenge, fields)
}
