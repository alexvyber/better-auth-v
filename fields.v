module better_auth

import json
import time
import x.json2

const core_user_fields = ['id', 'name', 'email', 'emailVerified', 'image', 'createdAt', 'updatedAt']
const sign_up_reserved_fields = ['name', 'email', 'password', 'image', 'callbackURL', 'rememberMe']
const core_session_fields = ['id', 'userId', 'token', 'expiresAt', 'createdAt', 'updatedAt',
	'ipAddress', 'userAgent', 'persistent', 'encrypted_token', 'additional_fields', '$vSession']

fn merge_fields(base string, fields map[string]json2.Any) string {
	mut encoded := base[..base.len - 1]
	for key, value in fields {
		encoded += ',' + json.encode(key) + ':' + value.json_str()
	}
	return encoded + '}'
}

// User records are flat JSON objects even though dynamic V fields live in a map.
pub fn encode_user(user User) string {
	mut fields := user.additional_fields.clone()
	if user.image == none { fields['image'] = json2.Null{} }
	return merge_fields(json.encode(user), fields)
}

pub fn decode_user(encoded string) !User {
	user := json.decode(User, encoded)!
	fields := json2.decode[map[string]json2.Any](encoded)!
	mut additional := map[string]json2.Any{}
	for key, value in fields {
		if key !in core_user_fields { additional[key] = value }
	}
	return User{
		...user
		additional_fields: additional
	}
}

fn decode_account(encoded string) !Account {
	account := json.decode(Account, encoded)!
	fields := json2.decode[map[string]json2.Any](encoded)!
	// Preserve records written by schema versions predating camelCase account DTOs.
	return Account{
		...account
		user_id:     if account.user_id != '' {
			account.user_id
		} else {
			(fields['user_id'] or { json2.Any('') }).str()
		}
		provider_id: if account.provider_id != '' {
			account.provider_id
		} else {
			(fields['provider_id'] or { json2.Any('') }).str()
		}
		account_id:  if account.account_id != '' {
			account.account_id
		} else {
			(fields['account_id'] or { json2.Any('') }).str()
		}
	}
}

fn decode_auth_result(encoded string) !AuthResult {
	result := json.decode(AuthResult, encoded)!
	fields := json2.decode[map[string]json2.Any](encoded)!
	if result.two_factor_redirect { return result }
	return AuthResult{
		...result
		user: decode_user((fields['user'] or { return error('missing user') }).json_str())!
	}
}

fn decode_session_result(encoded string) !SessionResult {
	result := json.decode(SessionResult, encoded)!
	fields := json2.decode[map[string]json2.Any](encoded)!
	return SessionResult{
		...result
		session: decode_session((fields['session'] or { return error('missing session') }).json_str())!
		user:    decode_user((fields['user'] or { return error('missing user') }).json_str())!
	}
}

pub fn encode_session(session Session) string {
	return merge_fields(json.encode(session), session.additional_fields)
}

fn encode_internal_session(session Session) string {
	base := encode_session(session)
	return base[..base.len - 1] +
		',"$vSession":{"persistent":${session.persistent},"encryptedToken":${json.encode(session.encrypted_token)}}}'
}

pub fn decode_session(encoded string) !Session {
	session := json.decode(Session, encoded)!
	fields := json2.decode[map[string]json2.Any](encoded)!
	mut additional := map[string]json2.Any{}
	for key, value in fields {
		if key !in core_session_fields { additional[key] = value }
	}
	return Session{
		...session
		additional_fields: additional
		persistent:        if metadata := fields['$vSession'] {
			(metadata.as_map()['persistent'] or { json2.Any(true) }).bool()
		} else {
			session.persistent
		}
		encrypted_token:   if metadata := fields['$vSession'] {
			(metadata.as_map()['encryptedToken'] or { json2.Any('') }).str()
		} else {
			session.encrypted_token
		}
	}
}

fn (a &Auth) session_json(session Session) string {
	mut returned := map[string]json2.Any{}
	for key, value in session.additional_fields {
		if field := a.config.session_fields[key] {
			if field.returned { returned[key] = value }
		}
	}
	return encode_session(Session{ ...session, additional_fields: returned })
}

fn (a &Auth) user_json(user User) string {
	mut returned := map[string]json2.Any{}
	for key, field in a.config.user_fields {
		if value := user.additional_fields[key] {
			if field.returned { returned[key] = value }
		}
	}
	return encode_user(User{ ...user, additional_fields: returned })
}

fn (a &Auth) session_response(result SessionResult) Response {
	if needs := result.needs_refresh {
		return Response{
			headers: [Header{'content-type', 'application/json'},
				Header{'pragma', 'no-cache'}]
			body:    '{"session":${a.session_json(result.session)},"user":${a.user_json(result.user)},"needsRefresh":${needs}}'
		}
	}
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"session":${a.session_json(result.session)},"user":${a.user_json(result.user)}}'
	}
}

pub fn encode_email(message EmailMessage) string {
	return '{"kind":${json.encode(message.kind)},"user":${encode_user(message.user)},"token":${json.encode(message.token)},"url":${json.encode(message.url)},"newEmail":${json.encode(message.new_email)}}'
}

pub fn encode_user_source(source UserInfoSource) string {
	mut encoded := '{"action":${json.encode(source.action)},"method":${json.encode(source.method)}'
	if info := source.oauth {
		encoded += ',"oauth":{"providerId":${json.encode(info.provider_id)},"profile":${json2.Any(info.profile).json_str()}}'
	}
	return encoded + '}'
}

fn validate_field(field AdditionalField, value json2.Any) ! {
	if value is json2.Null {
		if field.required { return fail(400, 'VALIDATION_ERROR', 'Required field cannot be null') }
		return
	}
	valid := match field.field_type {
		'string' {
			value is string
		}
		'number' {
			value is int || value is i64 || value is f64 || value is u64
		}
		'boolean' {
			value is bool
		}
		'date' {
			if value is string {
				time.parse_rfc3339(value) or {
					return fail(400, 'VALIDATION_ERROR', 'Invalid date')
				}
				true
			} else {
				false
			}
		}
		'json' {
			true
		}
		'string[]', 'number[]' {
			if value is []json2.Any {
				for element in value {
					if field.field_type == 'string[]' && element !is string {
						return fail(400, 'VALIDATION_ERROR', 'Invalid array element')
					}
					if field.field_type == 'number[]' && !(element is int
						|| element is i64 || element is f64 || element is u64) {
						return fail(400, 'VALIDATION_ERROR', 'Invalid array element')
					}
				}
				true
			} else {
				false
			}
		}
		else {
			false
		}
	}

	if !valid { return fail(400, 'VALIDATION_ERROR', 'Invalid additional field type') }
}

fn (a &Auth) parse_user_fields(input map[string]json2.Any, existing map[string]json2.Any, creating bool) !map[string]json2.Any {
	return parse_fields(a.config.user_fields, input, existing, creating)
}

fn parse_fields(schema map[string]AdditionalField, input map[string]json2.Any, existing map[string]json2.Any, creating bool) !map[string]json2.Any {
	mut result := existing.clone()
	for key, field in schema {
		if value := input[key] {
			if !field.input {
				if creating {
					if fallback := field.default_value {
						result[key] = fallback
						continue
					}
				}
				if js_truthy(value) {
					return fail(400, 'FIELD_NOT_ALLOWED', '${key} is not allowed to be set')
				}
				continue
			}
			parsed := parse_field_value(field, value)!
			if !parsed.undefined_value { result[key] = parsed.value }
		} else if creating {
			if value := field.default_value {
				validate_field(field, value)!
				result[key] = value
			} else if field.required {
				return fail(400, 'MISSING_FIELD', '${key} is required')
			}
		}
	}
	return result
}

fn js_truthy(value json2.Any) bool {
	return match value {
		json2.Null { false }
		bool { value }
		string { value != '' }
		f64 { value != 0 }
		int { value != 0 }
		i64 { value != 0 }
		u64 { value != 0 }
		else { true }
	}
}
