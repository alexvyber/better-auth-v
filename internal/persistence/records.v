module better_auth

import json
import x.json2

fn org_json_fields(encoded string) !map[string]json2.Any {
	return json2.decode[map[string]json2.Any](encoded)
}

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

// Database account DTOs expose nullable token fields consistently across adapters.
// This normalizes output only; sparse hook input and storage patches stay sparse.
pub fn encode_account(account Account) string {
	mut fields := map[string]json2.Any{}
	if account.access_token == none { fields['accessToken'] = json2.Null{} }
	if account.refresh_token == none { fields['refreshToken'] = json2.Null{} }
	if account.access_token_expires_at == none { fields['accessTokenExpiresAt'] = json2.Null{} }
	if account.refresh_token_expires_at == none { fields['refreshTokenExpiresAt'] = json2.Null{} }
	if account.scope == none { fields['scope'] = json2.Null{} }
	return merge_fields(json.encode(account), fields)
}

pub fn encode_accounts(accounts []Account) string {
	return '[' + accounts.map(encode_account(it)).join(',') + ']'
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
