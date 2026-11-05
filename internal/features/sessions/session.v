module better_auth

import json
import net.urllib
import x.json2

fn (mut a Auth) make_session(user_id string, ctx RequestContext, remember bool) !Session {
	return a.make_session_overridden(user_id, ctx, remember, map[string]json2.Any{}, false)
}

fn (mut a Auth) make_session_overridden(user_id string, ctx RequestContext, remember bool, overrides map[string]json2.Any, override_all bool) !Session {
	mut arguments := '[${json.encode(user_id)},${!remember}]'
	if overrides.len > 0 {
		arguments = '[${json.encode(user_id)},${!remember},${json2.Any(overrides).json_str()},${override_all}]'
	}
	if encoded := (a.intercept_internal('createSession', arguments)!).value {
		return decode_session(encoded)!
	}

	now := a.clock_millis()
	token := random_token()!
	lifetime := if remember { a.config.session_expires_in } else { i64(86400) }
	session := Session{
		additional_fields: parse_fields(a.config.session_fields, map[string]json2.Any{},
			map[string]json2.Any{}, true)!
		persistent:        remember
		id:                a.new_id('session')!
		user_id:           user_id
		token:             token
		expires_at:        stamp_millis(now + lifetime * 1000)
		created_at:        stamp_millis(now)
		updated_at:        stamp_millis(now)
		// Forwarded headers require explicit opt-in behind a trusted ingress.
		ip_address: if a.config.trust_proxy_ip_headers {
			ctx.headers['x-forwarded-for'].all_before(',').trim_space()
		} else {
			''
		}
		user_agent: ctx.headers['user-agent']
	}
	if overrides.len > 0 {
		mut fields := json2.decode[map[string]json2.Any](encode_session(session))!
		for key, value in overrides {
			if key == 'id' { continue
			 }
			if !override_all {
				if key in ['userId', 'token', 'expiresAt', 'createdAt', 'updatedAt'] { continue
				 }
				if definition := a.config.session_fields[key] {
					if definition.has_default() { continue
					 }
				}
			}
			if key in core_session_fields || key in a.config.session_fields { fields[key] = value }
		}
		actual := decode_session(json2.Any(fields).json_str())!
		return a.persist_session(Session{ ...actual, persistent: remember })
	}
	return a.persist_session(session)
}

fn (mut a Auth) current_session(ctx RequestContext) !Lookup[SessionResult] {
	return a.lookup_session(ctx, true)
}

fn (mut a Auth) lookup_session(ctx RequestContext, delete_expired bool) !Lookup[SessionResult] {
	token := a.context_token(ctx) or { return Lookup[SessionResult]{} }
	found := a.find_session_record(token) or {
		storage := a.storage
		if storage is MongoStorage && storage.managed && err is MongoDriverError {
			if 'TransientTransactionError' in err.labels { return err }
		}
		a.config.log('error', 'Failed to get session: ${err.msg()}')
		return fail(500, 'FAILED_TO_GET_SESSION', 'Failed to get session')
	}
	mut result := found.value or { return Lookup[SessionResult]{} }
	if epoch_millis(result.session.expires_at)! < a.clock_millis() {
		if delete_expired { a.remove_session(token)! }
		return Lookup[SessionResult]{}
	}
	if marker := cookie_values(ctx)[a.cookie_name_for('dont_remember')] {
		if (a.verify_signed_value(marker) or { '' }) == 'true' {
			result = SessionResult{
				...result
				session: Session{
					...result.session
					persistent: false
				}
			}
		}
	}
	return Lookup[SessionResult]{
		value: result
	}
}

fn (mut a Auth) require_session(ctx RequestContext, fresh bool) !SessionResult {
	mut found := Lookup[SessionResult]{}
	if a.config.stateless_sessions && !a.has_secondary() {
		if cached := (a.cached_session(ctx)!).value { found = Lookup[SessionResult]{
				value: cached.result
			} }
	}
	if found.value == none { found = a.current_session(ctx)! }
	result := found.value or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }

	if fresh && a.config.session_fresh_age > 0
		&& a.clock_millis() - epoch_millis(result.session.created_at)! >= a.config.session_fresh_age * 1000 {
		return fail(403, 'SESSION_NOT_FRESH', 'Session is not fresh')
	}
	return result
}

fn (a &Auth) context_token(ctx RequestContext) ?string {
	for plugin in a.config.plugins {
		if plugin.id() == 'bearer' && ctx.headers['authorization'].to_lower().starts_with('bearer ') {
			token := ctx.headers['authorization'][7..].trim_space()
			if token != '' && !token.contains('.') { return token }
			decoded := if token.contains('%') {
				urllib.path_unescape(token) or { token }
			} else {
				token
			}
			if verified := a.verify_cookie(decoded) { return verified }
		}
	}

	for item in ctx.headers['cookie'].split(';') {
		name, raw := item.trim_space().split_once('=') or { continue }
		if name == a.cookie_name() {
			value := urllib.path_unescape(raw) or { return none }
			return a.verify_cookie(value)
		}
	}
	return none
}
