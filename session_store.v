module better_auth

import json
import x.json2

struct SessionReference {
	token      string
	expires_at i64 @[json: 'expiresAt']
}

fn (a &Auth) has_secondary() bool {
	return a.secondary !is NoSecondaryStorage
}

fn (a &Auth) database_sessions() bool {
	return !a.has_secondary() || a.config.store_session_in_database
}

fn (a &Auth) database_fallback() bool {
	return a.has_secondary() && a.config.store_session_in_database
		&& !a.config.preserve_session_in_database
}

fn (mut a Auth) persist_session(session Session) !Session {
	mut context := EndpointContext{
		auth: a
	}
	for plugin in a.config.plugins {
		if plugin is SessionCreationPlugin { plugin.before_session(mut context, session)! }
	}
	encoded := (a.before_record('session', 'create', encode_session(session))!).value or {
		return fail(400, 'FAILED_TO_CREATE_SESSION', 'Failed to create session')
	}

	decoded := decode_session(encoded)!
	mut actual := Session{
		...decoded
		persistent: session.persistent
	}
	if a.database_sessions() {
		actual = Session{
			...actual
			encrypted_token: a.seal_session_token(actual)!
		}
		a.storage.create_session(actual, digest(actual.token))!
	}
	if a.has_secondary() {
		if a.database_fallback() {
			a.queue_task(AfterCommitTask{ kind: 'mirror-session', session: actual })!
		} else {
			if a.transaction_active && a.transactions_enabled { a.secondary_created << actual }
			a.mirror_session(actual)!
		}
	}
	a.after_record('session', 'create', encode_session(actual))!
	return actual
}

fn (mut a Auth) cache_references(user_id string) ![]SessionReference {
	encoded := (a.secondary.get('active-sessions-' + user_id)!).value or {
		return []SessionReference{}
	}

	return json.decode([]SessionReference, encoded) or { []SessionReference{} }
}

fn (mut a Auth) mirror_session(session Session) ! {
	now := a.clock_millis()
	expires := epoch_millis(session.expires_at)!
	if expires <= now { return }
	user := (a.storage.user(session.user_id)!).value or { return }
	mut references := []SessionReference{}
	for reference in a.cache_references(session.user_id)! {
		if reference.expires_at > now && reference.token != session.token { references << reference }
	}
	references << SessionReference{
		token:      session.token
		expires_at: expires
	}
	references.sort(a.expires_at < b.expires_at)
	index_ttl := (references.last().expires_at - now) / 1000
	if index_ttl > 0 {
		a.secondary.set('active-sessions-' + session.user_id, json.encode(references), index_ttl)!
	}
	encoded := '{"session":${encode_session(session)},"user":${encode_user(user)},"persistent":${session.persistent}}'
	session_ttl := (expires - now) / 1000
	if session_ttl > 0 { a.secondary.set(session.token, encoded, session_ttl)! }
}

fn (mut a Auth) remove_cached_session(session Session) ! {
	if !a.has_secondary() { return }
	now := a.clock_millis()
	mut references := []SessionReference{}
	for reference in a.cache_references(session.user_id)! {
		if reference.token != session.token && reference.expires_at > now { references << reference }
	}
	if references.len == 0 {
		a.secondary.delete('active-sessions-' + session.user_id)!
	} else {
		references.sort(a.expires_at < b.expires_at)
		a.secondary.set('active-sessions-' + session.user_id, json.encode(references),
			(references.last().expires_at - now) / 1000)!
	}
	a.secondary.delete(session.token)!
}

fn (mut a Auth) find_session_record(token string) !Lookup[SessionResult] {
	if encoded := (a.intercept_internal('findSession', '[${json.encode(token)}]')!).value {
		if encoded == 'null' { return Lookup[SessionResult]{} }
		return Lookup[SessionResult]{
			value: decode_session_result(encoded)!
		}
	}

	if a.has_secondary() {
		if encoded := (a.secondary.get(token)!).value {
			result := decode_session_result(encoded) or { return Lookup[SessionResult]{} }
			fields := json2.decode[map[string]json2.Any](encoded) or {
				return Lookup[SessionResult]{}
			}
			persistent := if value := fields['persistent'] { value.bool() } else { true }
			if result.session.token != token { return Lookup[SessionResult]{} }
			return Lookup[SessionResult]{
				value: SessionResult{
					...result
					session: Session{
						...result.session
						persistent: persistent
					}
				}
			}
		}
		if !a.database_fallback() { return Lookup[SessionResult]{} }
	}
	return a.find_stored_session(token)
}

fn (mut a Auth) find_stored_session(token string) !Lookup[SessionResult] {
	query := '{"model":"session","where":[{"field":"token","value":${json.encode(token)}}]}'
	if encoded := (a.intercept_internal('adapter.findOne', '[${query}]')!).value {
		if encoded == 'null' { return Lookup[SessionResult]{} }
		return Lookup[SessionResult]{
			value: decode_session_result(encoded)!
		}
	}
	session := (a.stored_session_for_token(token)!).value or { return Lookup[SessionResult]{} }
	user := (a.storage.user(session.user_id)!).value or { return Lookup[SessionResult]{} }
	return Lookup[SessionResult]{
		value: SessionResult{
			user:    user
			session: Session{
				...session
				token: token
			}
		}
	}
}

fn (mut a Auth) find_user_by_email(email string) !Lookup[User] {
	query := '{"model":"user","where":[{"field":"email","value":${json.encode(email)}}]}'
	if encoded := (a.intercept_internal('adapter.findOne', '[${query}]')!).value {
		if encoded == 'null' { return Lookup[User]{} }
		return Lookup[User]{
			value: decode_user(encoded)!
		}
	}
	return a.storage.user_by_email(email)
}

fn (mut a Auth) user_sessions(user_id string) ![]Session {
	if encoded := (a.intercept_internal('listSessions', '[${json.encode(user_id)}]')!).value {
		values := json2.decode[[]json2.Any](encoded)!
		mut sessions := []Session{}
		for value in values {
			sessions << decode_session(value.json_str())!
		}
		return sessions
	}

	mut sessions := []Session{}
	if !a.has_secondary() || a.database_fallback() {
		for stored in a.storage.sessions(user_id)! {
			if epoch_millis(stored.expires_at)! <= a.clock_millis() { continue
			 }
			token := if stored.encrypted_token != '' {
				a.unseal_session_token(stored)!
			} else if a.plain_database_session_tokens() {
				stored.token
			} else {
				stored.id
			}
			sessions << Session{
				...stored
				token: token
			}
		}
		return sessions
	}
	mut seen := map[string]bool{}
	for reference in a.cache_references(user_id)! {
		if reference.expires_at <= a.clock_millis() || reference.token in seen { continue
		 }
		seen[reference.token] = true
		if result := (a.find_session_record(reference.token)!).value {
			if result.session.user_id == user_id
				&& epoch_millis(result.session.expires_at)! > a.clock_millis() {
				sessions << result.session
			}
		}
	}
	return sessions
}

fn (mut a Auth) remove_session(token string) ! {
	if _ := (a.intercept_internal('deleteSession', '[${json.encode(token)}]')!).value { return }

	result := (a.find_session_record(token)!).value or { return }
	a.remove_session_row(result.session)!
}

fn (mut a Auth) remove_session_row(session Session) ! {
	if (a.before_record('session', 'delete', encode_session(session))!).value == none { return }
	if a.has_secondary() {
		if a.database_fallback() {
			a.queue_task(AfterCommitTask{ kind: 'remove-session', session: session })!
		} else {
			a.remove_cached_session(session)!
		}
	}
	if a.database_sessions() {
		if a.has_secondary() && a.config.preserve_session_in_database {
			if epoch_millis(session.expires_at)! > a.clock_millis() { a.storage.update_session(Session{
					...session
					expires_at: stamp_millis(a.clock_millis())
				})! }
		} else {
			a.storage.delete_session(session.id)!
		}
	}
	a.after_record('session', 'delete', encode_session(session))!
}

fn (mut a Auth) remove_user_sessions(user_id string, except_id string) ! {
	if except_id == '' {
		if _ := (a.intercept_internal('deleteUserSessions', '[${json.encode(user_id)}]')!).value {
			return
		}
	}

	for session in a.user_sessions(user_id)! {
		if session.id != except_id { a.remove_session_row(session)! }
	}
}

fn (mut a Auth) update_session_record(session Session) !Session {
	if encoded := (a.intercept_internal('updateSession',
		'[${json.encode(session.token)},${encode_session(session)}]')!).value
	{
		if encoded == 'null' {
			if a.config.stateless_sessions && !a.has_secondary() { return session }
			return fail(401, 'FAILED_TO_GET_SESSION', 'Failed to get session')
		}
		return decode_session(encoded)!
	}

	encoded := (a.before_record('session', 'update', encode_session(session))!).value or {
		return session
	}

	updated := decode_session(encoded)!
	actual := Session{
		...updated
		persistent:      session.persistent
		encrypted_token: session.encrypted_token
	}
	if actual.id != session.id || actual.token != session.token || actual.user_id != session.user_id {
		return error('session update hook cannot change identity')
	}
	if a.database_sessions() { a.storage.update_session(actual)! }
	if a.has_secondary() { a.mirror_session(actual)! }
	a.after_record('session', 'update', encode_session(actual))!
	return actual
}

fn (mut a Auth) refresh_cached_user(user User) ! {
	if !a.has_secondary() { return }
	for reference in a.cache_references(user.id)! {
		if reference.expires_at <= a.clock_millis() { continue
		 }
		if result := (a.find_session_record(reference.token)!).value {
			a.mirror_session(result.session)!
		}
	}
}

fn (a &Auth) plain_database_session_tokens() bool {
	if a.storage is PlainSessionTokenStorage { return a.storage.stores_plain_session_tokens() }
	return false
}

fn (mut a Auth) stored_session_for_token(token string) !Lookup[Session] {
	mut storage := a.storage
	if mut storage is TokenLookupStorage { return storage.session_by_token(token) }
	return storage.session(digest(token))
}
