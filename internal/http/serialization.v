module better_auth

import x.json2

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
