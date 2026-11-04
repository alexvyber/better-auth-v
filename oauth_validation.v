module better_auth

import x.json2

fn validate_direct_id_token_body(fields map[string]json2.Any) ! {
	value := fields['idToken'] or { return }
	if value !is map[string]json2.Any {
		return fail(400, 'VALIDATION_ERROR', 'idToken must be an object')
	}
	token := value.as_map()
	if (token['token'] or { json2.Any(json2.Null{}) }) !is string {
		return fail(400, 'VALIDATION_ERROR', 'idToken.token must be a string')
	}
	for key in ['nonce', 'accessToken', 'refreshToken'] {
		if item := token[key] {
			if item !is string { return fail(400, 'VALIDATION_ERROR', 'Invalid idToken field') }
		}
	}
	if expires := token['expiresAt'] {
		if expires !is int && expires !is i64 && expires !is f64 {
			return fail(400, 'VALIDATION_ERROR', 'Invalid idToken expiresAt')
		}
	}
	if user := token['user'] {
		if user !is map[string]json2.Any {
			return fail(400, 'VALIDATION_ERROR', 'Invalid idToken user')
		}
		data := user.as_map()
		if email := data['email'] {
			if email !is string {
				return fail(400, 'VALIDATION_ERROR', 'Invalid idToken user email')
			}
		}
		if name := data['name'] {
			if name !is map[string]json2.Any {
				return fail(400, 'VALIDATION_ERROR', 'Invalid idToken user name')
			}
			for key in ['firstName', 'lastName'] {
				if part := name.as_map()[key] {
					if part !is string {
						return fail(400, 'VALIDATION_ERROR', 'Invalid idToken user name')
					}
				}
			}
		}
	}
}
