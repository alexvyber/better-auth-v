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

fn validate_oauth_authorization_body(fields map[string]json2.Any) ! {
	if scopes := fields['scopes'] {
		if scopes !is []json2.Any || scopes.as_array().any(it !is string) {
			return fail(400, 'VALIDATION_ERROR', 'scopes must be an array of strings')
		}
	}
	if hint := fields['loginHint'] {
		if hint !is string { return fail(400, 'VALIDATION_ERROR', 'loginHint must be a string') }
	}
	if additional := fields['additionalParams'] {
		if additional !is map[string]json2.Any {
			return fail(400, 'VALIDATION_ERROR', 'additionalParams must be an object')
		}
		for name, value in additional.as_map() {
			if value !is string {
				return fail(400, 'VALIDATION_ERROR', 'additionalParams values must be strings')
			}
			if name in reserved_authorization_params {
				return fail(400, 'VALIDATION_ERROR',
					'additionalParams cannot include reserved OAuth parameters: ' +
					reserved_authorization_params.join(','))
			}
		}
	}
}
