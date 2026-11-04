module better_auth

import math
import strconv
import x.json2

// Dates cross a platform boundary as clipped epoch milliseconds (null denotes
// an Invalid Date), while provider fields and raw code responses retain shape.
pub fn normalize_oauth_token_response(encoded string, grant_type string, now_millis i64) !string {
	fields := json2.decode[map[string]json2.Any](encoded)!
	mut result := map[string]json2.Any{}
	for source, target in {
		'access_token': 'accessToken'
		'token_type':   'tokenType'
	} {
		if value := fields[source] { result[target] = value }
	}
	if grant_type != 'client_credentials' {
		for source, target in {
			'refresh_token': 'refreshToken'
			'id_token':      'idToken'
		} {
			if value := fields[source] { result[target] = value }
		}
		result['scopes'] =
			oauth_scope_field(fields['scope'] or { json2.Any(json2.Null{}) }).map(json2.Any(it))
	} else if scope := fields['scope'] {
		if scope !is json2.Null {
			if scope !is string {
				return error('provider scope must be a string for client_credentials')
			}
			result['scopes'] = scope.str().split(' ').map(json2.Any(it))
		}
	}
	mut expiries := {
		'expires_in': 'accessTokenExpiresAt'
	}
	if grant_type != 'client_credentials' {
		expiries['refresh_token_expires_in'] = 'refreshTokenExpiresAt'
	}
	for source, target in expiries {
		if value := fields[source] {
			if !js_truthy(value) { continue
			 }
			number := if value is bool {
				f64(1)
			} else if value is string {
				if value.trim_space() == '' { f64(0) } else { strconv.atof64(value.trim_space()) or {
						math.nan()} }
			} else if value is int || value is i64 || value is f64 {
				value.f64()
			} else {
				math.nan()
			}
			millis := f64(now_millis) + number * 1000
			result[target] = if math.is_nan(millis) || math.is_inf(millis, 0)
				|| math.abs(millis) > 8640000000000000 {
				json2.Any(json2.Null{})
			} else {
				json2.Any(i64(millis))
			}
		}
	}
	if grant_type == 'authorization_code' { result['raw'] = fields }
	return json2.Any(result).json_str()
}
