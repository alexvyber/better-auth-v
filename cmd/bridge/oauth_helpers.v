module main

import better_auth
import json
import os
import x.json2

fn oauth_helper_command() ! {
	fields := json2.decode[map[string]json2.Any](os.get_raw_line())!
	op := (fields['op'] or { json2.Any('') }).str()
	match op {
		'reserved' {
			println(json.encode(better_auth.reserved_authorization_params))
		}
		'form-encode' {
			println(json.encode(better_auth.oauth_form_encode((fields['value'] or { json2.Any('') }).str())))
		}
		'form-decode' {
			println(json.encode(better_auth.oauth_form_decode((fields['value'] or { json2.Any('') }).str())))
		}
		'basic-encode' {
			println(json.encode(better_auth.encode_basic_credentials((fields['clientId'] or {
				json2.Any('')
			}).str(), (fields['clientSecret'] or { json2.Any('') }).str())))
		}
		'basic-decode' {
			println(json.encode(better_auth.decode_basic_credentials((fields['authorization'] or {
				json2.Any('')
			}).str())!))
		}
		'authorization-url' {
			mut input := (fields['input'] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
			mut options :=
				(input['options'] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
			client := options['clientId'] or { json2.Any('') }
			primary := if client is []json2.Any {
				if client.len > 0 { client[0] } else { json2.Any('') }
			} else {
				client
			}
			options['clientId'] = if primary is string { primary } else { json2.Any('') }
			input['options'] = options
			request := json.decode(better_auth.OAuthAuthorizationRequest,
				json2.Any(input).json_str())!
			println(json.encode(better_auth.create_oauth_authorization_url(request)!))
		}
		else {
			return error('unknown OAuth helper operation')
		}
	}
}
