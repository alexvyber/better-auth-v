module main

import better_auth
import json
import os
import x.json2

fn google_command() ! {
	input := json2.decode[map[string]json2.Any](os.get_raw_line())!
	op := (input['op'] or { json2.Any('') }).str()
	options := (input['options'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	provider := better_auth.GoogleProvider{
		client_id: (options['clientId'] or { json2.Any('') }).str()
		hd:        (options['hd'] or { json2.Any('') }).str()
	}
	token := (input['token'] or { json2.Any('') }).str()
	match op {
		'metadata' {
			println('{"hasHostedDomainVerifier":${provider.hd != ''}}')
		}
		'hosted-domain' {
			println(json.encode(better_auth.google_hosted_domain_allowed(provider.hd, input['claim'] or {
				json2.Any(json2.Null{})
			})))
		}
		'profile' {
			info := provider.user_info(better_auth.OAuthTokens{ id_token: token })!
			if identity := info.value {
				mut user := {
					'name':          json2.Any(identity.name)
					'email':         json2.Any(identity.email)
					'emailVerified': json2.Any(identity.email_verified)
				}
				if image := identity.image { user['image'] = image }
				println(json2.Any({
					'user': json2.Any(user)
					'data': json2.Any(identity.profile)
				}).json_str())
			} else {
				println('null')
			}
		}
		'keys-request' {
			request := better_auth.google_id_token_key_request(token) or {
				println('null')
				return
			}
			println(json.encode(request))
		}
		'verify' {
			audiences :=
				(input['audiences'] or { json2.Any([]json2.Any{}) }).as_array().map(it.str())
			result := better_auth.verify_google_id_token_jwks(token, audiences, (input['nonce'] or {
				json2.Any('')
			}).str(), (input['jwks'] or { json2.Any(map[string]json2.Any{}) }).json_str(), (input['now'] or {
				json2.Any(i64(0))
			}).i64(), false)
			if payload := result.value {
				println(payload)
			} else {
				println('null')
			}
		}
		else {
			return error('unknown Google fixture operation')
		}
	}
}
