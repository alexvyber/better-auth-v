module better_auth

import json
import net.urllib
import x.json2

fn (mut a Auth) intercept_internal(name string, arguments_json string) !Lookup[string] {
	if a.config.internal_interceptor == pass_internal_operation || name in a.intercepting {
		return Lookup[string]{}
	}
	a.intercepting[name] = true
	defer { a.intercepting.delete(name) }
	mut context := EndpointContext{
		auth: a
	}
	result := a.config.internal_interceptor(mut context, InternalOperation{
		name:           name
		arguments_json: arguments_json
	})!
	return if result.handled {
		Lookup[string]{
			value: result.value_json
		}
	} else {
		Lookup[string]{}
	}
}

pub fn (mut c EndpointContext) invoke_internal(name string, arguments_json string) !string {
	args := json2.decode[[]json2.Any](arguments_json)!
	match name {
		'verifyCookieJWT' {
			if args.len != 1 { return error('verifyCookieJWT requires a token') }
			if !c.auth.jwks_cache_enabled() {
				return error('local JWKS cookie signing is not configured')
			}
			cached := c.auth.decode_cookie_cache(args[0].str()) or { return 'null' }
			payload := c.auth.verify_jwks_payload(args[0].str(), true, '') or { return 'null' }
			return '{"payload":${js_json(json2.Any(payload))},"expiresAt":${cached.expires_at}}'
		}
		'generateJWK' {
			options := c.auth.jwt_options()!
			public, private := generate_exported_keypair(options)!
			return '{"publicWebKey":${public},"privateWebKey":${private},"alg":${json.encode(options.algorithm)}}'
		}
		'signJWT' {
			if args.len != 1 { return error('signJWT requires a payload') }
			return '{"token":${json.encode(c.sign_jwt(args[0].json_str())!)}}'
		}
		'verifyJWT' {
			if args.len < 1 { return error('verifyJWT requires a token') }
			issuer := if args.len > 1 { args[1].str() } else { '' }
			payload := c.auth.verify_jwks_payload(args[0].str(), false, issuer) or {
				return '{"payload":null}'
			}
			return '{"payload":${js_json(json2.Any(payload))}}'
		}
		'cookieInfo' {
			return '{"sessionToken":{"name":${json.encode(c.auth.cookie_name())}},"sessionData":{"name":${json.encode(c.auth.cache_cookie_name())}}}'
		}
		'sessionFromContext' {
			if args.len < 3 {
				return error('sessionFromContext requires headers, query, and strictness')
			}
			mut headers := map[string]string{}
			for key, value in args[0].as_map() {
				headers[key.to_lower()] = value.str()
			}
			mut query := urllib.new_values()
			for key, value in args[1].as_map() {
				query.set(key, value.str())
			}
			if args[2].bool() {
				// A strict caller owns this choice. Caller-controlled query flags
				// cannot re-enable stale cookies when a durable store is configured.
				stateful := !c.auth.config.stateless_sessions || c.auth.has_secondary()
				query.set('disableCookieCache', stateful.str())
			}
			previous := c.auth.request_context
			c.auth.request_context = RequestContext{
				headers: headers
			}
			defer { c.auth.request_context = previous }
			response := c.auth.dispatch(Request{
				method:  'GET'
				url:     c.auth.config.base_url + c.auth.config.base_path + '/get-session?' +
					query.encode()
				headers: headers
			}, '/get-session', Payload{})!
			return json.encode(response)
		}
		'adapterFindOne' {
			if args.len != 1 { return error('adapterFindOne requires a query') }
			query := args[0].as_map()
			filters := (query['where'] or { return error('missing where') }).as_array()
			if filters.len != 1 { return error('unsupported adapter filter') }
			filter := filters[0].as_map()
			model := (query['model'] or { return error('missing model') }).str()
			field := (filter['field'] or { return error('missing field') }).str()
			value := (filter['value'] or { return error('missing value') }).str()
			if model == 'session' && field == 'token' {
				if result := (c.auth.find_stored_session(value)!).value {
					return '{"session":${encode_internal_session(result.session)},"user":${encode_user(result.user)}}'
				}
				return 'null'
			}
			if model == 'user' && field == 'email' {
				if user := (c.auth.find_user_by_email(value)!).value { return encode_user(user) }
				return 'null'
			}
			return error('unsupported adapter model or filter')
		}
		'adapterUpdateSession' {
			if args.len < 2 { return error('adapterUpdateSession requires an id and update') }
			if session := (c.adapter_update_session(args[0].str(), args[1].json_str())!).value {
				return encode_internal_session(session)
			}
			return 'null'
		}
		'createSession' {
			if args.len < 1 { return error('createSession requires a user id') }
			remember := if args.len > 1 { !args[1].bool() } else { true }
			session := c.auth.make_session(args[0].str(), c.auth.request_context, remember)!
			return encode_internal_session(session)
		}
		'findSession' {
			if args.len < 1 { return error('findSession requires a token') }
			if result := (c.auth.find_session_record(args[0].str())!).value {
				return '{"session":' + encode_internal_session(result.session) + ',"user":' +
					c.auth.user_json(result.user) + '}'
			}
			return 'null'
		}
		'listSessions' {
			if args.len < 1 { return error('listSessions requires a user id') }
			sessions := c.auth.user_sessions(args[0].str())!
			return '[' + sessions.map(encode_internal_session(it)).join(',') + ']'
		}
		'deleteSession' {
			if args.len < 1 { return error('deleteSession requires a token') }
			c.auth.remove_session(args[0].str())!
			return 'null'
		}
		'deleteUserSessions' {
			if args.len < 1 { return error('deleteUserSessions requires a user id') }
			c.auth.remove_user_sessions(args[0].str(), '')!
			return 'null'
		}
		'updateSession' {
			if args.len < 2 { return error('updateSession requires a token and update') }
			current := (c.auth.find_session_record(args[0].str())!).value or { return 'null' }
			merged := merge_record_json(encode_session(current.session), args[1].json_str())!
			decoded := decode_session(merged)!
			updated := c.auth.update_session_record(Session{
				...decoded
				persistent:      current.session.persistent
				encrypted_token: current.session.encrypted_token
			})!
			return encode_internal_session(updated)
		}
		'findUserById' {
			if args.len < 1 { return error('findUserById requires an id') }
			if user := (c.auth.storage.user(args[0].str())!).value { return encode_user(user) }
			return 'null'
		}
		'findUserByEmail' {
			if args.len < 1 { return error('findUserByEmail requires an email') }
			if user := (c.auth.storage.user_by_email(args[0].str())!).value {
				return '{"user":' + encode_user(user) + ',"accounts":' +
					json.encode(c.auth.storage.accounts(user.id)!) + '}'
			}
			return 'null'
		}
		'createUser' {
			if args.len < 1 { return error('createUser requires user data') }
			mut fields := args[0].as_map()
			if 'id' !in fields { fields['id'] = random_token()! }
			if 'createdAt' !in fields { fields['createdAt'] = stamp(c.auth.config.clock()) }
			if 'updatedAt' !in fields { fields['updatedAt'] = stamp(c.auth.config.clock()) }
			user := c.auth.persist_user(decode_user(json2.Any(fields).json_str())!)!
			return encode_user(user)
		}
		'updateUser' {
			if args.len < 2 { return error('updateUser requires an id and update') }
			current := (c.auth.storage.user(args[0].str())!).value or { return 'null' }
			updated := c.auth.update_user_record(decode_user(merge_record_json(encode_user(current),
				args[1].json_str())!)!)!
			return encode_user(updated)
		}
		'findCredentialAccount' {
			if args.len < 1 { return error('findCredentialAccount requires a user id') }
			if account := (c.auth.storage.account(args[0].str(), 'credential')!).value {
				return json.encode(account)
			}
			return 'null'
		}
		'deleteAccount' {
			if args.len < 1 { return error('deleteAccount requires an id') }
			c.auth.remove_account(args[0].str())!
			return 'null'
		}
		'createAccount' {
			if args.len < 1 { return error('createAccount requires account data') }
			mut fields := args[0].as_map()
			if 'id' !in fields { fields['id'] = random_token()! }
			account := c.auth.persist_account(decode_account(json2.Any(fields).json_str())!)!
			return json.encode(account)
		}
		else {
			return error('unsupported internal operation: ${name}')
		}
	}
}
