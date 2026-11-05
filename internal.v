module better_auth

import better_auth.schema as model_schema
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
		'adapterQuery' {
			if args.len != 2 { return error('adapterQuery requires operation and query') }
			return c.adapter_query(args[0].str(), args[1].as_map())
		}
		'adapterCreateOrganizationModel' {
			if args.len != 2 { return error('organization model create requires model and record') }
			model := args[0].str()
			organization_model(model)!
			mut fields := args[1].as_map().clone()
			if 'id' !in fields { fields['id'] = c.auth.new_id(model)! }
			data := c.auth.organization_defaults(model, fields)!
			c.organization_create_record(model, data)!
			return json2.Any(data).json_str()
		}
		'adapterDeleteOrganizationModel' {
			if args.len != 2 {
				return error('organization model delete requires model and equality filters')
			}
			model := args[0].str()
			organization_model(model)!
			mut filter := map[string]string{}
			for condition in args[1].as_array() {
				item := condition.as_map()
				field := (item['field'] or { json2.Any('') }).str()
				if field !in ['id', 'organizationId'] || (item['operator'] or { json2.Any('eq') }).str() != 'eq' || (item['connector'] or {
					json2.Any('AND')
				}).str() != 'AND' {
					return error('organization deletion supports scoped ID equalities only')
				}
				if field in filter { return error('duplicate organization filter') }
				filter[field] = (item['value'] or { json2.Any('') }).str()
			}
			if filter.len == 0 { return error('organization deletion requires a scope') }
			rows := c.organization_rows(model, filter)!
			mut storage := c.auth.storage
			if mut storage is OrganizationStorage {
				for encoded in rows {
					storage.organization_delete(model, (org_json_fields(encoded)!['id'] or {
						json2.Any('')
					}).str())!
				}
			}
			return 'null'
		}
		'adapterUpdateVerification' {
			if args.len != 3 || args[0].str() !in ['id', 'identifier'] {
				return error('verification update requires id/identifier equality')
			}
			for record in c.auth.storage.verifications()! {
				value := if args[0].str() == 'id' { record.id } else { record.identifier }
				if value != args[1].str() { continue
				 }
				mut fields := json2.decode[map[string]json2.Any](encode_verification(record))!
				for key, item in args[2].as_map() {
					if key !in ['value', 'expiresAt', 'updatedAt'] {
						return error('unsupported verification update field')
					}
					fields[key] = item
				}
				updated := decode_verification_record(json2.Any(fields).json_str())!
				c.auth.storage.delete_verification(record.id)!
				c.auth.storage.create_verification(updated)!
				return encode_verification(updated)
			}
			return 'null'
		}
		'adapterCreateTwoFactor' {
			if args.len != 1 { return error('two-factor create requires a record') }
			input := json.decode(TwoFactorRecord, args[0].json_str())!
			record := TwoFactorRecord{
				...input
				id: if input.id == '' { c.auth.new_id('twoFactor')! } else { input.id }
			}
			c.save_two_factor(record, true)!
			return encode_two_factor(record)
		}
		'adapterUpdateTwoFactor' {
			if args.len != 3 || args[0].str() !in ['id', 'userId'] {
				return error('two-factor update requires id/userId equality')
			}
			for record in c.two_factors('')! {
				value := if args[0].str() == 'id' { record.id } else { record.user_id }
				if value != args[1].str() { continue
				 }
				mut fields := json2.decode[map[string]json2.Any](json.encode(record))!
				for key, item in args[2].as_map() {
					if key !in ['secret', 'backupCodes', 'verified', 'failedVerificationCount',
						'lockedUntil'] {
						return error('unsupported two-factor update field')
					}
					fields[key] = item
				}
				updated := json.decode(TwoFactorRecord, json2.Any(fields).json_str())!
				c.save_two_factor(updated, false)!
				return encode_two_factor(updated)
			}
			return 'null'
		}
		'setOAuthNonceRequirement' {
			if args.len != 2 { return error('nonce mutation requires provider and boolean') }
			c.auth.oauth_nonce_requirements[args[0].str()] = args[1].bool()
			return 'null'
		}
		'listOAuthProviders' {
			mut values := []json2.Any{}
			for provider in c.auth.config.social_providers {
				mut item := {
					'id': json2.Any(provider.id())
				}
				if provider is OAuthNamedProvider { item['name'] = provider.name() }
				if provider is GenericOAuthProvider {
					item['requiresIdTokenNonce'] = provider.requires_nonce()
					if provider.issuer != '' { item['issuer'] = provider.issuer }
				}
				values << json2.Any(item)
			}
			return json2.Any(values).json_str()
		}
		'createVerificationOTP', 'getVerificationOTP' {
			if args.len != 1 { return error('OTP operation requires one argument') }
			return c.email_otp_internal(name, args[0].json_str())
		}
		'createVerificationValue', 'findVerificationValue', 'consumeVerificationValue',
		'reserveVerificationValue', 'deleteVerificationByIdentifier',
		'updateVerificationByIdentifier' {
			return c.verification_internal(name, args)
		}
		'validateRedirect' {
			if args.len != 1 { return error('validateRedirect requires a callback value') }
			for value in args[0].as_array() {
				if value is json2.Null { continue
				 }
				if value !is string {
					return fail(400, 'VALIDATION_ERROR', 'Redirect parameter must be a string')
				}
				c.validate_redirect(value.str())!
			}
			return 'null'
		}
		'isTrustedOrigin' {
			if args.len != 2 { return error('isTrustedOrigin requires URL and relative-path flag') }
			return json.encode(c.is_trusted_origin(args[0].str(), args[1].bool()))
		}
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
		'getTokenFromContext' {
			if args.len != 1 { return error('getTokenFromContext requires headers') }
			mut headers := map[string]string{}
			for field, value in args[0].as_map() {
				headers[field.to_lower()] = value.str()
			}
			return '{"token":${json.encode(c.get_token(RequestContext{ headers: headers })!)}}'
		}
		'adapterCreateJWK' {
			if args.len != 1 { return error('adapterCreateJWK requires a record') }
			input := json.decode(Jwk, args[0].json_str())!
			key := Jwk{
				...input
				id: if input.id == '' { c.auth.new_id('jwks')! } else { input.id }
			}
			c.auth.storage.create_jwk(key)!
			return json.encode(key)
		}
		'jwkLookup' {
			if args.len != 3 {
				return error('jwkLookup requires a method, value, and default algorithm')
			}
			current := c.auth.jwt_options()!
			options := JWTOptions{
				...current
				algorithm: if args[2].str() != '' { args[2].str() } else { current.algorithm }
			}
			method := args[0].str()
			if method == 'getAllKeys' { return json.encode(c.auth.jwk_records(options)!) }
			key := c.auth.lookup_jwk(options, if method == 'getKeyById' {
				?string(args[1].str())
			} else {
				none
			}, if method == 'getLatestKeyByAlg' { ?string(args[1].str()) } else { none })!
			return if value := key.value { json.encode(value) } else { 'null' }
		}
		'signJWTWith' {
			if args.len != 2 { return error('signJWTWith requires payload and signing config') }
			config := jwt_signing_config_from_json(args[1].json_str())!
			return json.encode(c.sign_jwt_with(args[0].json_str(), config)!)
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
			mut cookies := map[string]json2.Any{}
			for kind, cookie in c.auth.auth_cookie_factory().get_cookies() {
				cookies[kind] = {
					'name':       json2.Any(cookie.name)
					'attributes': json2.Any(cookie.attributes)
				}
			}
			return json2.Any(cookies).json_str()
		}
		'secretConfig' {
			match c.auth.secret_config {
				string { return json.encode(c.auth.secret_config) }
				SecretConfig { return encode_secret_config(c.auth.secret_config) }
			}
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
				...previous
				headers: headers
			}
			defer { c.auth.request_context = previous }
			response := c.auth.dispatch(Request{
				method:  'GET'
				url:     c.auth.base_url() + c.auth.config.base_path + '/get-session?' +
					query.encode()
				headers: headers
			}, '/get-session', Payload{})!
			return json.encode(response)
		}
		'adapterUpdateOrganizationModel' {
			if args.len != 3 {
				return error('organization model update requires model, record id and patch')
			}
			model := args[0].str()
			organization_model(model)!
			encoded := (c.organization_find(model, {
				'id': args[1].str()
			})!).value or { return 'null' }
			mut data := org_json_fields(encoded)!
			patch := args[2].as_map()
			if 'id' in patch { return error('organization model update cannot change identity') }
			for field, value in patch {
				data[field] = value
			}
			proposed := c.auth.organization_defaults(model, data)!
			actual := c.organization_update_record(model, proposed)!
			return json2.Any(actual).json_str()
		}
		'adapterFindOne' {
			if args.len != 1 { return error('adapterFindOne requires a query') }
			query := args[0].as_map()
			filters := (query['where'] or { return error('missing where') }).as_array()
			if filters.len != 1 { return error('unsupported adapter filter') }
			filter := filters[0].as_map()
			model := (query['model'] or { return error('missing model') }).str()
			if model in organization_models {
				if (filter['operator'] or { json2.Any('eq') }).str() != 'eq' {
					return error('organization lookup supports equality only')
				}
				field := (filter['field'] or { return error('missing field') }).str()
				if field !in model_schema.core_fields(model)
					&& field !in c.auth.config.model_fields[model] {
					return error('unknown organization lookup field')
				}
				value := (filter['value'] or { return error('missing value') }).str()
				return (c.organization_find(model, {
					field: value
				})!).value or { 'null' }
			}
			field := (filter['field'] or { return error('missing field') }).str()
			value := (filter['value'] or { return error('missing value') }).str()
			if model == 'session' && field == 'token' {
				if result := (c.auth.find_stored_session(value)!).value {
					return '{"session":${encode_internal_session(result.session)},"user":${encode_user(result.user)}}'
				}
				return 'null'
			}
			if model == 'user' && field == 'id' {
				if user := (c.auth.storage.user(value)!).value { return encode_user(user) }
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
			mut overrides := map[string]json2.Any{}
			if args.len > 2 {
				if args[2] !is json2.Null { overrides = args[2].as_map().clone() }
			}
			all := args.len > 3 && args[3].bool()
			session := c.auth.make_session_overridden(args[0].str(), c.auth.request_context,
				remember, overrides, all)!
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
		'setPassword' {
			if args.len != 2 { return error('setPassword requires password and headers') }
			mut headers := map[string]string{}
			for key, value in args[1].as_map() {
				headers[key.to_lower()] = value.str()
			}
			c.set_password(args[0].str(), RequestContext{ headers: headers })!
			return '{"status":true}'
		}
		'adapterDeleteSession' {
			if args.len != 1 { return error('adapterDeleteSession requires token') }
			if session := (c.auth.stored_session_for_token(args[0].str())!).value {
				c.auth.storage.delete_session(session.id)!
			}
			return 'null'
		}
		'adapterDeleteSessions' {
			if args.len != 1 || args[0] !is string {
				return error('adapterDeleteSessions requires userId')
			}
			user_id := args[0].str()
			mut deleted := 0
			for session in c.auth.storage.sessions(user_id)! {
				if session.user_id == user_id {
					c.auth.storage.delete_session(session.id)!
					deleted++
				}
			}
			return deleted.str()
		}
		'updateAccount' {
			if args.len != 2 { return error('updateAccount requires id and patch') }
			account := (c.auth.storage.account_by_id(args[0].str())!).value or { return 'null' }
			c.auth.update_account_record(account, args[1].json_str())!
			return 'null'
		}
		'findAccounts' {
			return encode_accounts(c.auth.storage.accounts(args[0].str())!)
		}
		'adapterUpdateUser' {
			if args.len != 3 { return error('adapterUpdateUser requires field, value and patch') }
			current := if args[0].str() == 'email' {
				c.auth.storage.user_by_email(args[1].str())!
			} else if args[0].str() == 'id' {
				c.auth.storage.user(args[1].str())!
			} else {
				return error('unsupported user filter')
			}
			user := current.value or { return 'null' }
			updated := decode_user(merge_record_json(encode_user(user), args[2].json_str())!)!
			if updated.id != user.id { return error('cannot change primary key') }
			c.auth.storage.update_user(updated)!
			return encode_user(updated)
		}
		'updatePassword' {
			if args.len != 2 { return error('updatePassword requires user id and password hash') }
			c.auth.update_password(args[0].str(), args[1].str())!
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
					encode_accounts(c.auth.storage.accounts(user.id)!) + '}'
			}
			return 'null'
		}
		'createUser', 'adapterCreateUser' {
			if args.len < 1 { return error('createUser requires user data') }
			mut fields := args[0].as_map()
			if name == 'adapterCreateUser' && (args.len < 2 || !args[1].bool()) {
				fields.delete('id')
			}
			if 'id' !in fields { fields['id'] = c.auth.new_id('user')! }
			if 'createdAt' !in fields { fields['createdAt'] = stamp_millis(c.auth.clock_millis()) }
			if 'updatedAt' !in fields { fields['updatedAt'] = stamp_millis(c.auth.clock_millis()) }
			if name == 'adapterCreateUser' {
				decoded := decode_user(json2.Any(fields).json_str())!
				user := User{
					...decoded
					additional_fields: fill_field_defaults(c.auth.config.user_fields,
						decoded.additional_fields)!
				}
				c.auth.storage.create_user(user)!
				return encode_user(user)
			}
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
				return encode_account(account)
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
			if 'id' !in fields { fields['id'] = c.auth.new_id('account')! }
			account := c.auth.persist_account(decode_account(json2.Any(fields).json_str())!)!
			return encode_account(account)
		}
		else {
			return error('unsupported internal operation: ${name}')
		}
	}
}
