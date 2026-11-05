module better_auth

import x.json2

pub struct OpenAPIOptions {
pub:
	path                      string = '/reference'
	disable_default_reference bool @[json: disableDefaultReference]
	theme                     string = 'default'
	nonce                     string
}

pub struct OpenAPIPlugin {
pub:
	options OpenAPIOptions
}

pub fn (_ OpenAPIPlugin) id() string {
	return 'open-api'
}

pub fn (_ OpenAPIPlugin) schema() PluginFields {
	return PluginFields{}
}

pub fn (plugin OpenAPIPlugin) endpoints() []Endpoint {
	return [
		Endpoint{
			path:    '/open-api/generate-schema'
			method:  'GET'
			handler: openapi_endpoint
		},
		Endpoint{
			path:    plugin.options.path
			method:  'GET'
			handler: openapi_reference
		},
	]
}

fn openapi_type(field AdditionalField, model bool) map[string]json2.Any {
	mut schema := map[string]json2.Any{}
	match field.field_type {
		'date' {
			schema['type'] = 'string'
			schema['format'] = 'date-time'
		}
		'json' {}
		'string[]', 'number[]' {
			schema['type'] = 'array'
			schema['items'] = json2.Any({
				'type': json2.Any(field.field_type.all_before('['))
			})
		}
		else {
			schema['type'] = field.field_type
		}
	}

	if value := field.default_value { schema['default'] = value }
	if model && !field.input { schema['readOnly'] = true }
	return schema
}

fn openapi_ref(model string) json2.Any {
	return json2.Any({
		'$ref': json2.Any('#/components/schemas/' + model)
	})
}

fn openapi_core_fields(model string) map[string]AdditionalField {
	mut result := map[string]AdditionalField{}
	for name in postgres_core_fields[model] {
		if name == 'id' { continue
		 }
		date := name in ['createdAt', 'updatedAt', 'expiresAt', 'accessTokenExpiresAt',
			'refreshTokenExpiresAt']
		protected := name in ['token', 'userId', 'emailVerified', 'createdAt', 'updatedAt',
			'expiresAt', 'accessToken', 'refreshToken', 'idToken', 'password']
		required := name in ['name', 'email', 'emailVerified', 'createdAt', 'updatedAt', 'expiresAt',
			'token', 'userId', 'accountId', 'providerId', 'identifier', 'value', 'organizationId',
			'role', 'slug', 'status', 'inviterId', 'permission']
		result[name] = AdditionalField{
			field_type: if date {
				'date'
			} else if name == 'emailVerified' {
				'boolean'
			} else {
				'string'
			}
			input:      !protected
			required:   required
		}
	}
	if model == 'user' { result['emailVerified'] = AdditionalField{
			field_type:    'boolean'
			input:         false
			required:      true
			default_value: json2.Any(false)
		} }
	return result
}

fn openapi_model(model string, additional map[string]AdditionalField) json2.Any {
	mut properties := {
		'id': json2.Any({
			'type':     json2.Any('string')
			'readOnly': json2.Any(true)
		})
	}
	mut required := [json2.Any('id')]
	mut fields := openapi_core_fields(model)
	for name, definition in additional {
		fields[name] = definition
	}
	for name, definition in fields {
		properties[name] = json2.Any(openapi_type(definition, true))
		if definition.required && definition.returned { required << json2.Any(name) }
	}
	return json2.Any({
		'type':       json2.Any('object')
		'properties': json2.Any(properties)
		'required':   json2.Any(required)
	})
}

fn openapi_body(fields map[string]json2.Any, required []json2.Any) json2.Any {
	return json2.Any({
		'required': json2.Any(true)
		'content':  json2.Any({
			'application/json': json2.Any({
				'schema': json2.Any({
					'type':       json2.Any('object')
					'properties': json2.Any(fields)
					'required':   json2.Any(required)
				})
			})
		})
	})
}

fn (auth &Auth) openapi_core_operation(path string, method string) !map[string]json2.Any {
	mut properties := map[string]json2.Any{}
	mut required := []json2.Any{}
	mut names := []string{}
	mut mandatory := []string{}
	match path {
		'/sign-up/email' {
			names = ['name', 'email', 'password', 'image', 'rememberMe', 'callbackURL']
			mandatory = ['name', 'email', 'password']
		}
		'/sign-in/email' {
			names = ['email', 'password', 'rememberMe', 'callbackURL']
			mandatory = ['email', 'password']
		}
		'/update-user' {
			names = ['name', 'image']
		}
		'/sign-in/social' {
			names = ['provider', 'callbackURL', 'errorCallbackURL', 'newUserCallbackURL',
				'disableRedirect', 'scopes', 'idToken', 'requestSignUp']
			mandatory = ['provider']
		}
		'/change-email' {
			names = ['newEmail', 'callbackURL']
			mandatory = ['newEmail']
		}
		'/change-password' {
			names = ['currentPassword', 'newPassword', 'revokeOtherSessions']
			mandatory = ['currentPassword', 'newPassword']
		}
		'/verify-password' {
			names = ['password']
			mandatory = ['password']
		}
		'/revoke-session' {
			names = ['token']
			mandatory = ['token']
		}
		'/reset-password' {
			names = ['newPassword', 'token']
			mandatory = ['newPassword']
		}
		'/request-password-reset', '/send-verification-email' {
			names = ['email', 'callbackURL']
			mandatory = ['email']
		}
		'/delete-user' {
			names = ['password', 'token', 'callbackURL']
		}
		else {}
	}

	for name in names {
		kind := if name in ['rememberMe', 'disableRedirect', 'requestSignUp', 'revokeOtherSessions'] {
			'boolean'
		} else if name == 'idToken' {
			'object'
		} else if name == 'scopes' {
			'array'
		} else {
			'string'
		}
		mut schema := {
			'type': json2.Any(kind)
		}
		if kind == 'array' { schema['items'] = json2.Any({
				'type': json2.Any('string')
			}) }
		if name == 'idToken' {
			mut token_fields := map[string]json2.Any{}
			for token_field in ['token', 'nonce', 'accessToken', 'refreshToken'] {
				token_fields[token_field] = json2.Any({
					'type': json2.Any('string')
				})
			}
			token_fields['expiresAt'] = json2.Any({
				'type': json2.Any('number')
			})
			schema['properties'] = json2.Any(token_fields)
			schema['required'] = json2.Any([json2.Any('token')])
		}
		properties[name] = json2.Any(schema)
		if name in mandatory { required << json2.Any(name) }
	}
	if path in ['/sign-up/email', '/update-user'] {
		for name, field in auth.config.user_fields {
			if !field.input { continue
			 }
			properties[name] = json2.Any(openapi_type(field, false))
			if path == '/sign-up/email' && field.required && !field.has_default() {
				required << json2.Any(name)
			}
		}
	}
	mut response_schema := json2.Any(map[string]json2.Any{})
	if path == '/get-session' {
		response_schema = json2.Any({
			'type':       json2.Any([json2.Any('object'), json2.Any('null')])
			'properties': json2.Any({
				'user':    openapi_ref('User')
				'session': openapi_ref('Session')
			})
			'required':   json2.Any([json2.Any('user'), json2.Any('session')])
		})
	}

	if path == '/sign-in/social' {
		response_schema = json2.Any({
			'type':       json2.Any('object')
			'properties': json2.Any({
				'redirect': json2.Any({
					'type': json2.Any('boolean')
				})
				'token':    json2.Any({
					'type': json2.Any('string')
				})
				'url':      json2.Any({
					'type': json2.Any('string')
				})
				'user':     openapi_ref('User')
			})
			'required':   json2.Any([json2.Any('redirect')])
		})
	}
	mut segments := path.trim('/').replace('/', '-').split('-')
	mut operation_id := segments[0]
	for word in segments[1..] {
		if word != '' { operation_id += word[..1].to_upper() + word[1..] }
	}
	if (core_routes()[path] or { []string{} }).len > 1 && method != 'GET' {
		operation_id += method[..1].to_upper() + method[1..].to_lower()
	}

	mut operation := {
		'operationId': json2.Any(operation_id)
		'responses':   json2.Any({
			'200': json2.Any({
				'description': json2.Any('Success')
				'content':     json2.Any({
					'application/json': json2.Any({
						'schema': response_schema
					})
				})
			})
		})
	}
	if method == 'POST' && properties.len > 0 {
		operation['requestBody'] = openapi_body(properties, required)
	}
	if method == 'GET' && path == '/get-session' {
		operation['parameters'] = json2.Any(['disableCookieCache', 'disableRefresh'].map(json2.Any({
			'name':     json2.Any(it)
			'in':       json2.Any('query')
			'required': json2.Any(false)
			'schema':   json2.Any({
				'type': json2.Any('boolean')
			})
		})))
	}
	return operation
}

// Configuration-only generation: no stored users, tokens, secrets or hook calls.
pub fn (auth &Auth) generate_openapi_schema() !string {
	mut schemas := map[string]json2.Any{}
	schemas['User'] = openapi_model('user', auth.config.user_fields)
	schemas['Session'] = openapi_model('session', auth.config.session_fields)
	schemas['Account'] = openapi_model('account', {})
	schemas['Verification'] = openapi_model('verification', {})
	for plugin in auth.config.plugins {
		if plugin.id() == 'organization' {
			for model in organization_models {
				schemas[model[..1].to_upper() + model[1..]] = openapi_model(model, auth.config.model_fields[model] or {
					map[string]AdditionalField{}
				})
			}
		}
		if plugin.id() == 'jwt' { schemas['Jwks'] = openapi_model('jwks', {}) }
	}
	mut paths := map[string]json2.Any{}
	mut used_ids := map[string]bool{}
	for path, methods in core_routes() {
		mut operations := map[string]json2.Any{}
		for method in methods {
			mut operation := auth.openapi_core_operation(path, method)!
			openapi_unique_id(mut operation, mut used_ids)
			operations[method.to_lower()] = json2.Any(operation)
		}
		paths[path] = json2.Any(operations)
	}
	for plugin in auth.config.plugins {
		for endpoint in plugin.endpoints() {
			if endpoint.hide_from_docs || endpoint.path.starts_with('/internal/') || (plugin is OpenAPIPlugin && endpoint.path == plugin.options.path) { continue
			 }
			mut operations :=
				(paths[endpoint.path] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
			mut operation := auth.openapi_core_operation(endpoint.path, endpoint.method)!
			if endpoint.openapi_metadata != '' {
				for name, value in json2.decode[map[string]json2.Any](endpoint.openapi_metadata)! {
					operation[name] = value
				}
			}
			openapi_unique_id(mut operation, mut used_ids)
			operations[endpoint.method.to_lower()] = json2.Any(operation)
			paths[endpoint.path] = json2.Any(operations)
		}
	}
	return json2.Any({
		'openapi':    json2.Any('3.1.1')
		'info':       json2.Any({
			'title':       json2.Any('Better Auth')
			'description': json2.Any('API Reference for your Better Auth Instance')
			'version':     json2.Any('1.1.0')
		})
		'servers':    json2.Any([
			json2.Any({
				'url': json2.Any(auth.config.base_url.trim_right('/') + auth.config.base_path)
			}),
		])
		'components': json2.Any({
			'schemas':         json2.Any(schemas)
			'securitySchemes': json2.Any({
				'apiKeyCookie': json2.Any({
					'type': json2.Any('apiKey')
					'in':   json2.Any('cookie')
					'name': json2.Any(auth.cookie_name())
				})
				'bearerAuth':   json2.Any({
					'type':   json2.Any('http')
					'scheme': json2.Any('bearer')
				})
			})
		})
		'paths':      json2.Any(paths)
	}).json_str()
}

fn openapi_endpoint(mut context EndpointContext, _ Request) !Response {
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    context.auth.generate_openapi_schema()!
	}
}

fn openapi_unique_id(mut operation map[string]json2.Any, mut used map[string]bool) {
	base := (operation['operationId'] or { json2.Any('operation') }).str()
	mut candidate := base
	mut counter := 2
	for (candidate in used) {
		candidate = base + counter.str()
		counter++
	}
	used[candidate] = true
	operation['operationId'] = candidate
}

fn openapi_script(value string) string {
	return value.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
}

fn openapi_reference(mut context EndpointContext, _ Request) !Response {
	mut options := OpenAPIOptions{}
	for plugin in context.auth.config.plugins {
		if plugin is OpenAPIPlugin { options = plugin.options }
	}
	if options.disable_default_reference { return fail(404, 'NOT_FOUND', 'Not found') }
	schema := openapi_script(context.auth.generate_openapi_schema()!)
	configuration := openapi_script(json2.Any(json2.Any({
		'theme': json2.Any(options.theme)
	}).json_str()).json_str())

	nonce := options.nonce.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace('>',
		'&gt;')
	return Response{
		headers: [Header{'content-type', 'text/html; charset=utf-8'}]
		body:
			'<!doctype html><html><head><meta charset="utf-8"><title>Scalar API Reference</title></head><body><script id="api-reference" type="application/json">' +
			schema + '</script><script nonce="' + nonce +
			'">document.getElementById("api-reference").dataset.configuration=' + configuration +
			';</script><script nonce="' + nonce +
			'" src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script></body></html>'
	}
}
