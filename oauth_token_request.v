module better_auth

pub struct OAuthFormParameter {
pub:
	name  string
	value string
}

pub struct OAuthForm {
pub mut:
	entries []OAuthFormParameter
}

pub fn (form OAuthForm) has(name string) bool {
	return form.entries.any(it.name == name)
}

pub fn (form OAuthForm) get(name string) ?string {
	for entry in form.entries {
		if entry.name == name { return entry.value }
	}
	return none
}

pub fn (mut form OAuthForm) append(name string, value string) {
	form.entries << OAuthFormParameter{name, value}
}

pub fn (mut form OAuthForm) delete(name string) {
	form.entries = form.entries.filter(it.name != name)
}

pub fn (mut form OAuthForm) set(name string, value string) {
	mut entries := []OAuthFormParameter{}
	mut found := false
	for entry in form.entries {
		if entry.name == name {
			if !found {
				entries << OAuthFormParameter{name, value}
				found = true
			}
		} else {
			entries << entry
		}
	}
	if !found { entries << OAuthFormParameter{name, value} }
	form.entries = entries.clone()
}

pub fn (form OAuthForm) encode() string {
	return form.entries.map(oauth_form_encode(it.name) + '=' + oauth_form_encode(it.value)).join('&')
}

pub struct OAuthTokenClientOptions {
pub:
	client_id     string @[json: clientId]
	client_secret string @[json: clientSecret]
	client_key    string @[json: clientKey]
	redirect_uri  string @[json: redirectURI]
}

pub struct OAuthTokenRequest {
pub mut:
	body    OAuthForm
	headers map[string]string
}

pub struct OAuthTokenRequestContext {
pub:
	options        OAuthTokenClientOptions
	token_endpoint string @[json: tokenEndpoint]
	grant_type     string @[json: grantType]
pub mut:
	request OAuthTokenRequest
}

pub type ClientAssertionGetter = fn (ClientAssertionContext) !string

fn no_client_assertion(_ ClientAssertionContext) !string {
	return error('missing client assertion getter')
}

fn no_token_customize(mut _ OAuthTokenRequestContext) ! {
	return error('missing token request customization callback')
}

pub struct OAuthTokenEndpointAuth {
pub:
	method               string
	get_client_assertion ClientAssertionGetter               = no_client_assertion               @[skip]
	customize_request    fn (mut OAuthTokenRequestContext) ! = no_token_customize @[skip]
}

pub struct OAuthTokenRequestInput {
pub:
	options             OAuthTokenClientOptions
	token_endpoint      string @[json: tokenEndpoint]
	authentication      string
	code                string
	code_verifier       string @[json: codeVerifier]
	redirect_uri        string @[json: redirectURI]
	device_id           string @[json: deviceId]
	refresh_token       string @[json: refreshToken]
	scope               string
	resource            []string
	headers             map[string]string
	additional_params   map[string]string       @[json: additionalParams]
	extra_params        map[string]string       @[json: extraParams]
	token_endpoint_auth ?OAuthTokenEndpointAuth @[skip]
}

fn assert_manual_client_assertion(body OAuthForm) ! {
	if body.has('client_assertion') != body.has('client_assertion_type') {
		return error('client_assertion and client_assertion_type must both be provided')
	}
}

fn assert_no_token_client_secret(method string, options OAuthTokenClientOptions, body OAuthForm) ! {
	if options.client_secret != '' || body.has('client_secret') {
		return error('${method} token endpoint authentication cannot be combined with clientSecret')
	}
}

pub fn apply_oauth_token_endpoint_auth(mut context OAuthTokenRequestContext, selected ?OAuthTokenEndpointAuth, authentication string) ! {
	assert_manual_client_assertion(context.request.body)!
	client := context.options.client_id
	if context.request.body.has('client_assertion') {
		if selected != none {
			return error('client_assertion body parameters cannot be combined with tokenEndpointAuth')
		}
		assert_no_token_client_secret('private_key_jwt', context.options, context.request.body)!
		if client != '' { context.request.body.set('client_id', client) }
		return
	}
	auth := selected or {
		OAuthTokenEndpointAuth{
			method: if authentication == 'basic' {
				'client_secret_basic'
			} else if context.options.client_secret != '' {
				'client_secret_post'
			} else {
				'none'
			}
		}
	}

	if auth.method == 'custom' {
		auth.customize_request(mut context)!
		assert_manual_client_assertion(context.request.body)!
		return
	}
	if auth.method in ['none', 'private_key_jwt'] {
		assert_no_token_client_secret(auth.method, context.options, context.request.body)!
		if auth.method == 'none' && context.grant_type == 'client_credentials' {
			return error('none token endpoint authentication cannot be used with client_credentials grant')
		}
		if client == '' {
			return error('${auth.method} token endpoint authentication requires clientId')
		}
		if auth.method == 'private_key_jwt' {
			if context.token_endpoint == '' {
				return error('private_key_jwt token endpoint authentication requires tokenEndpoint')
			}
			assertion := auth.get_client_assertion(ClientAssertionContext{
				client_id:      client
				token_endpoint: context.token_endpoint
				grant_type:     context.grant_type
			})!
			context.request.body.set('client_id', client)
			context.request.body.set('client_assertion', assertion)
			context.request.body.set('client_assertion_type', client_assertion_type)
		} else {
			context.request.body.set('client_id', client)
		}
		return
	}
	if auth.method == 'client_secret_basic' && context.request.body.has('client_secret') {
		return error('client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters')
	}
	method := if auth.method == 'client_secret_basic' { auth.method } else { 'client_secret_post' }
	if context.options.client_secret == '' {
		return error('${method} token endpoint authentication requires clientSecret')
	}
	if client == '' { return error('${method} token endpoint authentication requires clientId') }
	if method == 'client_secret_basic' {
		context.request.headers['authorization'] = encode_basic_credentials(client,
			context.options.client_secret)
	} else {
		context.request.body.set('client_id', client)
		context.request.body.set('client_secret', context.options.client_secret)
	}
}

pub fn oauth_token_request(input OAuthTokenRequestInput, grant_type string) !OAuthTokenRequest {
	if grant_type !in ['authorization_code', 'refresh_token', 'client_credentials'] {
		return error('unsupported OAuth grant type')
	}
	mut request := OAuthTokenRequest{
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
			'accept':       'application/json'
		}
	}
	request.body.set('grant_type', grant_type)
	if grant_type == 'authorization_code' {
		for name, value in input.headers {
			request.headers[name] = value
		}
		request.body.set('code', input.code)
		if input.code_verifier != '' { request.body.set('code_verifier', input.code_verifier) }
		if input.options.client_key != '' {
			request.body.set('client_key', input.options.client_key)
		}
		if input.device_id != '' { request.body.set('device_id', input.device_id) }
		request.body.set('redirect_uri', if input.options.redirect_uri != '' {
			input.options.redirect_uri
		} else {
			input.redirect_uri
		})
	} else if grant_type == 'refresh_token' {
		request.body.set('refresh_token', input.refresh_token)
	} else if input.scope != '' {
		request.body.set('scope', input.scope)
	}
	for resource in input.resource {
		request.body.append('resource', resource)
	}
	if grant_type == 'refresh_token' {
		for name, value in input.extra_params {
			if name !in ['grant_type', 'refresh_token', '__proto__', 'constructor', 'prototype'] {
				request.body.set(name, value)
			}
		}
	} else if grant_type == 'authorization_code' {
		for name, value in input.additional_params {
			if !request.body.has(name) { request.body.append(name, value) }
		}
	}
	mut context := OAuthTokenRequestContext{
		options:        input.options
		token_endpoint: input.token_endpoint
		grant_type:     grant_type
		request:        request
	}
	apply_oauth_token_endpoint_auth(mut context, input.token_endpoint_auth, input.authentication)!
	return context.request
}

pub fn request_oauth_token(input OAuthTokenRequestInput, grant_type string, transport OAuthTransport) !string {
	request := oauth_token_request(input, grant_type)!
	response := transport.request(Request{
		method:  'POST'
		url:     input.token_endpoint
		headers: request.headers
		body:    request.body.encode()
	})!
	if response.status in [301, 302, 303, 307, 308] || response.status_text == 'opaqueredirect' {
		return error('The OAuth endpoint "${input.token_endpoint}" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.')
	}
	if response.status < 200 || response.status >= 300 {
		return error('OAuth token endpoint returned HTTP ${response.status}: ${response.body}')
	}
	return response.body
}
