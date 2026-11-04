module main

import better_auth
import json
import os
import x.json2

fn assertion_options(fields map[string]json2.Any) better_auth.PrivateKeyJWTOptions {
	jwk := fields['privateKeyJwk'] or { json2.Any(json2.Null{}) }
	kid := fields['kid'] or { json2.Any(json2.Null{}) }
	algorithm := fields['algorithm'] or { json2.Any(json2.Null{}) }
	return better_auth.PrivateKeyJWTOptions{
		private_key_jwk: if jwk is json2.Null { '' } else { jwk.json_str() }
		private_key_pem: (fields['privateKeyPem'] or { json2.Any('') }).str()
		kid:             if kid is string { ?string(kid) } else { none }
		algorithm:       if algorithm is string { ?string(algorithm) } else { none }
		expires_in:      (fields['expiresIn'] or { json2.Any(120) }).f64()
	}
}

fn oauth_assertion_command() ! {
	input := json2.decode[map[string]json2.Any](os.get_raw_line())!
	if (input['op'] or { json2.Any('') }).str() == 'metadata' {
		println('{"type":${json.encode(better_auth.client_assertion_type)},"algorithms":${json.encode(better_auth.private_key_jwt_algorithms)}}')
		return
	}
	fields := (input['options'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	options := assertion_options(fields)
	if (input['op'] or { json2.Any('') }).str() == 'validate' {
		println(json.encode(better_auth.validate_private_key_jwt_options(options)!))
		return
	}
	context := json.decode(better_auth.ClientAssertionContext, (input['context'] or {
		json2.Any(map[string]json2.Any{})
	}).json_str())!
	println(json.encode(better_auth.sign_private_key_jwt_client_assertion(context, options, (input['now'] or {
		json2.Any(0)
	}).i64())!))
}

fn oauth_request_json(request better_auth.OAuthTokenRequest) string {
	return '{"body":${json.encode(request.body.encode())},"headers":${json.encode(request.headers)}}'
}

fn oauth_request_from_json(encoded string) !better_auth.OAuthTokenRequest {
	fields := json2.decode[map[string]json2.Any](encoded)!
	mut form := better_auth.OAuthForm{}
	body := (fields['body'] or { json2.Any('') }).str()
	for part in body.split('&') {
		if part == '' { continue
		 }
		name, value := part.split_once('=') or { part, '' }
		form.append(better_auth.oauth_form_decode(name), better_auth.oauth_form_decode(value))
	}
	return better_auth.OAuthTokenRequest{
		body:    form
		headers: json.decode(map[string]string, (fields['headers'] or {
			json2.Any(map[string]json2.Any{})
		}).json_str())!
	}
}

fn oauth_token_input(fields map[string]json2.Any) !better_auth.OAuthTokenRequestInput {
	mut input := fields.clone()
	mut options := (input['options'] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
	client := options['clientId'] or { json2.Any('') }
	primary := if client is []json2.Any {
		if client.len > 0 { client[0] } else { json2.Any('') }
	} else {
		client
	}
	options['clientId'] = if primary is string { primary } else { json2.Any('') }
	input['options'] = options
	if resource := input['resource'] {
		if resource is string { input['resource'] = [json2.Any(resource)] }
	}
	base := json.decode(better_auth.OAuthTokenRequestInput, json2.Any(input).json_str())!
	if strategy := fields['tokenEndpointAuth'] {
		auth := strategy.as_map()
		return better_auth.OAuthTokenRequestInput{
			...base
			token_endpoint_auth: better_auth.OAuthTokenEndpointAuth{
				method:               (auth['method'] or { json2.Any('') }).str()
				get_client_assertion: fn (context better_auth.ClientAssertionContext) !string {
					return json2.decode[string](callback_rpc('token.assertion',
						json.encode(context))!)
				}
				customize_request:    fn (mut context better_auth.OAuthTokenRequestContext) ! {
					payload := '{"request":${oauth_request_json(context.request)},"tokenEndpoint":${json.encode(context.token_endpoint)},"grantType":${json.encode(context.grant_type)}}'
					context.request = oauth_request_from_json(callback_rpc('token.customize',
						payload)!)!
				}
			}
		}
	}
	return base
}

struct RemoteTokenTransport {}

fn (_ RemoteTokenTransport) request(request better_auth.Request) !better_auth.Response {
	return json.decode(better_auth.Response, callback_rpc('token.fetch', json.encode(request))!)
}

fn oauth_token_dispatch(fields map[string]json2.Any) !string {
	input := oauth_token_input((fields['input'] or { json2.Any(map[string]json2.Any{}) }).as_map())!
	grant := (fields['grant_type'] or { json2.Any('') }).str()
	if (fields['op'] or { json2.Any('') }).str() == 'request' {
		return oauth_request_json(better_auth.oauth_token_request(input, grant)!)
	}
	data := better_auth.request_oauth_token(input, grant, RemoteTokenTransport{})!
	return better_auth.normalize_oauth_token_response(data, grant, json2.decode[i64](callback_rpc('token.clock',
		'{}')!)!)
}

fn oauth_token_command() ! {
	for {
		line := os.get_raw_line()
		if line == '' { return }
		fields := json2.decode[map[string]json2.Any](line)!
		id := (fields['id'] or { json2.Any(0) }).int()
		if (fields['op'] or { json2.Any('') }).str() == 'close' {
			emit(Reply{ id: id })
			return
		}
		value := oauth_token_dispatch(fields) or {
			emit(Reply{ id: id, error: err.msg() })
			continue
		}
		emit(Reply{ id: id, value_json: value })
	}
}
