module better_auth

import crypto.sha256
import net.urllib
import x.json2

pub const reserved_authorization_params = ['state', 'client_id', 'redirect_uri', 'response_type',
	'code_challenge', 'code_challenge_method', 'nonce', 'scope']

pub struct OAuthAuthorizationOptions {
pub:
	client_id              string @[json: clientId]
	authorization_endpoint string @[json: authorizationEndpoint]
	redirect_uri           string @[json: redirectURI]
}

pub struct OAuthAuthorizationRequest {
pub:
	options                OAuthAuthorizationOptions
	authorization_endpoint string @[json: authorizationEndpoint]
	state                  string
	code_verifier          string @[json: codeVerifier]
	scopes                 []string
	claims                 ?[]string
	redirect_uri           string @[json: redirectURI]
	duration               string
	prompt                 string
	access_type            string @[json: accessType]
	response_type          string @[json: responseType]
	display                string
	login_hint             string @[json: loginHint]
	nonce                  string
	hd                     string
	response_mode          string            @[json: responseMode]
	additional_params      map[string]string @[json: additionalParams]
	scope_joiner           string            @[json: scopeJoiner]
}

struct OAuthQueryParameter {
	name  string
	value string
}

fn oauth_query_set(mut entries []OAuthQueryParameter, name string, value string) {
	mut next := []OAuthQueryParameter{}
	mut found := false
	for entry in entries {
		if entry.name == name {
			if !found {
				next << OAuthQueryParameter{name, value}
				found = true
			}
		} else {
			next << entry
		}
	}
	if !found { next << OAuthQueryParameter{name, value} }
	entries = next.clone()
}

pub fn create_oauth_authorization_url(input OAuthAuthorizationRequest) !string {
	challenge := if input.code_verifier != '' {
		base64url(sha256.sum(input.code_verifier.bytes()))
	} else {
		''
	}
	return create_oauth_authorization_url_with_challenge(input, challenge)
}

// OAuthProvider's existing interface supplies a previously computed challenge.
// Keeping this entry point separate prevents hashing that challenge a second time.
pub fn create_oauth_authorization_url_with_challenge(input OAuthAuthorizationRequest, challenge string) !string {
	endpoint := if input.options.authorization_endpoint != '' {
		input.options.authorization_endpoint
	} else {
		input.authorization_endpoint
	}
	mut url := urllib.parse(endpoint)!
	if url.scheme == '' { return error('Invalid URL') }
	if url.scheme in ['http', 'https', 'ws', 'wss', 'ftp'] {
		if url.host == '' { return error('Invalid URL') }
		url.host = url.host.to_lower()
		default_port := if url.scheme in ['http', 'ws'] {
			':80'
		} else if url.scheme in ['https', 'wss'] {
			':443'
		} else {
			':21'
		}
		if url.host.ends_with(default_port) {
			url.host = url.host[..url.host.len - default_port.len]
		}
		if url.path == '' { url.path = '/' }
	}
	mut entries := []OAuthQueryParameter{}
	for part in url.raw_query.split('&') {
		if part == '' { continue
		 }
		name, value := part.split_once('=') or { part, '' }
		entries << OAuthQueryParameter{oauth_form_decode(name), oauth_form_decode(value)}
	}
	oauth_query_set(mut entries, 'response_type', if input.response_type != '' {
		input.response_type
	} else {
		'code'
	})
	if input.options.client_id == '' { return error('OAuth provider requires clientId') }
	oauth_query_set(mut entries, 'client_id', input.options.client_id)
	oauth_query_set(mut entries, 'state', input.state)
	if input.scopes.len > 0 {
		oauth_query_set(mut entries, 'scope', input.scopes.join(if input.scope_joiner != '' {
			input.scope_joiner
		} else {
			' '
		}))
	}
	oauth_query_set(mut entries, 'redirect_uri', if input.options.redirect_uri != '' {
		input.options.redirect_uri
	} else {
		input.redirect_uri
	})
	for name, value in {
		'duration':      input.duration
		'display':       input.display
		'login_hint':    input.login_hint
		'nonce':         input.nonce
		'prompt':        input.prompt
		'hd':            input.hd
		'access_type':   input.access_type
		'response_mode': input.response_mode
	} {
		if value != '' { oauth_query_set(mut entries, name, value) }
	}
	if challenge != '' {
		oauth_query_set(mut entries, 'code_challenge_method', 'S256')
		oauth_query_set(mut entries, 'code_challenge', challenge)
	}
	if claims := input.claims {
		mut fields := {
			'email':          json2.Any(json2.Null{})
			'email_verified': json2.Any(json2.Null{})
		}
		for claim in claims {
			if claim != '__proto__' { fields[claim] = json2.Null{} }
		}
		oauth_query_set(mut entries, 'claims', js_json(json2.Any({
			'id_token': json2.Any(fields)
		})))
	}
	for name, value in input.additional_params {
		if name !in reserved_authorization_params { oauth_query_set(mut entries, name, value) }
	}
	url.raw_query =
		entries.map(oauth_form_encode(it.name) + '=' + oauth_form_encode(it.value)).join('&')
	return url.str()
}
