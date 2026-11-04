module better_auth

import net.urllib
import time
import x.json2

// Google's code exchange and ID-token verifier use separate trust policies.
pub struct GoogleProvider {
pub:
	client_id                string   @[json: clientId]
	client_ids               []string @[json: clientIds]
	client_secret            string   @[json: clientSecret]
	authorization_endpoint   string   @[json: authorizationEndpoint]
	scope                    []string
	disable_default_scope    bool   @[json: disableDefaultScope]
	access_type              string @[json: accessType]
	display                  string
	hd                       string
	prompt                   string
	include_granted_scopes   bool = true           @[json: includeGrantedScopes]
	redirect_uri             string         @[json: redirectURI]
	disable_id_token_sign_in bool           @[json: disableIdTokenSignIn]
	transport                OAuthTransport = OAuthHTTPTransport{} @[skip]
	clock_millis             fn () i64      = cookie_reader_clock      @[skip]
}

pub fn (_ GoogleProvider) id() string {
	return 'google'
}

fn (provider GoogleProvider) primary_client_id() string {
	if provider.client_ids.len > 0 { return provider.client_ids[0] }
	return provider.client_id
}

fn (provider GoogleProvider) audiences() []string {
	if provider.client_ids.len > 0 { return provider.client_ids }
	return [provider.client_id]
}

pub fn google_hosted_domain_allowed(configured string, claim json2.Any) bool {
	if configured == '' { return true }
	if claim !is string { return false }
	if claim.str() == '' { return false }
	return configured == '*' || claim.str() == configured
}

pub fn (provider GoogleProvider) authorization_url(state string, challenge string, redirect_uri string) !string {
	return provider.authorization_request(OAuthAuthorizationRequest{
		state:        state
		redirect_uri: redirect_uri
	}, challenge)
}

pub fn (provider GoogleProvider) authorization_request(input OAuthAuthorizationRequest, challenge string) !string {
	if provider.primary_client_id() == '' || provider.client_secret == '' {
		return error('CLIENT_ID_AND_SECRET_REQUIRED')
	}
	if challenge == '' { return error('codeVerifier is required for Google') }
	mut scopes := if provider.disable_default_scope { []string{} } else { ['email', 'profile',
			'openid'] }
	scopes << provider.scope
	scopes << input.scopes
	mut additional := map[string]string{}
	if provider.include_granted_scopes { additional['include_granted_scopes'] = 'true' }
	for name, value in input.additional_params {
		additional[name] = value
	}
	return create_oauth_authorization_url_with_challenge(OAuthAuthorizationRequest{
		options:                OAuthAuthorizationOptions{
			client_id:              provider.primary_client_id()
			authorization_endpoint: provider.authorization_endpoint
			redirect_uri:           provider.redirect_uri
		}
		authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth'
		state:                  input.state
		scopes:                 scopes
		redirect_uri:           input.redirect_uri
		access_type:            provider.access_type
		display:                if input.display != '' { input.display } else { provider.display }
		login_hint:             input.login_hint
		hd:                     provider.hd
		prompt:                 provider.prompt
		additional_params:      additional
	}, challenge)
}

pub fn (provider GoogleProvider) exchange(code string, verifier string, redirect_uri string) !OAuthIdentity {
	mut body := urllib.new_values()
	for key, value in {
		'client_id':     provider.primary_client_id()
		'client_secret': provider.client_secret
		'code':          code
		'grant_type':    'authorization_code'
		'redirect_uri':  if provider.redirect_uri != '' {
			provider.redirect_uri
		} else {
			redirect_uri
		}
		'code_verifier': verifier
	} {
		body.set(key, value)
	}
	response := provider.transport.request(Request{
		method:  'POST'
		url:     'https://oauth2.googleapis.com/token'
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
			'accept':       'application/json'
		}
		body:    body.encode()
	})!
	if response.status < 200 || response.status >= 300 {
		return fail(502, 'OAUTH_TOKEN_ERROR', 'Provider token exchange failed')
	}
	tokens := parse_oauth_tokens(response.body, provider.clock_millis())!
	if tokens.id_token == '' {
		return fail(400, 'OAUTH_PROFILE_ERROR', 'Google did not return an ID token')
	}
	parts := tokens.id_token.split('.')
	if parts.len != 3 { return fail(400, 'OAUTH_PROFILE_ERROR', 'Invalid provider profile') }
	profile := json2.decode[map[string]json2.Any](decode_base64url(parts[1])!.bytestr())!
	if !google_hosted_domain_allowed(provider.hd, profile['hd'] or { json2.Any(json2.Null{}) }) {
		return fail(403, 'OAUTH_HOSTED_DOMAIN_MISMATCH', 'Google hosted domain does not match')
	}
	return google_profile_identity(profile, tokens)
}

pub fn parse_oauth_tokens(encoded string, now_millis i64) !OAuthTokens {
	fields := json2.decode[map[string]json2.Any](encoded)!
	if 'error' in fields {
		return fail(400, 'OAUTH_TOKEN_ERROR', 'Provider rejected the authorization code')
	}
	access := oauth_optional_string(fields, 'access_token')!
	refresh := oauth_optional_string(fields, 'refresh_token')!
	return OAuthTokens{
		access_token:             access.value
		refresh_token:            refresh.value
		id_token:                 (oauth_optional_string(fields, 'id_token')!).value or { '' }
		access_token_expires_at:  (oauth_token_expiry(fields, 'expires_in', now_millis)!).value
		refresh_token_expires_at: (oauth_token_expiry(fields, 'refresh_token_expires_in',
			now_millis)!).value
		scope:                    oauth_scope_field(fields['scope'] or { json2.Any(json2.Null{}) }).join(',')
	}
}

fn oauth_optional_string(fields map[string]json2.Any, name string) !Lookup[string] {
	value := fields[name] or { return Lookup[string]{} }
	if value is json2.Null { return Lookup[string]{} }
	if value !is string { return error('invalid OAuth token field ${name}') }
	return Lookup[string]{
		value: value.str()
	}
}

fn oauth_token_expiry(fields map[string]json2.Any, name string, now_millis i64) !Lookup[string] {
	value := fields[name] or { return Lookup[string]{} }
	if !js_truthy(value) { return Lookup[string]{} }
	seconds := if value is string { value.f64() } else { numeric_date_field(fields, name)! }
	return Lookup[string]{
		value: time.unix_milli(i64(f64(now_millis) + seconds * 1000)).format_rfc3339()
	}
}

pub fn oauth_scope_field(value json2.Any) []string {
	if value is string { return value.fields() }
	mut scopes := []string{}
	if value is []json2.Any {
		for item in value {
			if item is string {
				if item.trim_space() != '' { scopes << item.trim_space() }
			}
		}
	}
	return scopes
}

pub fn merge_oauth_scopes(stored string, incoming []string) string {
	mut scopes := []string{}
	mut all := stored.split(',')
	all << incoming
	for item in all {
		trimmed := item.trim_space()
		if trimmed != '' && trimmed !in scopes { scopes << trimmed }
	}
	return scopes.join(',')
}
