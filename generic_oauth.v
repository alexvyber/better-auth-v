module better_auth

import net.urllib
import x.json2

pub struct GenericOAuthConfig {
pub:
	provider_id                    string @[json: providerId]
	name                           string
	client_id                      string            @[json: clientId]
	client_secret                  string            @[json: clientSecret]
	discovery_url                  string            @[json: discoveryUrl]
	discovery_headers              map[string]string @[json: discoveryHeaders]
	authorization_url              string            @[json: authorizationUrl]
	token_url                      string            @[json: tokenUrl]
	user_info_url                  string            @[json: userInfoUrl]
	redirect_uri                   string            @[json: redirectURI]
	scopes                         []string
	pkce                           bool = true
	require_id_token_verification  bool @[json: requireIdTokenVerification]
	disable_id_token_nonce_binding bool @[json: disableIdTokenNonceBinding]
	disable_sign_up                bool @[json: disableSignUp]
	disable_implicit_sign_up       bool @[json: disableImplicitSignUp]
	authentication                 string
	token_endpoint_auth            ?OAuthTokenEndpointAuth @[json: tokenEndpointAuth]
	authorization_url_params       map[string]string       @[json: authorizationUrlParams]
	token_url_params               map[string]string       @[json: tokenUrlParams]
	authorization_headers          map[string]string       @[json: authorizationHeaders]
	prompt                         string
	access_type                    string         @[json: accessType]
	response_type                  string         @[json: responseType]
	response_mode                  string         @[json: responseMode]
	transport                      OAuthTransport = OAuthHTTPTransport{} @[skip]
	clock_millis                   fn () i64      = cookie_reader_clock      @[skip]
	get_token                      fn (string, string, string) !OAuthTokens = default_generic_get_token @[skip]
	map_profile                    fn (string) !string                      = default_generic_map_profile                      @[skip]
}

fn default_generic_get_token(_ string, _ string, _ string) !OAuthTokens {
	return error('custom token callback is not configured')
}

fn default_generic_map_profile(_ string) !string {
	return '{}'
}

pub struct GenericOAuthProvider {
pub:
	options    GenericOAuthConfig
	issuer     string
	jwks_uri   string
	algorithms []string
	oidc       bool
}

pub fn (provider GenericOAuthProvider) id() string {
	return provider.options.provider_id
}

pub fn (provider GenericOAuthProvider) requires_nonce() bool {
	return provider.jwks_uri != '' && !provider.options.disable_id_token_nonce_binding
}

pub fn (provider GenericOAuthProvider) sign_up_allowed(requested bool) bool {
	return !provider.options.disable_sign_up
		&& (!provider.options.disable_implicit_sign_up || requested)
}

fn generic_http_url(value string) !string {
	url := urllib.parse(value)!
	if url.scheme !in ['http', 'https'] || url.host == ''
		|| value.all_after('://').all_before('/').all_before('?').contains('@') {
		return error('invalid OAuth endpoint URL')
	}
	return value
}

pub fn resolve_generic_oauth_provider(input GenericOAuthConfig) !Lookup[GenericOAuthProvider] {
	mut options := input
	mut issuer := ''
	mut jwks := ''
	mut algorithms := []string{}
	mut oidc := false
	if input.discovery_url != '' {
		generic_http_url(input.discovery_url)!
		response := input.transport.request(Request{
			method:  'GET'
			url:     input.discovery_url
			headers: input.discovery_headers
		})!
		if response.status < 200 || response.status >= 300 { return Lookup[GenericOAuthProvider]{} }
		document := json2.decode[map[string]json2.Any](response.body)!
		issuer = (document['issuer'] or { json2.Any('') }).str()
		if issuer != '' { generic_http_url(issuer)! }
		if supplied := document['id_token_signing_alg_values_supported'] {
			if supplied is []json2.Any {
				algorithms = supplied.map(it.str())
				oidc = algorithms.len > 0
			}
		}
		raw_jwks := (document['jwks_uri'] or { json2.Any('') }).str()
		if raw_jwks != '' && issuer != '' {
			base := urllib.parse(input.discovery_url)!
			relative := urllib.parse(raw_jwks)!
			jwks = generic_http_url(base.resolve_reference(relative)!.str())!
		}
		options = GenericOAuthConfig{
			...input
			authorization_url: if input.authorization_url != '' {
				input.authorization_url
			} else {
				(document['authorization_endpoint'] or { json2.Any('') }).str()
			}
			token_url:         if input.token_url != '' {
				input.token_url
			} else {
				(document['token_endpoint'] or { json2.Any('') }).str()
			}
			user_info_url:     if input.user_info_url != '' {
				input.user_info_url
			} else {
				(document['userinfo_endpoint'] or { json2.Any('') }).str()
			}
		}
	}
	if input.require_id_token_verification && jwks == '' {
		if input.discovery_url != '' { return Lookup[GenericOAuthProvider]{} }
		return error('Provider "${input.provider_id}": requires verified ID tokens, but discovery did not provide a usable issuer and jwks_uri.')
	}
	if options.authorization_url == ''
		|| (options.token_url == '' && options.get_token == default_generic_get_token) {
		return Lookup[GenericOAuthProvider]{}
	}
	generic_http_url(options.authorization_url)!
	if options.token_url != '' { generic_http_url(options.token_url)! }
	if options.user_info_url != '' { generic_http_url(options.user_info_url)! }
	return Lookup[GenericOAuthProvider]{
		value: GenericOAuthProvider{
			options:    options
			issuer:     issuer
			jwks_uri:   jwks
			algorithms: algorithms
			oidc:       oidc
		}
	}
}

fn resolve_generic_oauth_config(config Config) !Config {
	mut providers := config.social_providers.clone()
	for input in config.generic_oauth {
		resolved := resolve_generic_oauth_provider(input) or {
			if input.discovery_url == '' { return err }
			config.log('error', 'Discovery failed for provider ' + input.provider_id)
			continue
		}
		if provider := resolved.value { providers << OAuthProvider(provider) }
	}
	return Config{
		...config
		social_providers: providers
	}
}

pub fn (provider GenericOAuthProvider) authorization_url(state string, challenge string, redirect_uri string) !string {
	return provider.authorization_request(OAuthAuthorizationRequest{
		state:        state
		redirect_uri: redirect_uri
	}, challenge)
}

pub fn (provider GenericOAuthProvider) authorization_request(input OAuthAuthorizationRequest, challenge string) !string {
	mut scopes := input.scopes.clone()
	scopes << provider.options.scopes
	if provider.oidc && 'openid' !in scopes { scopes.insert(0, 'openid') }
	mut additional := provider.options.authorization_url_params.clone()
	additional.delete('nonce')
	for name, value in input.additional_params {
		additional[name] = value
	}
	return create_oauth_authorization_url_with_challenge(OAuthAuthorizationRequest{
		...input
		options:                OAuthAuthorizationOptions{
			client_id:    provider.options.client_id
			redirect_uri: provider.options.redirect_uri
		}
		authorization_endpoint: provider.options.authorization_url
		scopes:                 scopes
		nonce:                  input.nonce
		additional_params:      additional
		prompt:                 provider.options.prompt
		access_type:            provider.options.access_type
		response_type:          provider.options.response_type
		response_mode:          provider.options.response_mode
	}, if provider.options.pkce {
		challenge
	} else {
		''
	})
}

fn (provider GenericOAuthProvider) verified_profile(token string, nonce string) !string {
	header := id_token_header(token)!
	response :=
		provider.options.transport.request(Request{ method: 'GET', url: provider.jwks_uri })!
	if response.status < 200 || response.status >= 300 { return error('ID token JWKS fetch failed') }
	key := generic_id_token_key(header, response.body)!
	return verify_id_token_with_jwk(token, key, IDTokenVerifyConfig{
		issuers:         [provider.issuer]
		issuer_required: true
		audiences:       [provider.options.client_id]
		algorithms:      if provider.algorithms.len > 0 { provider.algorithms } else { [
				'RS256',
				'RS384',
				'RS512',
				'PS256',
				'PS384',
				'PS512',
				'ES256',
				'ES384',
				'ES512',
				'EdDSA',
			] }
		nonce:           nonce
	}, provider.options.clock_millis() / 1000)
}

fn generic_id_token_key(header map[string]json2.Any, encoded string) !string {
	algorithm := (header['alg'] or { return error('missing ID token algorithm') }).str()
	if algorithm.starts_with('HS') || algorithm == 'none' {
		return error('invalid remote ID token algorithm')
	}
	keys := json2.decode[map[string]json2.Any](encoded)!['keys'] or {
		return error('missing JWKS keys')
	}
	if keys !is []json2.Any { return error('invalid JWKS keys') }
	mut candidates := []string{}
	for item in keys.as_array() {
		if item !is map[string]json2.Any { continue
		 }
		key := item.as_map()
		if wanted := header['kid'] {
			if (key['kid'] or { json2.Any(json2.Null{}) }) != wanted { continue
			 }
		}
		if given := key['alg'] {
			if given != json2.Any(algorithm) { continue
			 }
		}
		if usage := key['use'] {
			if usage != json2.Any('sig') { continue
			 }
		}
		if operations := key['key_ops'] {
			if operations !is []json2.Any { continue
			 }
			if !operations.as_array().any(it == json2.Any('verify')) { continue
			 }
		}
		kind := (key['kty'] or { json2.Any('') }).str()
		expected := if algorithm.starts_with('RS') || algorithm.starts_with('PS') {
			'RSA'
		} else if algorithm.starts_with('ES') {
			'EC'
		} else if algorithm == 'EdDSA' {
			'OKP'
		} else {
			''
		}
		if kind != expected || expected == '' { continue
		 }
		candidates << item.json_str()
	}
	if candidates.len != 1 { return error('JWKS did not resolve exactly one signing key') }
	return candidates[0]
}

pub fn (provider GenericOAuthProvider) exchange(code string, verifier string, redirect_uri string) !OAuthIdentity {
	return provider.exchange_bound(code, verifier, redirect_uri, '')
}

pub fn (provider GenericOAuthProvider) exchange_bound(code string, verifier string, redirect_uri string, nonce string) !OAuthIdentity {
	tokens := if provider.options.get_token != default_generic_get_token {
		provider.options.get_token(code, verifier, redirect_uri)!
	} else {
		encoded := request_oauth_token(OAuthTokenRequestInput{
			options:             OAuthTokenClientOptions{
				client_id:     provider.options.client_id
				client_secret: provider.options.client_secret
				redirect_uri:  provider.options.redirect_uri
			}
			token_endpoint:      provider.options.token_url
			code:                code
			code_verifier:       if provider.options.pkce { verifier } else { '' }
			redirect_uri:        redirect_uri
			authentication:      provider.options.authentication
			token_endpoint_auth: provider.options.token_endpoint_auth
			additional_params:   provider.options.token_url_params
			headers:             provider.options.authorization_headers
		}, 'authorization_code', provider.options.transport)!
		parse_oauth_tokens(encoded, provider.options.clock_millis())!
	}
	if provider.requires_nonce() && nonce == '' {
		return fail(401, 'NONCE_BINDING_MISSING', 'Missing expected ID token nonce')
	}
	return provider.profile_identity(tokens, nonce)
}

fn (provider GenericOAuthProvider) profile_identity(tokens OAuthTokens, nonce string) !OAuthIdentity {
	mut raw := map[string]json2.Any{}
	if tokens.id_token != '' {
		encoded := if provider.jwks_uri != '' {
			provider.verified_profile(tokens.id_token, nonce)!
		} else {
			parts := tokens.id_token.split('.')
			if parts.len != 3 { return error('invalid ID token') }
			decode_base64url(parts[1])!.bytestr()
		}
		decoded := json2.decode[map[string]json2.Any](encoded)!
		if (decoded['sub'] or { json2.Any('') }).str() != '' && (decoded['email'] or {
			json2.Any('')
		}).str() != '' {
			raw = decoded.clone()
		}
	}
	if raw.len == 0 {
		if provider.options.user_info_url == '' { return error('no provider user info') }
		access := tokens.access_token or { return error('missing access token') }
		response := provider.options.transport.request(Request{
			method:  'GET'
			url:     provider.options.user_info_url
			headers: {
				'authorization': 'Bearer ' + access
			}
		})!
		if response.status < 200 || response.status >= 300 {
			return error('provider user info failed')
		}
		raw = json2.decode[map[string]json2.Any](response.body)!
	}
	raw['emailVerified'] = raw['email_verified'] or { json2.Any(false) }
	raw['image'] = raw['picture'] or { json2.Any(json2.Null{}) }
	mapped :=
		json2.decode[map[string]json2.Any](provider.options.map_profile(json2.Any(raw).json_str())!)!
	mut user := raw.clone()
	for key, value in mapped {
		user[key] = value
	}
	subject := if provider.oidc { raw['sub'] or { json2.Any('') } } else { raw['id'] or {
			raw['sub'] or { json2.Any('') }} }
	image := user['image'] or { json2.Any(json2.Null{}) }
	return OAuthIdentity{
		id:                subject.str()
		email:             (user['email'] or { json2.Any('') }).str()
		email_verified:    (user['emailVerified'] or { json2.Any(false) }).bool()
		name:              (user['name'] or { json2.Any('') }).str()
		image:             if image is string { ?string(image.str()) } else { none }
		additional_fields: oauth_extra_fields(mapped)
		profile:           raw
		tokens:            tokens
	}
}

pub fn (provider GenericOAuthProvider) supports_id_token() bool {
	return provider.jwks_uri != ''
}

pub fn (provider GenericOAuthProvider) verify_id_token(token string, nonce string) Lookup[string] {
	payload := provider.verified_profile(token, nonce) or { return Lookup[string]{} }
	return Lookup[string]{
		value: payload
	}
}

pub fn (provider GenericOAuthProvider) user_info(tokens OAuthTokens) !Lookup[OAuthIdentity] {
	// Direct ID-token credentials were verified by the core before this call.
	identity := provider.profile_identity(tokens, '')!
	return Lookup[OAuthIdentity]{
		value: identity
	}
}
