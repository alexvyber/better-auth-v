module better_auth

import net.urllib
import x.json2

// Verification profiles are independent of authorization-code/user-info provider
// implementations. They can be used by native integrations before those flows
// are supplied, without claiming that the complete OAuth provider is implemented.
pub struct IDTokenProviderProfile {
pub:
	id                 string
	disabled           bool
	configured         bool
	allow_opaque_token bool
	config             IDTokenVerifyConfig
	jwks_url           string
	key_selection      string = 'kid-first'
	hosted_domain      string
	tenant             string
	authority          string
}

pub fn id_token_provider_profile(id string, options_json string) !IDTokenProviderProfile {
	options := json2.decode[map[string]json2.Any](options_json)!
	client := id_token_strings(options['clientId'] or { json2.Any(json2.Null{}) })
	disabled := js_truthy(options['disableIdTokenSignIn'] or { json2.Any(false) })
	base := IDTokenVerifyConfig{
		audiences:     client
		algorithms:    ['RS256']
		max_token_age: f64(3600)
	}
	match id {
		'paypal' {
			return IDTokenProviderProfile{
				id:       id
				disabled: disabled
			}
		}
		'google' {
			return IDTokenProviderProfile{
				id:            id
				disabled:      disabled
				configured:    true
				config:        IDTokenVerifyConfig{
					...base
					issuers: ['https://accounts.google.com', 'accounts.google.com']
				}
				jwks_url:      'https://www.googleapis.com/oauth2/v3/certs'
				key_selection: 'google-first'
				hosted_domain: (options['hd'] or { json2.Any('') }).str()
			}
		}
		'apple' {
			audiences := if given := options['audience'] {
				if js_truthy(given) && id_token_strings(given).len > 0 {
					id_token_strings(given)
				} else {
					[]string{}
				}
			} else {
				[]string{}
			}
			bundle := (options['appBundleIdentifier'] or { json2.Any('') }).str()
			return IDTokenProviderProfile{
				id:         id
				disabled:   disabled
				configured: true
				config:     IDTokenVerifyConfig{
					...base
					issuers:          ['https://appleid.apple.com']
					audiences:        if audiences.len > 0 {
						audiences
					} else if bundle != '' {
						[bundle]
					} else {
						client
					}
					nonce_comparison: 'exact-or-sha256'
				}
				jwks_url:   'https://appleid.apple.com/auth/keys'
			}
		}
		'cognito' {
			region := (options['region'] or { json2.Any('undefined') }).str()
			pool := (options['userPoolId'] or { json2.Any('undefined') }).str()
			issuer := 'https://cognito-idp.${region}.amazonaws.com/${pool}'
			return IDTokenProviderProfile{
				id:         id
				disabled:   disabled
				configured: true
				config:     IDTokenVerifyConfig{
					...base
					issuers: [issuer]
				}
				jwks_url:   issuer + '/.well-known/jwks.json'
			}
		}
		'facebook' {
			return IDTokenProviderProfile{
				id:                 id
				disabled:           disabled
				configured:         true
				allow_opaque_token: true
				config:             IDTokenVerifyConfig{
					...base
					issuers:       ['https://www.facebook.com']
					max_token_age: none
				}
				jwks_url:           'https://limited.facebook.com/.well-known/oauth/openid/jwks/'
				key_selection:      'remote-jwks'
			}
		}
		'microsoft' {
			given_tenant := options['tenantId'] or { json2.Any('') }
			tenant := if js_truthy(given_tenant) { given_tenant.str() } else { 'common' }
			given_authority := options['authority'] or { json2.Any('') }
			authority := (if js_truthy(given_authority) {
				given_authority.str()
			} else {
				'https://login.microsoftonline.com'
			}).trim_right('/')
			return IDTokenProviderProfile{
				id:         id
				disabled:   disabled
				configured: true
				tenant:     tenant
				authority:  authority
				config:     IDTokenVerifyConfig{
					...base
					issuers: if tenant in ['common', 'organizations', 'consumers'] { []string{} } else { [
							authority + '/' + tenant + '/v2.0',
						] }
				}
				jwks_url:   authority + '/' + tenant + '/discovery/v2.0/keys'
			}
		}
		else {
			return error('unknown ID token provider profile')
		}
	}
}

pub fn (profile IDTokenProviderProfile) accepts_claims(payload_json string) !bool {
	claims := json2.decode[map[string]json2.Any](payload_json)!
	if profile.id == 'google' { return google_hosted_domain_allowed(profile.hosted_domain, claims['hd'] or {
			json2.Any(json2.Null{})}) }
	if profile.id == 'microsoft' {
		tenant := claims['tid'] or { return false }
		if tenant !is string { return false }
		if (claims['iss'] or { json2.Any(json2.Null{}) }) != json2.Any(profile.authority + '/' +
			tenant.str() + '/v2.0') {
			return false
		}
		consumer := '9188040d-6c67-4c5b-b112-36a304b66dad'
		if profile.tenant == 'organizations' && tenant.str() == consumer { return false }
		if profile.tenant == 'consumers' && tenant.str() != consumer { return false }
	}
	return true
}

pub fn (profile IDTokenProviderProfile) resolve_key(header_json string, jwks_json string) !string {
	header := json2.decode[map[string]json2.Any](header_json)!
	if (header['alg'] or { json2.Any('') }) != json2.Any('RS256') {
		return error('ID token profile requires RS256')
	}
	if profile.key_selection == 'google-first' {
		// Reuse Google's import-all-before-selecting behavior and optional kid.
		token := base64url(header_json.bytes()) + '.e30.'
		return google_id_token_keys(token, jwks_json)![0]
	}
	set := json2.decode[map[string]json2.Any](jwks_json)!
	keys := set['keys'] or { return error('missing ID token key set') }
	if keys !is []json2.Any { return error('invalid ID token key set') }
	kid := header['kid'] or { json2.Any(json2.Null{}) }
	mut candidates := []string{}
	for item in keys.as_array() {
		if item !is map[string]json2.Any { continue
		 }
		key := item.as_map()
		if profile.key_selection == 'remote-jwks' {
			if 'kid' in header && (key['kid'] or { json2.Any(json2.Null{}) }) != kid { continue
			 }
			if (key['kty'] or { json2.Any('') }) != json2.Any('RSA') { continue
			 }
			if alg := key['alg'] {
				if alg != json2.Any('RS256') { continue
				 }
			}
			if usage := key['use'] {
				if usage != json2.Any('sig') { continue
				 }
			}
			if ops := key['key_ops'] {
				if ops !is []json2.Any || !ops.as_array().any(it == json2.Any('verify')) { continue
				 }
			}
		} else {
			if (key['kid'] or { json2.Any(json2.Null{}) }) != kid { continue
			 }
			given_algorithm := key['alg'] or { json2.Any(json2.Null{}) }
			algorithm := if given_algorithm is json2.Null && profile.id == 'microsoft' {
				json2.Any('RS256')
			} else {
				given_algorithm
			}
			if algorithm != json2.Any('RS256') {
				return error('imported key algorithm does not match RS256')
			}
		}
		validate_id_token_jwk(item.json_str(), 'RS256')!
		candidates << item.json_str()
		if profile.key_selection != 'remote-jwks' { break
		 }
	}
	if candidates.len != 1 { return error('ID token key set did not resolve one key') }
	return candidates[0]
}

pub fn (profile IDTokenProviderProfile) policy(transport OAuthTransport) ProviderIDTokenPolicy {
	return ProviderIDTokenPolicy{
		disabled:           profile.disabled
		configured:         profile.configured
		allow_opaque_token: profile.allow_opaque_token
		config:             profile.config
		resolve_key:        fn [profile, transport] (header string, _ string) !string {
			url := urllib.parse(profile.jwks_url)!
			if url.scheme !in ['http', 'https'] { return error('invalid ID token key endpoint') }
			response := transport.request(Request{ method: 'GET', url: profile.jwks_url })!
			if response.status < 200 || response.status >= 300 {
				return error('ID token key request failed')
			}
			return profile.resolve_key(header, response.body)
		}
		verify_claims:      fn [profile] (payload string) !bool {
			return profile.accepts_claims(payload)
		}
	}
}
