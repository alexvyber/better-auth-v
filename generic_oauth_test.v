module better_auth

struct NativeOIDCTransport {
	discovery string
	jwks      string
}

fn (transport NativeOIDCTransport) request(request Request) !Response {
	assert request.method == 'GET'
	return Response{
		status: 200
		body:   if request.url.ends_with('/discovery') {
			transport.discovery
		} else {
			transport.jwks
		}
	}
}

fn test_native_oidc_discovery_signature_nonce_and_subject_binding() ! {
	public, private := openssl_keypair('RS256', 2048)!
	transport := NativeOIDCTransport{
		discovery: '{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"/jwks","id_token_signing_alg_values_supported":["RS256"]}'
		jwks:      '{"keys":[${public}]}'
	}
	payload := '{"iss":"https://issuer.example","aud":"native-client","sub":"immutable-subject","id":"mutable-id","email":"native@example.com","email_verified":true,"exp":2000000000,"iat":1900000000,"nonce":"native-nonce"}'
	input := base64url('{"alg":"RS256"}'.bytes()) + '.' + base64url(payload.bytes())
	token := input + '.' + base64url(openssl_sign('RS256', private, input.bytes())!)
	provider := (resolve_generic_oauth_provider(GenericOAuthConfig{
		provider_id:                   'tinyauth'
		client_id:                     'native-client'
		discovery_url:                 'https://issuer.example/discovery'
		require_id_token_verification: true
		disable_sign_up:               true
		transport:                     transport
		clock_millis:                  fn () i64 {
			return 1900000000000
		}
		get_token:                     fn [token] (_ string, _ string, _ string) !OAuthTokens {
			return OAuthTokens{
				id_token: token
			}
		}
	})!).value or { return error('native discovery did not register provider') }
	assert provider.requires_nonce()
	assert provider.jwks_uri == 'https://issuer.example/jwks'
	identity := provider.exchange_bound('code', 'verifier', 'https://app.example/callback',
		'native-nonce')!
	assert identity.id == 'immutable-subject'
	assert identity.email == 'native@example.com'
	mut rejected := false
	provider.exchange_bound('code', 'verifier', 'https://app.example/callback', 'wrong-nonce') or {
		rejected = true
	}
	assert rejected
	assert !provider.sign_up_allowed(false)
	assert !provider.sign_up_allowed(true)
	assert provider.verify_id_token(token[..token.len - 2] + 'xx', '').value == none
}
