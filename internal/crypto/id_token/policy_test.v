module better_auth

fn test_id_token_policy_callback_precedence_and_fail_closed() {
	missing := ProviderIDTokenPolicy{}
	assert !missing.supports_sign_in()
	assert !missing.verify('opaque', '', 0)
	override := ProviderIDTokenPolicy{
		override_verify: fn (token string, nonce string) !bool {
			return token == 'opaque' && nonce == 'expected'
		}
		custom_verify:   fn (_ string, _ string) !bool {
			panic('override must run first')
		}
	}
	assert override.supports_sign_in()
	assert override.verify('opaque', 'expected', 0)
	assert !ProviderIDTokenPolicy{
		...override
		disabled: true
	}.verify('opaque', 'expected', 0)
	assert !ProviderIDTokenPolicy{
		...override
		disabled: true
	}.supports_sign_in()
	assert !ProviderIDTokenPolicy{
		override_verify: fn (_ string, _ string) !bool {
			return error('application failure')
		}
	}.verify('opaque', '', 0)
	assert !ProviderIDTokenPolicy{
		configured:    true
		custom_verify: fn (_ string, _ string) !bool {
			return error('remote failure')
		}
	}.verify('opaque', '', 0)
	assert ProviderIDTokenPolicy{
		configured:         true
		allow_opaque_token: true
	}.verify('opaque', 'ignored', 0)
	assert !ProviderIDTokenPolicy{
		configured: true
	}.verify('opaque', '', 0)
	assert !ProviderIDTokenPolicy{
		configured:  true
		resolve_key: fn (_ string, _ string) !string {
			panic('audience must be checked first')
		}
	}.verify('e30.e30.signature', '', 0)
}

fn test_id_token_profile_key_selection_and_metadata() ! {
	public, _ := openssl_keypair('RS256', 2048)!
	other, _ := openssl_keypair('RS256', 2048)!
	key := public.trim_right('}') + ',"kid":"selected","alg":"RS256"}'
	wrong := other.trim_right('}') + ',"kid":"other","alg":"RS256"}'
	jwks := '{"keys":[${wrong},${key}]}'
	for id in ['apple', 'cognito', 'facebook', 'google', 'microsoft'] {
		profile := id_token_provider_profile(id,
			'{"clientId":"client","region":"us-east-1","userPoolId":"pool"}')!
		assert profile.config.algorithms == ['RS256']
		selected := profile.resolve_key('{"alg":"RS256","kid":"selected"}', jwks)!
		assert selected.contains('"kid":"selected"')
		mut rejected := false
		profile.resolve_key('{"alg":"HS256","kid":"selected"}', jwks) or { rejected = true }
		assert rejected
	}
	microsoft := id_token_provider_profile('microsoft', '{"clientId":"client"}')!
	assert microsoft.resolve_key('{"alg":"RS256"}', '{"keys":[${public}]}')! != ''
	assert microsoft.resolve_key('{"alg":"RS256"}',
		'{"keys":[${public.trim_right('}')},"alg":null}]}')! != ''
	facebook := id_token_provider_profile('facebook', '{"clientId":"client"}')!
	mut ambiguous := false
	facebook.resolve_key('{"alg":"RS256"}', jwks) or { ambiguous = true }
	assert ambiguous
	assert id_token_provider_profile('paypal', '{}')!.configured == false
}

fn test_id_token_profile_microsoft_tenant_binding_and_apple_audience() ! {
	organizations := id_token_provider_profile('microsoft',
		'{"tenantId":"organizations","authority":"https://custom.example///"}')!
	assert organizations.jwks_url == 'https://custom.example/organizations/discovery/v2.0/keys'
	assert organizations.accepts_claims('{"tid":"work","iss":"https://custom.example/work/v2.0"}')!
	assert !organizations.accepts_claims('{"tid":"work","iss":"https://custom.example/other/v2.0"}')!
	assert !organizations.accepts_claims('{"tid":1,"iss":"https://custom.example/1/v2.0"}')!
	assert !organizations.accepts_claims('{"tid":"9188040d-6c67-4c5b-b112-36a304b66dad","iss":"https://custom.example/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"}')!
	apple := id_token_provider_profile('apple',
		'{"clientId":"web","appBundleIdentifier":"app","audience":[]}')!
	assert apple.config.audiences == ['app']
	assert apple.config.nonce_comparison == 'exact-or-sha256'
}

fn test_id_token_policy_signature_then_claim_callback() ! {
	public, private := openssl_keypair('RS256', 2048)!
	config :=
		id_token_config_from_json('{"issuer":"issuer","audience":"client","algorithms":["RS256"],"maxTokenAge":"1h"}')!
	token := policy_token_fixture(private,
		'{"iss":"issuer","aud":"client","sub":"subject","iat":1893456000,"exp":1893459600}',
		'{"alg":"RS256"}')!
	policy := ProviderIDTokenPolicy{
		configured:    true
		config:        config
		resolve_key:   fn [public] (_ string, _ string) !string {
			return public
		}
		verify_claims: fn (payload string) !bool {
			return payload.contains('subject')
		}
	}
	assert policy.verify(token, '', 1893456000)
	assert !ProviderIDTokenPolicy{
		...policy
		verify_claims: fn (_ string) !bool {
			return false
		}
	}.verify(token, '', 1893456000)
	assert !ProviderIDTokenPolicy{
		...policy
		verify_claims: fn (_ string) !bool {
			return error('claim callback failure')
		}
	}.verify(token, '', 1893456000)
	assert !policy.verify(token, '', 1893460000)
}

fn policy_token_fixture(private_key string, payload string, header string) !string {
	input := base64url(header.bytes()) + '.' + base64url(payload.bytes())
	return input + '.' + base64url(openssl_sign('RS256', private_key, input.bytes())!)
}
