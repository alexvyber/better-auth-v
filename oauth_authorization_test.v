module better_auth

import net.urllib

fn test_native_oauth_authorization_pkce_reserved_parameters_and_ordered_query() ! {
	url := create_oauth_authorization_url(OAuthAuthorizationRequest{
		options:                OAuthAuthorizationOptions{
			client_id: 'client'
		}
		authorization_endpoint: 'https://idp.example/auth?state=old&state=other&custom=first&custom=second'
		state:                  'trusted'
		redirect_uri:           'https://app.example/callback'
		code_verifier:          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
		additional_params:      {
			'state':  'forged'
			'custom': 'new'
		}
	})!
	parsed := urllib.parse(url)!
	assert (parsed.query().get('code_challenge') or { '' }) == 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	assert parsed.query().get_all('state') == ['trusted']
	assert parsed.query().get_all('custom') == ['new']
	assert !url.contains('forged')
}

fn test_native_oauth_basic_credentials_and_lenient_utf8() ! {
	encoded := encode_basic_credentials('id:!()', '🔑 +&secret')
	decoded := decode_basic_credentials(encoded)!
	assert decoded.client_id == 'id:!()'
	assert decoded.client_secret == '🔑 +&secret'
	assert oauth_form_encode("!*'()~ ") == '%21*%27%28%29%7E+'
	assert oauth_form_decode('%E1%80/%ZZ+%20') == '�/%ZZ  '
	mut rejected := false
	decode_basic_credentials('Basic\tinvalid') or { rejected = true }
	assert rejected
}
