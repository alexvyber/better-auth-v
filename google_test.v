module better_auth

import json
import net.urllib
import x.json2

struct GoogleFixtureTransport {
	body string
}

fn (transport GoogleFixtureTransport) request(request Request) !Response {
	assert request.method == 'POST'
	assert request.url == 'https://oauth2.googleapis.com/token'
	assert request.headers['content-type'] == 'application/x-www-form-urlencoded'
	form := urllib.parse_query(request.body)!
	assert (form.get('client_id') or { '' }) == 'client'
	assert (form.get('client_secret') or { '' }) == 'secret'
	assert (form.get('code_verifier') or { '' }) == 'verifier'
	assert (form.get('code') or { '' }) == 'code'
	assert (form.get('grant_type') or { '' }) == 'authorization_code'
	return Response{
		status: 200
		body:   transport.body
	}
}

fn test_native_google_code_exchange_and_authorization_configuration() ! {
	profile := '{"sub":"subject","email":"user@example.com","email_verified":true,"name":"Name","hd":"example.com"}'
	token := base64url('{"alg":"RS256"}'.bytes()) + '.' + base64url(profile.bytes()) +
		'.transport-fixture'
	provider := GoogleProvider{
		client_id:     'client'
		client_secret: 'secret'
		scope:         ['calendar', 'email']
		hd:            'example.com'
		access_type:   'offline'
		clock_millis:  fn () i64 {
			return 1893456000123
		}
		transport:     GoogleFixtureTransport{
			body: '{"access_token":"access","refresh_token":"refresh","id_token":${json.encode(token)},"expires_in":12.5,"scope":["email"," read ",false,""]}'
		}
	}
	url := urllib.parse(provider.authorization_url('state', 'challenge',
		'http://localhost:3000/api/auth/callback/google')!)!
	assert (url.query().get('scope') or { '' }) == 'email profile openid calendar email'
	assert (url.query().get('include_granted_scopes') or { '' }) == 'true'
	assert (url.query().get('hd') or { '' }) == 'example.com'
	identity := provider.exchange('code', 'verifier',
		'http://localhost:3000/api/auth/callback/google')!
	assert identity.id == 'subject' && identity.email_verified
	assert (identity.tokens.access_token or { '' }) == 'access'
	assert (identity.tokens.scope or { '' }) == 'email,read'
	assert (identity.tokens.access_token_expires_at or { '' }) == stamp_millis(1893456012623)
}

fn test_native_google_hosted_domain_and_scope_helpers() ! {
	for claim in [json2.Any(''), json2.Any(json2.Null{}), json2.Any(1), json2.Any('other.example')] {
		assert google_hosted_domain_allowed('', claim)
		assert !google_hosted_domain_allowed('example.com', claim)
	}
	assert google_hosted_domain_allowed('*', json2.Any('workspace.example'))
	assert !google_hosted_domain_allowed('*', json2.Any(''))
	assert google_hosted_domain_allowed('example.com', json2.Any('example.com'))
	assert !google_hosted_domain_allowed('example.com', json2.Any('EXAMPLE.COM'))
	assert oauth_scope_field(json2.Any(' email\tread\n write ')) == ['email', 'read', 'write']
	assert merge_oauth_scopes('email,read,email', ['write', ' read ', '']) == 'email,read,write'
	parsed := parse_oauth_tokens('{"expires_in":0,"refresh_token_expires_in":"0","scope":[" email ",false,""]}',
		1893456000123)!
	assert parsed.access_token_expires_at == none
	assert (parsed.refresh_token_expires_at or { '' }) == stamp_millis(1893456000123)
	assert (parsed.scope or { '' }) == 'email'
}
