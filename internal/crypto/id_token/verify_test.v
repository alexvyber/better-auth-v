module better_auth

import crypto.sha256
import encoding.hex
import json
import x.json2

struct IDTokenFixtureTransport {
	body string
}

fn (transport IDTokenFixtureTransport) request(request Request) !Response {
	assert request.method == 'GET'
	assert request.url == 'https://www.googleapis.com/oauth2/v3/certs'
	return Response{
		status: 200
		body:   transport.body
	}
}

fn id_token_fixture(private_key string, payload string, header string) !string {
	input := base64url(header.bytes()) + '.' + base64url(payload.bytes())
	return input + '.' + base64url(openssl_sign('RS256', private_key, input.bytes())!)
}

fn test_native_id_token_trust_nonce_required_claims_and_tolerance() ! {
	public, private := openssl_keypair('RS256', 2048)!
	nonce := 'expected-nonce'
	payload := '{"iss":"issuer","aud":"client","sub":"subject","exp":1893455970.5,"iat":1893456000,"nonce":${json.encode(hex.encode(sha256.sum(nonce.bytes())))}}'
	token := id_token_fixture(private, payload, '{"alg":"RS256"}')!
	config := IDTokenVerifyConfig{
		issuers:          ['issuer']
		audiences:        ['client']
		algorithms:       ['RS256']
		nonce:            nonce
		nonce_comparison: 'exact-or-sha256'
		max_token_age:    f64(3600)
	}
	verified := verify_id_token_with_jwk(token, public, config, 1893456000)!
	assert (json2.decode[map[string]json2.Any](verified)!['sub'] or { panic('missing subject') }).str() == 'subject'
	mut rejected := false
	verify_id_token_with_jwk(token, public, IDTokenVerifyConfig{
		...config
		nonce_comparison: 'exact'
	}, 1893456000) or {
		assert err.msg() == 'ID-token nonce mismatch'
		rejected = true
	}
	assert rejected
	mut expired := false
	verify_id_token_with_jwk(token, public, config, 1893456001) or {
		assert err.msg() == 'expired ID token'
		expired = true
	}
	assert expired
}

fn test_native_google_id_token_candidate_iteration_and_resolver_policy() ! {
	public, private := openssl_keypair('RS256', 2048)!
	other_public, _ := openssl_keypair('RS256', 2048)!
	payload := '{"iss":"accounts.google.com","aud":["other","client"],"sub":"subject","exp":1893459600,"iat":1893456000,"hd":"example.com"}'
	token := id_token_fixture(private, payload, '{"alg":"RS256"}')!
	jwks := '{"keys":[${other_public},${public}]}'
	assert verify_google_id_token_jwks(token, ['client'], '', jwks, 1893456000, false).value != none
	assert verify_google_id_token_jwks(token, ['client'], '', jwks, 1893456000, true).value == none
	provider := GoogleProvider{
		client_ids:   ['other', 'client']
		hd:           'example.com'
		clock_millis: fn () i64 {
			return 1893456000000
		}
		transport:    IDTokenFixtureTransport{
			body: '{"keys":[${public}]}'
		}
	}
	assert provider.verify_id_token(token, '').value != none
	assert GoogleProvider{
		...provider
		hd: 'different.example'
	}.verify_id_token(token, '').value == none
	assert GoogleProvider{
		...provider
		disable_id_token_sign_in: true
	}.verify_id_token(token, '').value == none
}
