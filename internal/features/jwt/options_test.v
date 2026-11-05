module better_auth

import crypto.ed25519
import x.json2

fn test_pre_resolved_jwt_key_signs_without_storage_lookup_or_option_mutation() ! {
	mut storage := open_memory()
	mut auth := new(Config{ secret: 'resolved-jwt-secret-at-least-32-characters' }, storage)!
	defer { auth.close() or {} }
	public, private := generate_exported_keypair(JWTOptions{})!
	resolved := Jwk{
		id:          'pre-resolved-key'
		alg:         'EdDSA'
		crv:         'Ed25519'
		public_key:  public
		private_key: private
		created_at:  '2000-01-01T00:00:00Z'
		expires_at:  '2000-01-02T00:00:00Z'
	}
	// Upstream resolvedKey bypasses selection/expiry: the trusted caller has
	// already resolved the signing material, which can be independent of storage.
	token := auth.sign_jwt_with('{"sub":"native"}', JWTSigningConfig{
		options:      JWTOptions{
			algorithm: 'ES256'
			issuer:    'call-issuer'
			audience:  'call-audience'
		}
		resolved_key: resolved
		header_json:  '{"alg":"none","kid":"forged","typ":"logout+jwt"}'
	})!
	parts := token.split('.')
	header := json2.decode[map[string]json2.Any](decode_base64url(parts[0])!.bytestr())!
	assert header['alg']!.str() == 'EdDSA'
	assert header['kid']!.str() == resolved.id
	assert header['typ']!.str() == 'logout+jwt'
	claims := json2.decode[map[string]json2.Any](decode_base64url(parts[1])!.bytestr())!
	assert claims['iss']!.str() == 'call-issuer'
	assert claims['aud']!.str() == 'call-audience'
	jwk := json2.decode[map[string]json2.Any](public)!
	key := ed25519.PublicKey(decode_base64url(jwk['x']!.str())!)
	assert ed25519.verify(key, (parts[0] + '.' + parts[1]).bytes(), decode_base64url(parts[2])!)!
	assert storage.jwks()!.len == 0
}
