module better_auth

import crypto.ed25519
import x.json2

pub const client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
pub const private_key_jwt_algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256',
	'ES384', 'ES512', 'EdDSA']

pub struct ClientAssertionContext {
pub:
	client_id      string @[json: clientId]
	token_endpoint string @[json: tokenEndpoint]
	grant_type     string @[json: grantType]
}

pub struct PrivateKeyJWTOptions {
pub:
	private_key_jwk string
	private_key_pem string
	kid             ?string
	algorithm       ?string
	expires_in      f64 = 120
}

pub fn validate_private_key_jwt_options(options PrivateKeyJWTOptions) !string {
	if options.private_key_jwk == '' && options.private_key_pem == '' {
		return error('private_key_jwt requires either privateKeyJwk or privateKeyPem')
	}
	key := if options.private_key_jwk != '' {
		json2.decode[map[string]json2.Any](options.private_key_jwk)!
	} else {
		map[string]json2.Any{}
	}
	given := options.algorithm or { '' }
	embedded := key['alg'] or { json2.Any(json2.Null{}) }
	mut candidates := []string{}
	if given != '' { candidates << given }
	if embedded is string { candidates << embedded }
	for candidate in candidates {
		if candidate !in private_key_jwt_algorithms {
			return error('Unsupported private_key_jwt signing algorithm: ${candidate}. Use one of ${private_key_jwt_algorithms.join(', ')}.')
		}
	}
	if given != '' && embedded is string && given != embedded.str() {
		return error('JWK alg "${embedded.str()}" does not match configured algorithm "${given}". Remove the JWK alg field, or pass an algorithm that matches the JWK.')
	}
	return options.algorithm or {
		if embedded is string {
			embedded.str()
		} else {
			'RS256'
		}
	}
}

pub fn sign_private_key_jwt_client_assertion(context ClientAssertionContext, options PrivateKeyJWTOptions, now i64) !string {
	algorithm := validate_private_key_jwt_options(options)!
	encoded := if options.private_key_jwk != '' {
		options.private_key_jwk
	} else {
		openssl_private_pem_jwk(options.private_key_pem, algorithm)!
	}
	key := json2.decode[map[string]json2.Any](encoded)!
	validate_jwk_shape(algorithm, encoded)!
	if 'd' !in key { return error('private_key_jwt requires a private JWK') }
	if ext := key['ext'] {
		if ext !is bool { return error('invalid JWK extractability') }
	}
	if operations := key['key_ops'] {
		if operations !is []json2.Any || operations.as_array() != [json2.Any('sign')] {
			return error('private_key_jwt JWK must permit signing')
		}
	}
	mut header := {
		'alg': json2.Any(algorithm)
		'typ': json2.Any('JWT')
	}
	kid := options.kid or { (key['kid'] or { json2.Any('') }).str() }
	if kid != '' { header['kid'] = kid }
	payload := {
		'iss': json2.Any(context.client_id)
		'sub': json2.Any(context.client_id)
		'aud': json2.Any(context.token_endpoint)
		'iat': json2.Any(now)
		'exp': json2.Any(f64(now) + options.expires_in)
		'jti': json2.Any(crypto_uuid()!)
	}
	input := base64url(js_json(json2.Any(header)).bytes()) + '.' +
		base64url(js_json(json2.Any(payload)).bytes())
	signature := if algorithm == 'EdDSA' {
		seed := decode_base64url((key['d'] or { return error('missing Ed25519 seed') }).str())!
		if seed.len != ed25519.seed_size { return error('invalid Ed25519 seed') }
		private := ed25519.new_key_from_seed(seed)
		public :=
			decode_base64url((key['x'] or { return error('missing Ed25519 public key') }).str())!
		if public != []u8(private.public_key()) {
			return error('Ed25519 public and private keys do not match')
		}
		private.sign(input.bytes())!
	} else {
		openssl_sign(algorithm, encoded, input.bytes())!
	}
	return input + '.' + base64url(signature)
}
