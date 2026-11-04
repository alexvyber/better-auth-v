module better_auth

import crypto.aes
import crypto.ed25519
import crypto.hmac
import crypto.rand
import crypto.sha256
import json
import time
import x.json2

pub struct JWTOptions {
pub:
	algorithm                      string
	define_payload                 fn (SessionResult) !string         = default_jwt_payload         @[skip]
	get_subject                    fn (SessionResult) !Lookup[string] = default_jwt_subject @[skip]
	key_pair_configs               []JWTKeyPairConfig
	remote_url                     string
	sign                           fn (string) !string = local_jwt_sign @[skip]
	sign_with                      fn (string, string, JWTSigningConfig) !string = local_jwt_sign_with @[skip]
	curve                          string
	modulus_length                 int      = 2048
	key_store                      JWKStore = NoJWKStore{} @[skip]
	session_cookie_cache           bool
	rotation_interval              i64
	grace_period                   i64 = 2592000
	expiration_time                ?JWTExpiration @[skip]
	expires_in                     i64 = 900
	issuer                         string
	audience                       string
	audiences                      []string
	disable_private_key_encryption bool
	disable_setting_jwt_header     bool
	jwks_path                      string = '/jwks'
}

fn default_jwt_payload(_ SessionResult) !string {
	return error('custom JWT payload is not configured')
}

fn default_jwt_subject(_ SessionResult) !Lookup[string] {
	return Lookup[string]{}
}

pub struct JWTKeyPairConfig {
pub:
	algorithm      string
	curve          string
	modulus_length int = 2048
}

pub struct JWTSigningConfig {
pub:
	signing_key_id    ?string @[json: signingKeyId]
	signing_algorithm ?string @[json: signingAlgorithm]
	header_json       string = '{}'
}

fn local_jwt_sign_with(_ string, _ string, _ JWTSigningConfig) !string {
	return error('custom JWT signer is not configured')
}

fn (options JWTOptions) custom_signer() bool {
	return options.sign != local_jwt_sign || options.sign_with != local_jwt_sign_with
}

// A custom signer receives the complete JWT claims as JSON. Key management belongs
// to the configured remote service; cookie-cache signing always stays local.
fn local_jwt_sign(_ string) !string {
	return error('custom JWT signer is not configured')
}

fn normalized_jwt_options(options JWTOptions) JWTOptions {
	return JWTOptions{
		...options
		algorithm: if options.algorithm == '' { 'EdDSA' } else { options.algorithm }
	}
}

pub interface JWKStore {
mut:
	get_keys(mut EndpointContext) ![]Jwk
	create_key(Jwk, mut EndpointContext) !Jwk
}

pub struct NoJWKStore {}

pub fn (mut _ NoJWKStore) get_keys(mut _ EndpointContext) ![]Jwk {
	return error('custom JWK store is not configured')
}

pub fn (mut _ NoJWKStore) create_key(_ Jwk, mut _ EndpointContext) !Jwk {
	return error('custom JWK store is not configured')
}

fn (mut a Auth) jwk_records(options JWTOptions) ![]Jwk {
	mut records := []Jwk{}
	if options.key_store is NoJWKStore {
		records = a.storage.jwks()!
	} else {
		mut store := options.key_store
		mut context := EndpointContext{
			auth: a
		}
		records = store.get_keys(mut context)!
	}
	return records
}

fn normalize_jwk(key Jwk, options JWTOptions) Jwk {
	alg := if key.alg != '' { key.alg } else { options.algorithm }
	return Jwk{
		...key
		alg: alg
		crv: if key.crv != '' { key.crv } else { jwt_curve(alg) }
	}
}

pub struct JWTPlugin {
pub:
	options JWTOptions
}

pub fn (_ JWTPlugin) id() string {
	return 'jwt'
}

pub fn (p JWTPlugin) endpoints() []Endpoint {
	return [
		Endpoint{
			path:    p.options.jwks_path
			method:  'GET'
			handler: jwt_jwks_endpoint
		},
		Endpoint{
			path:    '/token'
			method:  'GET'
			handler: jwt_token_endpoint
		},
	]
}

fn (a &Auth) jwt_options() !JWTOptions {
	for plugin in a.config.plugins {
		if plugin is JWTPlugin { return normalized_jwt_options(plugin.options) }
	}
	return error('JWT plugin is not configured')
}

fn (a &Auth) jwks_cache_enabled() bool {
	options := a.jwt_options() or { return false }
	return options.session_cookie_cache
}

fn (a &Auth) seal_jwk(id string, plaintext string) !string {
	key := hmac.new(a.config.secret.bytes(), 'better-auth-v:jwks:v1'.bytes(), sha256.sum,
		sha256.block_size)
	gcm := aes.new_aes_gcm(key)!
	nonce := rand.bytes(aes.gcm_nonce_size)!
	mut encoded := nonce.clone()
	encoded << gcm.encrypt(plaintext.bytes(), nonce, ('jwks:' + id).bytes())!
	return base64url(encoded)
}

fn (a &Auth) private_jwk_json(record Jwk) !string {
	mut plaintext := record.private_key
	if plaintext.starts_with('"') {
		return symmetric_decrypt(SymmetricSecret(a.config.secret), json2.decode[string](plaintext)!)
	}
	if record.encrypted || plaintext.starts_with('v2.') {
		v2 := plaintext.starts_with('v2.')
		encoded := decode_base64url(if v2 { plaintext[3..] } else { plaintext })!
		if encoded.len < aes.gcm_nonce_size + aes.gcm_tag_size {
			return error('invalid encrypted JWK')
		}
		key := hmac.new(a.config.secret.bytes(), 'better-auth-v:jwks:v1'.bytes(), sha256.sum,
			sha256.block_size)
		gcm := aes.new_aes_gcm(key)!
		binding := if v2 { 'public:' + digest(record.public_key) } else { record.id }
		plaintext = gcm.decrypt(encoded[aes.gcm_nonce_size..], encoded[..aes.gcm_nonce_size], (
			'jwks:' + binding).bytes())!.bytestr()
	}
	return plaintext
}

fn (a &Auth) private_jwk(record Jwk) !ed25519.PrivateKey {
	fields := json2.decode[map[string]json2.Any](a.private_jwk_json(record)!)!
	seed := decode_base64url((fields['d'] or { return error('missing private JWK seed') }).str())!
	if seed.len != ed25519.seed_size { return error('invalid private JWK seed') }
	private := ed25519.new_key_from_seed(seed)
	public := json2.decode[map[string]json2.Any](record.public_key)!
	if (public['kty'] or { json2.Any('') }).str() != 'OKP' || (public['crv'] or { json2.Any('') }).str() != 'Ed25519' || (public['x'] or {
		json2.Any('')
	}).str() != base64url(private.public_key()) {
		return error('public and private JWK do not match')
	}
	return private
}

fn generate_exported_keypair(input JWTOptions) !(string, string) {
	options := normalized_jwt_options(input)
	mut public_json := ''
	mut private_json := ''
	if options.algorithm == 'EdDSA' {
		public, private := ed25519.generate_key()!
		public_json = '{"crv":"Ed25519","x":${json.encode(base64url(public))},"kty":"OKP"}'
		private_json = public_json[..public_json.len - 1] +
			',"d":${json.encode(base64url(private.seed()))}}'
	} else {
		public_json, private_json = openssl_keypair(options.algorithm, options.modulus_length)!
	}
	return public_json, private_json
}

fn (mut a Auth) create_signing_key(options JWTOptions) !Jwk {
	public_json, private_json := generate_exported_keypair(options)!

	id := random_token()!
	public_fields := json2.decode[map[string]json2.Any](public_json)!
	key := Jwk{
		alg:         options.algorithm
		crv:         (public_fields['crv'] or { json2.Any('') }).str()
		id:          id
		public_key:  public_json
		private_key: if options.disable_private_key_encryption {
			private_json
		} else {
			json.encode(symmetric_encrypt(SymmetricSecret(a.config.secret), private_json)!)
		}
		created_at:  time.unix_milli(a.clock_millis()).format_rfc3339()
		expires_at:  if options.rotation_interval > 0 {
			?string(time.unix_milli(a.clock_millis() + options.rotation_interval * 1000).format_rfc3339())
		} else {
			none
		}
		encrypted:   !options.disable_private_key_encryption
	}
	if options.key_store is NoJWKStore {
		a.storage.create_jwk(key)!
		return key
	}
	mut store := options.key_store
	mut context := EndpointContext{
		auth: a
	}
	created := store.create_key(key, mut context)!
	if created.id == '' { return error('custom JWK store returned an empty key id') }
	return normalize_jwk(created, options)
}

fn (mut a Auth) lookup_jwk(options JWTOptions, id ?string, algorithm ?string) !Lookup[Jwk] {
	mut latest := ?Jwk(none)
	for key in a.jwk_records(options)! {
		if requested := id {
			if key.id == requested { return Lookup[Jwk]{
					value: key
				} }
			continue
		}
		if expires := key.expires_at {
			if time.parse_rfc3339(expires)!.unix_milli() <= a.clock_millis() { continue
			 }
		}
		if requested := algorithm {
			if normalize_jwk(key, options).alg != requested { continue
			 }
		}
		if previous := latest {
			if time.parse_rfc3339(key.created_at)!.unix_milli() > time.parse_rfc3339(previous.created_at)!.unix_milli() {
				latest = key
			}
		} else {
			latest = key
		}
	}
	return Lookup[Jwk]{
		value: latest
	}
}

fn (mut a Auth) signing_key_with(options JWTOptions, config JWTSigningConfig) !Jwk {
	if id := config.signing_key_id {
		raw_key := (a.lookup_jwk(options, id, none)!).value or {
			return error('signJWT: signingKeyId "${id}" not found in JWKS. The key must be provisioned before it can be referenced.')
		}

		key := normalize_jwk(raw_key, options)
		if algorithm := config.signing_algorithm {
			if key.alg != algorithm {
				description := if raw_key.alg == '' {
					'unset (inherits keyPairConfig.alg "${options.algorithm}")'
				} else {
					key.alg
				}
				return error('signJWT: signingKeyId "${id}" has alg "${description}" but signingAlgorithm was set to "${algorithm}".')
			}
		}
		if expires := key.expires_at {
			if time.parse_rfc3339(expires)!.unix_milli() <= a.clock_millis() {
				return error('signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.')
			}
		}
		return key
	}
	if algorithm := config.signing_algorithm {
		if key := (a.lookup_jwk(options, none, algorithm)!).value {
			return normalize_jwk(key, options)
		}
		if algorithm == options.algorithm { return a.create_signing_key(options) }
		for extra in options.key_pair_configs {
			if extra.algorithm == algorithm {
				return a.create_signing_key(JWTOptions{
					...options
					algorithm:      extra.algorithm
					curve:          extra.curve
					modulus_length: extra.modulus_length
				})
			}
		}
		advertised := if options.key_pair_configs.len == 0 {
			'none'
		} else {
			options.key_pair_configs.map(it.algorithm).join(', ')
		}
		return error('signJWT: no key with alg "${algorithm}" found in JWKS. The plugin auto-mints only one key matching keyPairConfig.alg="${options.algorithm}"; additional algs configured via keyPairConfigs: ${advertised}. Add "${algorithm}" to jwks.keyPairConfigs so the plugin provisions it on first use, or mint the key explicitly via createJwk().')
	}
	if key := (a.lookup_jwk(options, none, options.algorithm)!).value {
		return normalize_jwk(key, options)
	}
	if key := (a.lookup_jwk(options, none, none)!).value { return normalize_jwk(key, options) }
	return a.create_signing_key(options)
}

fn (mut a Auth) signing_key(options JWTOptions) !Jwk {
	return a.signing_key_with(options, JWTSigningConfig{})
}

fn (mut a Auth) public_jwks_json() !string {
	options := a.jwt_options()!
	mut stored := a.jwk_records(options)!
	if stored.len == 0 {
		a.create_signing_key(options)!
		stored = a.jwk_records(options)!
		if stored.len == 0 { return error('No key sets found after creating a signing key') }
	}
	mut keys := []string{}
	for raw_key in stored {
		key := normalize_jwk(raw_key, options)
		if expires := key.expires_at {
			if time.parse_rfc3339(expires)!.unix_milli() + options.grace_period * 1000 <= a.clock_millis() { continue
			 }
		}
		stored_public := json2.decode[map[string]json2.Any](key.public_key)!
		// Publish the allowlisted Ed25519 public fields, never arbitrary stored
		// properties that might contain private material.
		mut public := map[string]json2.Any{}
		kind := (stored_public['kty'] or { json2.Any('') }).str()
		fields := if kind == 'RSA' {
			['kty', 'n', 'e']
		} else if kind == 'EC' {
			['kty', 'crv', 'x', 'y']
		} else if kind == 'OKP' {
			['kty', 'crv', 'x']
		} else {
			return error('unsupported public JWK type')
		}
		for field in fields {
			public[field] = stored_public[field] or { return error('invalid public JWK') }
		}
		public['kid'] = key.id
		public['alg'] = key.alg
		keys << json2.Any(public).json_str()
	}
	return '{"keys":[' + keys.join(',') + ']}'
}

fn (mut a Auth) sign_jwks_payload(payload map[string]json2.Any, typ string, cookie bool) !string {
	return a.sign_jwks_payload_with(payload, typ, cookie, JWTSigningConfig{})
}

fn (mut a Auth) sign_jwks_payload_with(payload map[string]json2.Any, typ string, cookie bool, config JWTSigningConfig) !string {
	options := a.jwt_options()!
	mut header := json2.decode[map[string]json2.Any](config.header_json)!
	if typ != '' { header['typ'] = typ }
	mut claims := payload.clone()
	if cookie {
		claims['iat'] = a.config.clock()
		claims['exp'] = a.config.clock() + a.config.cookie_cache.max_age
		claims['iss'] = a.base_url()
		claims['aud'] = 'better-auth:session-cache'
		data := decode_session_result(json2.Any(payload).json_str())!
		claims['sub'] = data.user.id
		claims['sid'] = data.session.token
	} else {
		if 'exp' !in claims {
			issued := if 'iat' in claims { numeric_field(claims, 'iat')! } else { a.config.clock() }
			claims['exp'] = if expiration := options.expiration_time {
				jwt_expiration(expiration, issued)!
			} else {
				f64(issued + options.expires_in)
			}
		}
		if 'iss' !in claims { claims['iss'] = if options.issuer != '' {
				options.issuer
			} else {
				a.base_url()
			}
		 }
		if 'aud' !in claims {
			default_audience := if options.audience != '' {
				options.audience
			} else {
				a.base_url()
			}
			claims['aud'] = if options.audiences.len > 0 {
				json2.Any(options.audiences.map(json2.Any(it)))
			} else {
				json2.Any(default_audience)
			}
		}
	}
	if !cookie && ((claims['iss'] or { json2.Any('') }).str() == '' || (claims['aud'] or {
		json2.Any('')
	}).str() == '') {
		a.config.log('warn',
			'[better-auth] The JWT plugin signed a JWT without an issuer or audience because no base URL was resolved for this call. Set baseURL, or jwt.issuer and jwt.audience in the JWT plugin options.')
	}
	if !cookie && options.sign_with != local_jwt_sign_with {
		return options.sign_with(js_json(json2.Any(claims)), config.header_json, config)
	}
	if !cookie && options.sign != local_jwt_sign {
		return options.sign(js_json(json2.Any(claims)))
	}
	key := a.signing_key_with(options, config)!
	header['alg'] = key.alg
	header['kid'] = key.id
	input := base64url(json2.Any(header).json_str().bytes()) + '.' +
		base64url(js_json(json2.Any(claims)).bytes())
	signature := if key.alg == 'EdDSA' {
		private := a.private_jwk(key)!
		private.sign(input.bytes())!
	} else {
		private_json := a.private_jwk_json(key)!
		validate_jwk_shape(key.alg, private_json)!
		public_fields := json2.decode[map[string]json2.Any](key.public_key)!
		private_fields := json2.decode[map[string]json2.Any](private_json)!
		for name in ['kty', 'crv', 'x', 'y', 'n', 'e'] {
			if value := public_fields[name] {
				if value.json_str() != (private_fields[name] or {
					return error('incomplete private JWK')
				}).json_str() {
					return error('public and private JWK do not match')
				}
			}
		}
		openssl_sign(key.alg, private_json, input.bytes())!
	}
	return input + '.' + base64url(signature)
}

fn audience_matches(claim json2.Any, expected []string) bool {
	if claim is string { return claim in expected }
	if claim is []json2.Any {
		for item in claim {
			if item is string && item in expected { return true }
		}
	}
	return false
}

fn (mut a Auth) verify_jwks_payload(token string, cookie bool, issuer_override string) !map[string]json2.Any {
	options := a.jwt_options()!
	parts := token.split('.')
	if parts.len != 3 { return error('invalid JWT') }
	header := json2.decode[map[string]json2.Any](decode_base64url(parts[0])!.bytestr())!
	if 'crit' in header { return error('unsupported critical JWT header') }
	if cookie && (header['typ'] or { json2.Any('') }).str() != 'better-auth.session-cache+jwt' {
		return error('invalid cache JWT type')
	}
	kid := (header['kid'] or { return error('missing JWT kid') }).str()
	mut found := ?Jwk(none)
	for key in a.jwk_records(options)! {
		if key.id == kid {
			found = key
			break
		}
	}
	key := normalize_jwk(found or { return error('unknown JWT kid') }, options)
	if (header['alg'] or { json2.Any('') }).str() != key.alg {
		return error('JWT algorithm does not match stored key')
	}
	validate_jwk_shape(key.alg, key.public_key)!
	message := (parts[0] + '.' + parts[1]).bytes()
	signature := decode_base64url(parts[2])!
	verified := if key.alg == 'EdDSA' {
		public := json2.decode[map[string]json2.Any](key.public_key)!
		x := decode_base64url((public['x'] or { return error('missing public key') }).str())!
		if x.len != ed25519.public_key_size { return error('invalid Ed25519 public key') }
		ed25519.verify(ed25519.PublicKey(x), message, signature)!
	} else {
		openssl_verify(key.alg, key.public_key, message, signature)!
	}
	if !verified { return error('invalid JWT signature') }

	claims := json2.decode[map[string]json2.Any](decode_base64url(parts[1])!.bytestr())!
	tolerance := if cookie { i64(15) } else { i64(0) }
	if 'exp' in claims && numeric_field(claims, 'exp')! <= a.config.clock() - tolerance {
		return error('expired JWT')
	}
	if 'nbf' in claims && numeric_field(claims, 'nbf')! > a.config.clock() + tolerance {
		return error('JWT not yet valid')
	}
	if 'iat' in claims { numeric_field(claims, 'iat')! }
	issuer := if cookie {
		a.base_url()
	} else if issuer_override != '' {
		issuer_override
	} else if options.issuer != '' {
		options.issuer
	} else {
		a.base_url()
	}
	if (cookie || issuer != '') && (claims['iss'] or { json2.Any('') }).str() != issuer {
		return error('JWT issuer mismatch')
	}
	default_audience := if options.audience != '' { options.audience } else { a.base_url() }
	expected_audiences := if cookie {
		['better-auth:session-cache']
	} else if options.audiences.len > 0 {
		options.audiences
	} else {
		[default_audience]
	}
	if !cookie && (issuer == '' || expected_audiences == ['']) {
		a.config.log('warn',
			'[better-auth] The JWT plugin is verifying a JWT without checking its issuer or audience because no base URL was resolved for this call. Set baseURL, or jwt.issuer and jwt.audience in the JWT plugin options.')
	}
	if (cookie || expected_audiences != ['']) && !audience_matches(claims['aud'] or {
		json2.Any(json2.Null{})
	}, expected_audiences) {
		return error('JWT audience mismatch')
	}
	if cookie {
		data := decode_session_result(json2.Any(claims).json_str())!
		if (claims['sub'] or { json2.Any('') }).str() != data.user.id || (claims['sid'] or {
			json2.Any('')
		}).str() != data.session.token {
			return error('cache JWT identity mismatch')
		}
	} else if (claims['sub'] or { json2.Any('') }).str() == '' || (claims['aud'] or {
		json2.Any('')
	}).str() == '' {
		return error('missing JWT subject or audience')
	}
	return claims
}

fn jwt_jwks_endpoint(mut context EndpointContext, _ Request) !Response {
	if (context.auth.jwt_options()!).remote_url != '' { return fail(404, 'NOT_FOUND', 'Not found') }
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    context.auth.public_jwks_json()!
	}
}

fn (mut a Auth) session_jwt(current SessionResult) !string {
	options := a.jwt_options()!
	encoded := if options.define_payload == default_jwt_payload {
		a.user_json(current.user)
	} else {
		options.define_payload(current)!
	}
	mut payload := json2.decode[map[string]json2.Any](encoded)!
	if 'iat' !in payload { payload['iat'] = a.config.clock() }
	payload['sub'] = (options.get_subject(current)!).value or { current.user.id }
	return a.sign_jwks_payload(payload, '', false)
}

fn jwt_token_endpoint(mut context EndpointContext, req Request) !Response {
	current := context.auth.require_session(RequestContext{ headers: req.headers }, false)!
	return json_response({
		'token': context.auth.session_jwt(current)!
	})
}

// Signing and verification APIs are server-only operations, never HTTP routes.
pub fn (mut context EndpointContext) sign_jwt(payload_json string) !string {
	return context.auth.sign_jwks_payload(json2.decode[map[string]json2.Any](payload_json)!, '',
		false)
}

pub fn (mut a Auth) sign_jwt(payload_json string) !string {
	return a.with_internal(fn [payload_json] (mut context EndpointContext) !string {
		return context.sign_jwt(payload_json)
	})
}

pub fn (mut a Auth) get_jwks() !string {
	if (a.jwt_options()!).remote_url != '' { return fail(404, 'NOT_FOUND', 'Not found') }
	return a.with_internal(fn (mut context EndpointContext) !string {
		return context.auth.public_jwks_json()
	})
}

pub fn (mut context EndpointContext) stored_jwks() ![]Jwk {
	return context.auth.storage.jwks()
}

pub fn (mut context EndpointContext) store_jwk(key Jwk) !Jwk {
	context.auth.storage.create_jwk(key)!
	return key
}

pub fn (mut context EndpointContext) verify_jwt(token string, issuer string) !Lookup[string] {
	payload := context.auth.verify_jwks_payload(token, false, issuer) or { return Lookup[string]{} }
	return Lookup[string]{
		value: js_json(json2.Any(payload))
	}
}

pub fn (mut a Auth) verify_jwt(token string, issuer string) !Lookup[string] {
	encoded := a.with_internal(fn [token, issuer] (mut context EndpointContext) !string {
		return (context.verify_jwt(token, issuer)!).value or { 'null' }
	})!
	if encoded == 'null' { return Lookup[string]{} }
	return Lookup[string]{
		value: encoded
	}
}

pub fn (mut a Auth) get_token(context RequestContext) !string {
	response := a.invoke('GET', '/token', '', context)!
	return (json2.decode[map[string]json2.Any](response.body)!['token'] or {
		return error('missing JWT')
	}).str()
}

// Trusted callers can pin a signing key or declared algorithm and supply profile
// headers. Resolved key identity always overrides caller alg/kid header fields.
pub fn (mut context EndpointContext) sign_jwt_with(payload_json string, config JWTSigningConfig) !string {
	return context.auth.sign_jwks_payload_with(json2.decode[map[string]json2.Any](payload_json)!,
		'', false, config)
}

pub fn (mut a Auth) sign_jwt_with(payload_json string, config JWTSigningConfig) !string {
	return a.with_internal(fn [payload_json, config] (mut context EndpointContext) !string {
		return context.sign_jwt_with(payload_json, config)
	})
}

// Trusted operations that already own the connection must use their context;
// reacquiring Auth's mutex or starting a nested DB transaction would deadlock.
pub fn (mut context EndpointContext) get_token(request RequestContext) !string {
	current := context.auth.require_session(request, false)!
	return context.auth.session_jwt(current)
}
