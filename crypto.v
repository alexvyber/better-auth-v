module better_auth

import crypto.argon2
import crypto.aes
import crypto.hmac
import crypto.rand
import crypto.sha256
import crypto.scrypt
import encoding.base64
import encoding.hex
import better_auth.normalization

// Matches Better Auth's salt encoding, parameters, key size, and NFKC input.
pub struct ScryptHasher {}

pub fn (_ ScryptHasher) hash(password string) !string {
	salt := hex.encode(rand.bytes(16)!)
	key := scrypt.scrypt(normalization.nfkc(password).bytes(), salt.bytes(), 16384, 16, 1, 64)!
	return salt + ':' + hex.encode(key)
}

pub fn (_ ScryptHasher) verify(password string, encoded string) !bool {
	parts := encoded.split(':')
	if parts.len < 2 || parts[0] == '' || parts[1] == '' { return error('Invalid password hash') }
	key := scrypt.scrypt(normalization.nfkc(password).bytes(), parts[0].bytes(), 16384, 16, 1, 64)!
	return hmac.equal(hex.encode(key).bytes(), parts[1].bytes())
}

pub struct Argon2Hasher {}

pub fn (_ Argon2Hasher) hash(password string) !string {
	return argon2.generate_from_password(password.bytes())
}

pub fn (_ Argon2Hasher) verify(password string, encoded string) !bool {
	argon2.compare_hash_and_password(password.bytes(), encoded.bytes()) or { return false }
	return true
}

fn random_token() !string {
	return hex.encode(rand.bytes(32)!)
}

fn digest(token string) string {
	return hex.encode(sha256.sum(token.bytes()))
}

fn (a &Auth) sign_cookie(token string) string {
	mac := hmac.new(a.config.secret.bytes(), token.bytes(), sha256.sum, sha256.block_size)
	return token + '.' + base64.encode(mac)
}

fn (a &Auth) verify_cookie(value string) ?string {
	token, signature := value.split_once('.') or { return none }
	if token.len != 64 || signature.len > 64 { return none }
	return a.verify_signed_value(value)
}

fn (a &Auth) verify_signed_value(value string) ?string {
	token, signature := value.split_once('.') or { return none }
	if signature.len > 64 { return none }
	expected := a.sign_cookie(token).all_after('.')
	if !hmac.equal(expected.bytes(), signature.bytes()) { return none }
	return token
}

fn (a &Auth) seal_session_token(session Session) !string {
	key := hmac.new(a.config.secret.bytes(), 'better-auth-v:session-token:v1'.bytes(), sha256.sum,
		sha256.block_size)
	cipher := aes.new_aes_gcm(key)!
	nonce := rand.bytes(aes.gcm_nonce_size)!
	sealed := cipher.encrypt(session.token.bytes(), nonce, ('session:' + session.id + ':' +
		session.user_id).bytes())!
	mut encoded := nonce.clone()
	encoded << sealed
	return base64.url_encode(encoded)
}

fn (a &Auth) unseal_session_token(session Session) !string {
	encoded := base64.url_decode(session.encrypted_token)
	if encoded.len < aes.gcm_nonce_size + aes.gcm_tag_size {
		return error('invalid sealed session token')
	}
	key := hmac.new(a.config.secret.bytes(), 'better-auth-v:session-token:v1'.bytes(), sha256.sum,
		sha256.block_size)
	cipher := aes.new_aes_gcm(key)!
	return cipher.decrypt(encoded[aes.gcm_nonce_size..], encoded[..aes.gcm_nonce_size], (
		'session:' + session.id + ':' + session.user_id).bytes())!.bytestr()
}
