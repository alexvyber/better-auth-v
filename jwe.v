module better_auth

import crypto.aes
import crypto.cipher
import crypto.hkdf
import crypto.hmac
import crypto.rand
import crypto.sha256
import crypto.sha512
import encoding.hex
import json
import x.json2

fn jwt_encryption_key(secret string, salt string, length int) ![]u8 {
	return hkdf.key(sha256.new, secret.bytes(), salt.bytes(),
		'BetterAuth.js Generated Encryption Key', length)
}

fn key_thumbprint(key []u8) string {
	return base64url(sha256.sum('{"k":${json.encode(base64url(key))},"kty":"oct"}'.bytes()))
}

fn jwe_authentication_input(header string, iv []u8, ciphertext []u8) []u8 {
	mut input := header.bytes()
	input << iv
	input << ciphertext
	bits := u64(header.len) * 8
	for shift := 56; shift >= 0; shift -= 8 {
		input << u8(bits >> shift)
	}
	return input
}

fn crypto_uuid() !string {
	mut bytes := rand.bytes(16)!
	bytes[6] = (bytes[6] & 15) | 64
	bytes[8] = (bytes[8] & 63) | 128
	value := hex.encode(bytes)
	return '${value[..8]}-${value[8..12]}-${value[12..16]}-${value[16..20]}-${value[20..]}'
}

// JOSE direct encryption, compatible with upstream's HKDF/A256CBC-HS512 JWTs.
// A caller supplies its clock explicitly so this primitive is deterministic in
// tests and does not accidentally use wall time for an application-owned clock.
pub fn symmetric_encode_jwt(payload_json string, secret string, salt string, expires_in i64, now i64) !string {
	mut payload := json2.decode[map[string]json2.Any](payload_json)!
	payload['iat'] = now
	payload['exp'] = now + expires_in
	payload['jti'] = crypto_uuid()!
	key := jwt_encryption_key(secret, salt, 64)!
	header :=
		base64url('{"alg":"dir","enc":"A256CBC-HS512","kid":${json.encode(key_thumbprint(key))}}'.bytes())
	iv := rand.bytes(16)!
	mut plaintext := json2.Any(payload).json_str().bytes()
	padding := 16 - plaintext.len % 16
	plaintext << []u8{len: padding, init: u8(padding)}
	mut cbc := cipher.new_cbc(aes.new_cipher(key[32..]), iv)
	mut ciphertext := []u8{len: plaintext.len}
	cbc.encrypt_blocks(mut ciphertext, plaintext)
	tag := hmac.new(key[..32], jwe_authentication_input(header, iv, ciphertext), sha512.sum512,
		sha512.block_size)[..32]
	return '${header}..${base64url(iv)}.${base64url(ciphertext)}.${base64url(tag)}'
}

// Authenticates before unpadding or decoding. Legacy A256GCM is accepted with
// its own 256-bit HKDF key; algorithm changes cannot reuse a 512-bit key/kid.
pub fn symmetric_decode_jwt(token string, secret string, salt string, now i64) !string {
	parts := token.split('.')
	if parts.len != 5 || parts[1] != '' { return error('invalid direct-encryption JWE') }
	header := json2.decode[map[string]json2.Any](decode_base64url(parts[0])!.bytestr())!
	if (header['alg'] or { json2.Any('') }).str() != 'dir' || 'crit' in header || 'zip' in header {
		return error('unsupported JWE header')
	}
	enc := (header['enc'] or { json2.Any('') }).str()
	if enc !in ['A256CBC-HS512', 'A256GCM'] { return error('unsupported JWE encryption') }
	key := jwt_encryption_key(secret, salt, if enc == 'A256CBC-HS512' { 64 } else { 32 })!
	if kid := header['kid'] {
		if kid !is string || kid.str() != key_thumbprint(key) { return error('unknown JWE key') }
	}
	iv := decode_base64url(parts[2])!
	ciphertext := decode_base64url(parts[3])!
	tag := decode_base64url(parts[4])!
	mut plaintext := []u8{}
	if enc == 'A256CBC-HS512' {
		if iv.len != 16 || tag.len != 32 || ciphertext.len == 0 || ciphertext.len % 16 != 0 {
			return error('invalid CBC JWE lengths')
		}
		expected := hmac.new(key[..32], jwe_authentication_input(parts[0], iv, ciphertext),
			sha512.sum512, sha512.block_size)[..32]
		if !hmac.equal(expected, tag) { return error('invalid JWE authentication tag') }
		mut cbc := cipher.new_cbc(aes.new_cipher(key[32..]), iv)
		plaintext = []u8{len: ciphertext.len}
		cbc.decrypt_blocks(mut plaintext, ciphertext)
		padding := int(plaintext.last())
		if padding == 0 || padding > 16 { return error('invalid JWE padding') }
		for byte in plaintext[plaintext.len - padding..] {
			if byte != padding { return error('invalid JWE padding') }
		}
		plaintext = plaintext[..plaintext.len - padding].clone()
	} else {
		if iv.len != aes.gcm_nonce_size || tag.len != aes.gcm_tag_size {
			return error('invalid GCM JWE lengths')
		}
		mut sealed := ciphertext.clone()
		sealed << tag
		gcm := aes.new_aes_gcm(key)!
		plaintext = gcm.decrypt(sealed, iv, parts[0].bytes())!
	}
	claims := json2.decode[map[string]json2.Any](plaintext.bytestr())!
	if 'exp' in claims && numeric_date_field(claims, 'exp')! <= f64(now - 15) {
		return error('expired JWE')
	}
	if 'nbf' in claims && numeric_date_field(claims, 'nbf')! > f64(now + 15) {
		return error('JWE not yet valid')
	}
	if 'iat' in claims { numeric_date_field(claims, 'iat')! }
	return plaintext.bytestr()
}
