module better_auth

import net.openssl as _
import x.json2

#include "@VMODROOT/jws_openssl.h"

fn C.ba_chacha_encrypt(&u8, &u8, &u8, usize, &u8) int
fn C.ba_chacha_decrypt(&u8, &u8, &u8, usize, &u8) int

fn C.ba_generate_jwk(&char, int, &u8, usize, &usize) int
fn C.ba_sign_jwk(&char, &&char, &u8, usize, &u8, usize, &usize) int
fn C.ba_verify_jwk(&char, &&char, &u8, usize, &u8, usize) int

const jwt_algorithms = ['EdDSA', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256',
	'PS384', 'PS512']

fn jwt_curve(algorithm string) string {
	return match algorithm {
		'EdDSA' { 'Ed25519' }
		'ES256' { 'P-256' }
		'ES384' { 'P-384' }
		'ES512' { 'P-521' }
		else { '' }
	}
}

fn validate_jwk_shape(algorithm string, encoded string) ! {
	if algorithm !in jwt_algorithms { return error('unsupported JWT algorithm') }
	key := json2.decode[map[string]json2.Any](encoded)!
	kind := (key['kty'] or { json2.Any('') }).str()
	curve := (key['crv'] or { json2.Any('') }).str()
	expected_kind := if algorithm == 'EdDSA' {
		'OKP'
	} else if algorithm.starts_with('ES') {
		'EC'
	} else {
		'RSA'
	}
	if kind != expected_kind || curve != jwt_curve(algorithm) {
		return error('JWK type or curve does not match algorithm')
	}
}

fn openssl_keypair(algorithm string, bits int) !(string, string) {
	mut output := []u8{len: 65536}
	mut length := usize(0)
	if C.ba_generate_jwk(algorithm.str, bits, output.data, usize(output.len), &length) != 1 {
		return error('OpenSSL JWK generation failed')
	}
	fields := json2.decode[map[string]json2.Any](output[..int(length)].bytestr())!
	return (fields['public'] or { return error('missing public JWK') }).json_str(), (fields['private'] or {
		return error('missing private JWK')
	}).json_str()
}

fn openssl_jwk_parts(encoded string) ![]string {
	key := json2.decode[map[string]json2.Any](encoded)!
	mut parts := []string{}
	for name in ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'x', 'y'] {
		parts << (key[name] or { json2.Any('') }).str()
	}
	return parts
}

fn openssl_sign(algorithm string, private_json string, message []u8) ![]u8 {
	parts := openssl_jwk_parts(private_json)!
	mut pointers := []&char{}
	for part in parts {
		pointers << unsafe { &char(part.str) }
	}
	mut signature := []u8{len: 2048}
	mut length := usize(0)
	if C.ba_sign_jwk(algorithm.str, pointers.data, message.data, usize(message.len),
		signature.data, usize(signature.len), &length) != 1 {
		return error('OpenSSL JWS signing failed')
	}
	return signature[..int(length)].clone()
}

fn openssl_verify(algorithm string, public_json string, message []u8, signature []u8) !bool {
	parts := openssl_jwk_parts(public_json)!
	mut pointers := []&char{}
	for part in parts {
		pointers << unsafe { &char(part.str) }
	}
	return C.ba_verify_jwk(algorithm.str, pointers.data, message.data, usize(message.len),
		signature.data, usize(signature.len)) == 1
}
