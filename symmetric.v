module better_auth

import crypto.hkdf
import crypto.rand
import crypto.sha256
import encoding.hex
import strconv
import x.json2

pub struct SecretConfig {
pub:
	keys            map[i64]string
	current_version i64    @[json: currentVersion]
	legacy_secret   string @[json: legacySecret]
}

pub type SymmetricSecret = SecretConfig | string

pub struct SecretEnvelope {
pub:
	version    i64
	ciphertext string
}

pub fn format_secret_envelope(version i64, ciphertext string) string {
	return '\$ba\$${version}\$${ciphertext}'
}

pub fn parse_secret_envelope(value string) ?SecretEnvelope {
	if !value.starts_with('\$ba\$') { return none }
	tail := value[4..]
	separator := tail.index('\$') or { return none }
	// Upstream parseInt accepts a decimal prefix; retain that pinned behavior.
	version := decimal_prefix(tail[..separator]) or { return none }
	if version < 0 { return none }
	return SecretEnvelope{
		version:    version
		ciphertext: tail[separator + 1..]
	}
}

fn decimal_prefix(input string) ?i64 {
	text := input.trim_space()
	mut end := 0
	if text.len > 0 && text[0] in [`+`, `-`] { end++ }
	start := end
	for end < text.len && text[end].is_digit() {
		end++
	}
	if start == end { return none }
	return strconv.parse_int(text[..end], 10, 64) or { return none }
}

fn current_symmetric_secret(secret SymmetricSecret) !string {
	match secret {
		string {
			return secret
		}
		SecretConfig {
			value := secret.keys[secret.current_version] or {
				return error('Secret version ${secret.current_version} not found in keys')
			}
			if value == '' {
				return error('Secret version ${secret.current_version} not found in keys')
			}
			return value
		}
	}
}

fn rotate_word(value u32, count int) u32 {
	return (value << count) | (value >> (32 - count))
}

fn chacha_quarter(mut state []u32, a int, b int, c int, d int) {
	state[a] += state[b]
	state[d] = rotate_word(state[d] ^ state[a], 16)
	state[c] += state[d]
	state[b] = rotate_word(state[b] ^ state[c], 12)
	state[a] += state[b]
	state[d] = rotate_word(state[d] ^ state[a], 8)
	state[c] += state[d]
	state[b] = rotate_word(state[b] ^ state[c], 7)
}

fn little_word(input []u8) u32 {
	return u32(input[0]) | u32(input[1]) << 8 | u32(input[2]) << 16 | u32(input[3]) << 24
}

// XChaCha's HChaCha20 subkey derivation; OpenSSL supplies the IETF AEAD primitive.
fn hchacha20(key []u8, nonce []u8) ![]u8 {
	if key.len != 32 || nonce.len != 16 { return error('invalid HChaCha20 key or nonce') }
	mut state := [u32(0x61707865), 0x3320646e, 0x79622d32, 0x6b206574]
	for offset := 0; offset < 32; offset += 4 {
		state << little_word(key[offset..offset + 4])
	}
	for offset := 0; offset < 16; offset += 4 {
		state << little_word(nonce[offset..offset + 4])
	}
	for _ in 0 .. 10 {
		chacha_quarter(mut state, 0, 4, 8, 12)
		chacha_quarter(mut state, 1, 5, 9, 13)
		chacha_quarter(mut state, 2, 6, 10, 14)
		chacha_quarter(mut state, 3, 7, 11, 15)
		chacha_quarter(mut state, 0, 5, 10, 15)
		chacha_quarter(mut state, 1, 6, 11, 12)
		chacha_quarter(mut state, 2, 7, 8, 13)
		chacha_quarter(mut state, 3, 4, 9, 14)
	}
	mut output := []u8{}
	for index in [0, 1, 2, 3, 12, 13, 14, 15] {
		word := state[index]
		for shift in [0, 8, 16, 24] {
			output << u8(word >> shift)
		}
	}
	return output
}

fn xchacha_encrypt(secret string, plaintext string) !string {
	nonce := rand.bytes(24)!
	key := hchacha20(sha256.sum(secret.bytes()), nonce[..16])!
	mut iv := []u8{len: 4}
	iv << nonce[16..]
	mut output := []u8{len: plaintext.len + 16}
	if C.ba_chacha_encrypt(key.data, iv.data, plaintext.str, usize(plaintext.len), output.data) != 1 {
		return error('XChaCha20-Poly1305 encryption failed')
	}
	mut encoded := nonce.clone()
	encoded << output
	return hex.encode(encoded)
}

fn xchacha_decrypt(secret string, ciphertext string) !string {
	if ciphertext.len % 2 != 0 { return error('invalid XChaCha20-Poly1305 ciphertext') }
	input := hex.decode(ciphertext)!
	if input.len < 40 { return error('invalid XChaCha20-Poly1305 ciphertext') }
	key := hchacha20(sha256.sum(secret.bytes()), input[..16])!
	mut iv := []u8{len: 4}
	iv << input[16..24]
	size := input.len - 40
	mut plaintext := []u8{len: if size == 0 { 1 } else { size }}
	if C.ba_chacha_decrypt(key.data, iv.data, input[24..].data, usize(input.len - 24),
		plaintext.data) != 1 {
		return error('XChaCha20-Poly1305 authentication failed')
	}
	return plaintext[..size].bytestr()
}

pub fn symmetric_encrypt(secret SymmetricSecret, plaintext string) !string {
	ciphertext := xchacha_encrypt(current_symmetric_secret(secret)!, plaintext)!
	return match secret {
		string { ciphertext }
		SecretConfig { format_secret_envelope(secret.current_version, ciphertext) }
	}
}

pub fn symmetric_decrypt(secret SymmetricSecret, ciphertext string) !string {
	match secret {
		string {
			return xchacha_decrypt(secret, ciphertext)
		}
		SecretConfig {
			if envelope := parse_secret_envelope(ciphertext) {
				key := secret.keys[envelope.version] or {
					return error('Secret version ${envelope.version} not found in keys (key may have been retired)')
				}
				if key == '' {
					return error('Secret version ${envelope.version} not found in keys (key may have been retired)')
				}
				return xchacha_decrypt(key, envelope.ciphertext)
			}
			if secret.legacy_secret == '' {
				return error('Cannot decrypt legacy bare-hex payload: no legacy secret available. Set BETTER_AUTH_SECRET for backwards compatibility.')
			}
			return xchacha_decrypt(secret.legacy_secret, ciphertext)
		}
	}
}

pub fn derive_purpose_key(secret SymmetricSecret, purpose string) !SymmetricSecret {
	if purpose !in ['oauth-state-cookie', 'oauth-proxy-state', 'oauth-proxy-package',
		'oauth-proxy-profile'] {
		return error('unsupported encryption purpose')
	}
	match secret {
		string {
			return purpose_secret(secret, purpose)!
		}
		SecretConfig {
			mut keys := map[i64]string{}
			for version, value in secret.keys {
				keys[version] = purpose_secret(value, purpose)!
			}
			return SecretConfig{
				keys:            keys
				current_version: secret.current_version
				legacy_secret:   if secret.legacy_secret == '' {
					''
				} else {
					purpose_secret(secret.legacy_secret, purpose)!
				}
			}
		}
	}
}

fn purpose_secret(secret string, purpose string) !string {
	return hex.encode(hkdf.key(sha256.new, secret.bytes(),
		'better-auth:oauth-encryption:v1'.bytes(), 'better-auth:${purpose}:v1', 32)!)
}

pub fn symmetric_encode_jwt_rotating(payload string, secret SymmetricSecret, salt string, expires_in i64, now i64) !string {
	return symmetric_encode_jwt(payload, current_symmetric_secret(secret)!, salt, expires_in, now)
}

pub fn symmetric_decode_jwt_rotating(token string, secret SymmetricSecret, salt string, now i64) !string {
	mut candidates := []string{}
	match secret {
		string {
			candidates << secret
		}
		SecretConfig {
			for _, value in secret.keys {
				candidates << value
			}
			if secret.legacy_secret != '' && secret.legacy_secret !in candidates {
				candidates << secret.legacy_secret
			}
		}
	}

	// The single-key decoder checks a present kid before decrypting. Trying other
	// secrets cannot bypass that binding; kid-less legacy tokens can use any key.
	for candidate in candidates {
		value := symmetric_decode_jwt(token, candidate, salt, now) or { continue }
		return value
	}
	return error('no matching JWE decryption secret')
}

// Wire transport helper: Maps in JS become a numeric-keyed JSON object only at
// the boundary; all version selection and rotation decisions stay in V.
pub fn decode_symmetric_secret(value json2.Any) !SymmetricSecret {
	if value is string { return value }
	fields := value.as_map()
	current :=
		(fields['currentVersion'] or { return error('missing current secret version') }).i64()
	mut keys := map[i64]string{}
	for version, secret in (fields['keys'] or { return error('missing secret keys') }).as_map() {
		parsed := decimal_prefix(version) or { return error('invalid secret version') }
		if parsed < 0 || parsed.str() != version || secret !is string {
			return error('invalid secret key entry')
		}
		keys[parsed] = secret.str()
	}
	return SymmetricSecret(SecretConfig{
		keys:            keys
		current_version: current
		legacy_secret:   (fields['legacySecret'] or { json2.Any('') }).str()
	})
}

pub fn encode_secret_config(config SecretConfig) string {
	mut keys := map[string]json2.Any{}
	for version, value in config.keys {
		keys[version.str()] = value
	}
	mut fields := {
		'keys':           json2.Any(keys)
		'currentVersion': json2.Any(config.current_version)
	}
	if config.legacy_secret != '' { fields['legacySecret'] = config.legacy_secret }
	return json2.Any(fields).json_str()
}
