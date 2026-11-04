module better_auth

import crypto.rand
import encoding.hex

pub fn generate_auth_id(size int) !string {
	length := if size == 0 { 32 } else { size }
	if length < 0 || length > 1048576 { return error('invalid ID length') }
	alphabet := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	mut result := []u8{cap: length}
	for result.len < length {
		for byte in rand.bytes(48)! {
			if byte < 248 { result << alphabet[int(byte) % alphabet.len] }
			if result.len == length { break
			 }
		}
	}
	return result.bytestr()
}

fn uuid_from_bytes(bytes []u8, version u8) !string {
	if bytes.len < 16 { return error('UUID requires at least 16 bytes') }
	mut value := bytes[..16].clone()
	value[6] = (value[6] & 0x0f) | (version << 4)
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.encode(value)
	return encoded[..8] + '-' + encoded[8..12] + '-' + encoded[12..16] + '-' + encoded[16..20] +
		'-' + encoded[20..]
}

pub fn generate_uuid() !string {
	return uuid_from_bytes(rand.bytes(16)!, 4)
}

pub fn encode_deterministic_id(digest []u8, strategy string) !string {
	return if strategy == 'uuid' { uuid_from_bytes(digest, 5)! } else { base64url(digest) }
}

fn no_id_generator(_ string) !string {
	return error('ID generator is not configured')
}

fn (a &Auth) new_id(model string) !string {
	value := if a.config.generate_id != no_id_generator {
		a.config.generate_id(model)!
	} else if a.config.id_strategy == 'uuid' {
		generate_uuid()!
	} else {
		generate_auth_id(32)!
	}
	if value == '' || value.contains('\x00') { return error('ID generator returned an invalid ID') }
	return value
}
