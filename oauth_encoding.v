module better_auth

import encoding.base64

// URLSearchParams uses form encoding, whose literal set differs from RFC 3986.
pub fn oauth_form_encode(value string) string {
	mut output := []u8{}
	digits := '0123456789ABCDEF'
	for ch in oauth_utf8_decode(value.bytes(), false).bytes() {
		if ch.is_alnum() || ch in [`*`, `-`, `.`, `_`] {
			output << ch
		} else if ch == ` ` {
			output << `+`
		} else {
			output << [u8(`%`), digits[ch >> 4], digits[ch & 15]]
		}
	}
	return output.bytestr()
}

fn oauth_hex(ch u8) int {
	if ch >= `0` && ch <= `9` { return int(ch - `0`) }
	if ch >= `a` && ch <= `f` { return int(ch - `a`) + 10 }
	if ch >= `A` && ch <= `F` { return int(ch - `A`) + 10 }
	return -1
}

pub fn oauth_form_decode(value string) string {
	mut bytes := []u8{}
	mut index := 0
	for index < value.len {
		ch := value[index]
		if ch == `%` && index + 2 < value.len {
			high, low := oauth_hex(value[index + 1]), oauth_hex(value[index + 2])
			if high >= 0 && low >= 0 {
				bytes << u8(high * 16 + low)
				index += 3
				continue
			}
		}
		bytes << if ch == `+` { u8(` `) } else { ch }
		index++
	}
	return oauth_utf8_decode(bytes, false)
}

// WHATWG UTF-8 decoding replaces each maximal invalid subsequence once, rather
// than replacing every byte of a truncated but otherwise valid sequence.
fn oauth_utf8_decode(bytes []u8, strip_bom bool) string {
	mut output := []u8{}
	mut index := if strip_bom && bytes.len >= 3 && bytes[..3] == [u8(0xef), 0xbb, 0xbf] {
		3
	} else {
		0
	}
	for index < bytes.len {
		lead := bytes[index]
		if lead < 128 {
			output << lead
			index++
			continue
		}
		length := if lead >= 0xc2 && lead <= 0xdf {
			2
		} else if lead >= 0xe0 && lead <= 0xef {
			3
		} else if lead >= 0xf0 && lead <= 0xf4 {
			4
		} else {
			0
		}
		if length == 0 {
			output << [u8(0xef), 0xbf, 0xbd]
			index++
			continue
		}
		mut consumed := 1
		for consumed < length && index + consumed < bytes.len {
			ch := bytes[index + consumed]
			minimum := if consumed == 1 && lead == 0xe0 {
				u8(0xa0)
			} else if consumed == 1 && lead == 0xf0 {
				u8(0x90)
			} else {
				u8(0x80)
			}
			maximum := if consumed == 1 && lead == 0xed {
				u8(0x9f)
			} else if consumed == 1 && lead == 0xf4 {
				u8(0x8f)
			} else {
				u8(0xbf)
			}
			if ch < minimum || ch > maximum { break
			 }
			consumed++
		}
		if consumed == length {
			output << bytes[index..index + length]
		} else {
			output << [u8(0xef), 0xbf, 0xbd]
		}
		index += consumed
	}
	return output.bytestr()
}

pub struct OAuthBasicCredentials {
pub:
	client_id     string @[json: clientId]
	client_secret string @[json: clientSecret]
}

pub fn encode_basic_credentials(client_id string, client_secret string) string {
	return 'Basic ' + base64.encode_str(oauth_form_encode(client_id) + ':' +
		oauth_form_encode(client_secret))
}

pub fn decode_basic_credentials(authorization string) !OAuthBasicCredentials {
	text := authorization
	if text.len < 6 || text[..5].to_lower() != 'basic' || text[5] != ` `
		|| text.contains_any('\r\n') || text.contains('\u2028') || text.contains('\u2029') {
		return error('Authorization header is not a Basic credential')
	}
	mut start := 5
	for start < text.len && text[start] == ` ` {
		start++
	}
	encoded := text[start..]
	alphabet := if encoded.contains_any('-_') {
		'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
	} else {
		'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	}
	mut bytes := []u8{}
	mut buffer := u32(0)
	mut bits := 0
	for ch in encoded.bytes() {
		if ch == `=` { break
		 }
		position := alphabet.index(ch.ascii_str()) or {
			return error('Invalid Base64 character: ${ch.ascii_str()}')
		}
		buffer = (buffer << 6) | u32(position)
		bits += 6
		if bits >= 8 {
			bits -= 8
			bytes << u8(buffer >> bits)
		}
	}
	decoded := oauth_utf8_decode(bytes, true)
	separator := decoded.index(':') or {
		return error('Basic credential is missing the client id/secret separator')
	}
	id, secret := decoded[..separator], decoded[separator + 1..]
	if id == '' || secret == '' {
		return error('Basic credential client id and secret must both be non-empty')
	}
	return OAuthBasicCredentials{
		client_id:     oauth_form_decode(id.all_before('&'))
		client_secret: oauth_form_decode(secret.all_before('&'))
	}
}
