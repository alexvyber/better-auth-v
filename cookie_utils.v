module better_auth

import encoding.utf8
import net.urllib
import strconv
import time
import x.json2

pub const secure_cookie_prefix = '__Secure-'
pub const host_cookie_prefix = '__Host-'

// Attributes retain their lowercase wire names. Date and NaN metadata are kept
// separately because JSON cannot represent JavaScript Date or NaN values.
pub struct ParsedSetCookie {
pub:
	value           string
	attributes      map[string]json2.Any
	expires_present bool
	expires_at      ?i64
	invalid_max_age bool
}

pub fn strip_secure_cookie_prefix(name string) string {
	for prefix in [secure_cookie_prefix, host_cookie_prefix] {
		if name.starts_with(prefix) { return name[prefix.len..] }
	}
	return name
}

fn decode_cookie_component(value string) string {
	if !value.contains('%') { return value }
	decoded := urllib.path_unescape(value) or { return value }
	return if utf8.validate_str(decoded) { decoded } else { value }
}

fn unquote_cookie_value(value string) string {
	return if value.len >= 2 && value.starts_with('"') && value.ends_with('"') {
		value[1..value.len - 1]
	} else {
		value
	}
}

fn valid_cookie_value(value string) bool {
	for ch in value.bytes() {
		if ch < 32 || ch > 126 || ch in [`"`, `;`, `\\`] { return false }
	}
	return true
}

// Validate wire octets before decoding. Only SP/HTAB are trimmed: accepting CR
// or LF through general whitespace trimming would admit malformed headers.
// Duplicate names use the last value and retain their original insertion order.
pub fn parse_cookies(header string) map[string]string {
	mut result := map[string]string{}
	for part in header.split(';') {
		eq := part.index('=') or { continue }
		name := part[..eq].trim(' \t')
		value := unquote_cookie_value(part[eq + 1..].trim(' \t'))
		if valid_cookie_name(name) && valid_cookie_value(value) {
			result[name] = decode_cookie_component(value)
		}
	}
	return result
}

// A comma belongs to the next cookie only when followed by a name/value pair.
// This preserves the commas inside all three HTTP-date representations.
pub fn split_set_cookie_header(header string) []string {
	mut result := []string{}
	mut start := 0
	mut i := 0
	for i < header.len {
		if header[i] == `,` {
			mut next := i + 1
			for next < header.len && header[next] == ` ` {
				next++
			}
			for next < header.len && header[next] !in [`=`, `;`, `,`] {
				next++
			}
			if next < header.len && header[next] == `=` {
				part := header[start..i].trim_space()
				if part != '' { result << part }
				start = i + 1
				for start < header.len && header[start] == ` ` {
					start++
				}
				i = start
				continue
			}
		}
		i++
	}
	last := header[start..].trim_space()
	if last != '' { result << last }
	return result
}

fn cookie_max_age(value string) ?f64 {
	text := value.trim_space()
	mut end := 0
	if text.len > 0 && text[0] in [`+`, `-`] { end++ }
	start := end
	for end < text.len && text[end].is_digit() {
		end++
	}
	if end == start { return none }
	return strconv.atof64(text[..end]) or { return none }
}

fn cookie_expires(value string) ?i64 {
	// HTTP cookie dates. Non-standard JavaScript date strings are deliberately
	// kept invalid unless supported here; never silently replace them with now.
	parsed := time.parse_rfc2616(value) or { return none }
	return parsed.unix_milli()
}

pub fn parse_set_cookie_header(header string) map[string]ParsedSetCookie {
	mut result := map[string]ParsedSetCookie{}
	for entry in split_set_cookie_header(header) {
		parts := entry.split(';').map(it.trim_space())
		first := parts[0]
		eq := first.index('=') or { first.len }
		name := first[..eq]
		if name == '' { continue
		 }
		value := if eq < first.len { first[eq + 1..] } else { '' }
		mut attrs := map[string]json2.Any{}
		mut expires_present := false
		mut expires_at := ?i64(none)
		mut invalid_max_age := false
		for part in parts[1..] {
			sep := part.index('=') or { part.len }
			key := part[..sep].trim_space().to_lower()
			raw := if sep < part.len { part[sep + 1..] } else { '' }
			trimmed := raw.trim_space()
			match key {
				'max-age' {
					attrs.delete(key)
					invalid_max_age = false
					if raw != '' {
						if age := cookie_max_age(raw) {
							attrs[key] = age
						} else {
							invalid_max_age = true
						}
					}
				}
				'expires' {
					expires_present = raw != ''
					expires_at = if expires_present { cookie_expires(trimmed) } else { none }
				}
				'domain', 'path', 'samesite' {
					attrs.delete(key)
					if raw != '' { attrs[key] = if key == 'samesite' {
							trimmed.to_lower()
						} else {
							trimmed
						}
					 }
				}
				'secure', 'httponly', 'partitioned' {
					attrs[key] = true
				}
				else {
					attrs[key] = if raw == '' { json2.Any(true) } else { json2.Any(trimmed) }
				}
			}
		}
		result[name] = ParsedSetCookie{
			value:           decode_cookie_component(unquote_cookie_value(value))
			attributes:      attrs
			expires_present: expires_present
			expires_at:      expires_at
			invalid_max_age: invalid_max_age
		}
	}
	return result
}

pub fn to_cookie_options(attributes map[string]json2.Any) map[string]json2.Any {
	mut result := map[string]json2.Any{}
	for wire, option in {
		'max-age':     'maxAge'
		'expires':     'expires'
		'domain':      'domain'
		'path':        'path'
		'secure':      'secure'
		'httponly':    'httpOnly'
		'partitioned': 'partitioned'
		'samesite':    'sameSite'
	} {
		if value := attributes[wire] { result[option] = value }
	}
	return result
}

// encodeURIComponent's UTF-8 escaping, including literal '%' and reserved
// cookie bytes. '+' is encoded rather than being treated as a form space.
fn encode_cookie_component(value string) string {
	hex_digits := '0123456789ABCDEF'
	mut result := ''
	for ch in value.bytes() {
		if ch.is_alnum() || ch in [`-`, `_`, `.`, `!`, `~`, `*`, `'`, `(`, `)`] {
			result += ch.ascii_str()
		} else {
			result += '%' + hex_digits[ch >> 4].ascii_str() + hex_digits[ch & 15].ascii_str()
		}
	}
	return result
}

fn serialize_request_cookies(cookies map[string]string) string {
	mut parts := []string{}
	for name, value in cookies {
		parts << name + '=' + encode_cookie_component(value)
	}
	return parts.join('; ')
}

pub fn set_request_cookie(header string, name string, value string) string {
	mut cookies := parse_cookies(header)
	if valid_cookie_name(name) { cookies[name] = value }
	return serialize_request_cookies(cookies)
}

// Name/value merging, for a single request. This is intentionally not a browser
// cookie jar: Domain, Path and expiration do not select or delete entries.
pub fn apply_set_cookies(header string, set_cookie_values []string) string {
	mut cookies := parse_cookies(header)
	for value in set_cookie_values {
		for name, cookie in parse_set_cookie_header(value) {
			if valid_cookie_name(name) { cookies[name] = cookie.value }
		}
	}
	return serialize_request_cookies(cookies)
}

pub fn get_session_cookie(header string, prefix string, name string) ?string {
	cookies := parse_cookies(header)
	for separator in ['.', '-'] {
		key := prefix + separator + name
		value := cookies[secure_cookie_prefix + key] or { cookies[key] or { '' } }
		if value != '' { return value }
	}
	return none
}

pub fn get_chunked_cookie(header string, name string, direct_value ?string) ?string {
	if value := direct_value {
		if value != '' { return value }
	}
	cookies := parse_cookies(header)
	mut indices := []int{}
	for key, _ in cookies {
		if index := cache_chunk_index(key, name) { indices << index }
	}
	if indices.len == 0 { return none }
	indices.sort()
	mut result := ''
	for index in indices {
		result += cookies['${name}.${index}']
	}
	return result
}

// Remove the cookie and all its pending chunks before appending an expiry.
pub fn remove_set_cookie_entries(headers []string, name string) []string {
	mut result := []string{}
	for header in headers {
		for entry in split_set_cookie_header(header) {
			if !entry.starts_with(name + '=') && !entry.starts_with(name + '.') { result << entry }
		}
	}
	return result
}

pub fn expire_cookie_attributes(attributes map[string]json2.Any) map[string]json2.Any {
	mut result := attributes.clone()
	result['maxAge'] = 0
	return result
}
