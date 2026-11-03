module better_auth

import math
import strconv
import x.json2

// Compact cookies authenticate JSON.stringify output. V uses scientific notation
// for numbers such as Unix milliseconds, while ECMAScript uses decimal notation
// between 1e-6 and 1e21. Preserve that wire representation when re-signing JSON.
fn js_number(value f64) string {
	if math.is_nan(value) || math.is_inf(value, 0) { return 'null' }
	if value == 0 { return '0' }
	negative := value < 0
	absolute := math.abs(value)
	raw := absolute.str().to_lower()
	prefix := if negative { '-' } else { '' }
	if !raw.contains('e') { return prefix + raw.trim_string_right('.0') }
	mantissa, power := raw.split_once('e') or { return prefix + raw }
	exponent := strconv.atoi(power) or { return prefix + raw }
	if absolute < 1e-6 || absolute >= 1e21 {
		return prefix + mantissa.trim_string_right('.0') + 'e' + if exponent >= 0 {
			'+' + exponent.str()
		} else {
			exponent.str()
		}
	}
	digits := mantissa.replace('.', '')
	decimal := exponent + 1
	if decimal <= 0 { return prefix + '0.' + '0'.repeat(-decimal) + digits }
	if decimal >= digits.len { return prefix + digits + '0'.repeat(decimal - digits.len) }
	return prefix + digits[..decimal] + '.' + digits[decimal..]
}

fn js_json(value json2.Any) string {
	match value {
		f64 {
			return js_number(value)
		}
		[]json2.Any {
			return '[' + value.map(js_json(it)).join(',') + ']'
		}
		map[string]json2.Any {
			mut numeric := []u32{}
			mut ordinary := []string{}
			for key, _ in value {
				index := strconv.parse_uint(key, 10, 32) or {
					ordinary << key
					continue
				}
				if index < 4294967295 && index.str() == key {
					numeric << u32(index)
				} else {
					ordinary << key
				}
			}
			numeric.sort()
			mut keys := numeric.map(it.str())
			keys << ordinary
			return '{' + keys.map(json2.Any(it).json_str() + ':' + js_json(value[it] or {
				json2.Any(json2.Null{})
			})).join(',') + '}'
		}
		else {
			return value.json_str()
		}
	}
}
