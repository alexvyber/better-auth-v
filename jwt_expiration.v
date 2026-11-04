module better_auth

import math
import time

// Numeric expiration values are absolute NumericDate claims, dates are floored
// to Unix seconds, and duration strings are relative to the supplied issue time.
pub type JWTExpiration = f64 | string | time.Time

pub fn jwt_expiration(value JWTExpiration, issued_at i64) !f64 {
	return jwt_expiration_at(value, f64(issued_at))
}

pub fn jwt_expiration_at(value JWTExpiration, issued_at f64) !f64 {
	match value {
		f64 { return value }
		time.Time { return f64(value.unix()) + math.floor(f64(value.nanosecond) / 1000000000.0) }
		string { return issued_at + f64(duration_seconds(value)!) }
	}
}

// Implements the pinned upstream time-string grammar. Whitespace, signs and
// suffixes are deliberately parsed strictly rather than silently trimmed.
pub fn duration_seconds(value string) !i64 {
	invalid := 'Invalid time string format: "${value}". Use formats like "7d", "30m", "1 hour", etc.'
	text := value.to_lower()
	mut offset := 0
	mut signed := false
	mut negative := false
	if text.len > 0 && text[0] in [`+`, `-`] {
		signed = true
		negative = text[0] == `-`
		offset++
	}
	if offset < text.len && text[offset] == ` ` { offset++ }
	start := offset
	for offset < text.len && text[offset].is_digit() {
		offset++
	}
	if offset == start { return error(invalid) }
	if offset < text.len && text[offset] == `.` {
		offset++
		fraction := offset
		for offset < text.len && text[offset].is_digit() {
			offset++
		}
		if offset == fraction { return error(invalid) }
	}
	number := text[start..offset].f64()
	if offset < text.len && text[offset] == ` ` { offset++ }
	unit_start := offset
	for offset < text.len && text[offset] >= `a` && text[offset] <= `z` {
		offset++
	}
	unit := text[unit_start..offset]
	suffix := text[offset..]
	if suffix != '' {
		if signed || suffix !in [' ago', ' from now'] { return error(invalid) }
		negative = suffix == ' ago'
	}
	seconds := match unit {
		'years', 'year', 'yrs', 'yr', 'y' { f64(31557600) }
		'months', 'month', 'mo' { f64(2592000) }
		'weeks', 'week', 'w' { f64(604800) }
		'days', 'day', 'd' { f64(86400) }
		'hours', 'hour', 'hrs', 'hr', 'h' { f64(3600) }
		'minutes', 'minute', 'mins', 'min', 'm' { f64(60) }
		'seconds', 'second', 'secs', 'sec', 's' { f64(1) }
		else { return error(invalid) }
	}

	result := number * seconds * if negative { f64(-1) } else { f64(1) }
	// JavaScript Math.round ties toward positive infinity, including negatives.
	return i64(math.floor(result + 0.5))
}
