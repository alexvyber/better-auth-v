module better_auth

import math

// JOSE's duration grammar differs from the JWT plugin's expiration grammar:
// no month unit, and a negative sign applies after rounding the positive value.
fn id_token_duration_seconds(value string) !f64 {
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
	if offset == start { return error('Invalid time period format') }
	if offset < text.len && text[offset] == `.` {
		offset++
		fraction := offset
		for offset < text.len && text[offset].is_digit() {
			offset++
		}
		if offset == fraction { return error('Invalid time period format') }
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
		if signed || suffix !in [' ago', ' from now'] { return error('Invalid time period format') }
		negative = suffix == ' ago'
	}
	multiplier := match unit {
		'years', 'year', 'yrs', 'yr', 'y' { f64(31557600) }
		'weeks', 'week', 'w' { f64(604800) }
		'days', 'day', 'd' { f64(86400) }
		'hours', 'hour', 'hrs', 'hr', 'h' { f64(3600) }
		'minutes', 'minute', 'mins', 'min', 'm' { f64(60) }
		'seconds', 'second', 'secs', 'sec', 's' { f64(1) }
		else { return error('Invalid time period format') }
	}

	result := math.floor(number * multiplier + 0.5)
	if math.is_inf(result, 0) || math.is_nan(result) { return error('Invalid time period format') }
	return if negative { -result } else { result }
}
