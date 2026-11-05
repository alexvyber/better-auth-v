module better_auth

import time

fn (a &Auth) clock_millis() i64 {
	if a.config.clock_millis != no_millisecond_clock { return a.config.clock_millis() }
	if a.config.clock == time.unix_now { return time.now().unix_milli() }
	return a.config.clock() * 1000
}

fn stamp(epoch i64) string {
	return time.unix(epoch).format_rfc3339()
}

fn epoch(value string) !i64 {
	return time.parse_rfc3339(value)!.unix()
}

fn stamp_millis(value i64) string {
	return time.unix_milli(value).format_rfc3339()
}

fn epoch_millis(value string) !i64 {
	return time.parse_rfc3339(value)!.unix_milli()
}

fn verification_expiry_millis(value Verification) i64 {
	return value.expires_at_millis or { value.expires_at * 1000 }
}
