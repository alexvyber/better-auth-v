module better_auth

import better_auth.domain.ratelimit

pub struct RateLimitRule {
pub:
	window   i64 = 60
	max      int = 100
	disabled bool
}

pub struct RateLimitRecord {
pub:
	key          string
	count        i64
	last_request i64 @[json: lastRequest]
}

pub struct RateLimitInput {
pub:
	key          string
	now          i64
	window       i64
	max          int
	prune_before i64
}

pub struct RateLimitDecision {
pub:
	allowed     bool
	retry_after i64
	next        RateLimitRecord
	reset       bool
}

pub interface RateLimitDatabase {
mut:
	consume_rate_limit(input RateLimitInput) !RateLimitDecision
}

fn decide_rate_limit(previous ?RateLimitRecord, input RateLimitInput) RateLimitDecision {
	mut prior := ?ratelimit.Record(none)
	if record := previous { prior = ratelimit.Record{
			key:          record.key
			count:        record.count
			last_request: record.last_request
		} }
	decision := ratelimit.decide(prior, ratelimit.Input{
		key:          input.key
		now:          input.now
		window:       input.window
		max:          input.max
		prune_before: input.prune_before
	})
	return RateLimitDecision{
		allowed:     decision.allowed
		retry_after: decision.retry_after
		reset:       decision.reset
		next:        RateLimitRecord{
			key:          decision.next.key
			count:        decision.next.count
			last_request: decision.next.last_request
		}
	}
}

fn (mut a Auth) rate_limit(path string) !Lookup[Response] {
	if a.config.rate_limit_max == 0 { return Lookup[Response]{} }
	now := a.clock_millis()
	mut rule := RateLimitRule{
		max:    a.config.rate_limit_max
		window: a.config.rate_limit_window
	}
	mut longest_window := if rule.window > 60 { rule.window } else { i64(60) }
	if ['/sign-in', '/sign-up', '/change-password', '/change-email'].any(path.starts_with(it)) {
		rule = RateLimitRule{
			max:    3
			window: 10
		}
	} else if
		path in ['/request-password-reset', '/send-verification-email', '/email-otp/send-verification-otp', '/email-otp/request-password-reset']
		|| path.starts_with('/forget-password') {
		rule = RateLimitRule{
			max:    3
			window: 60
		}
	}
	if options := a.email_otp_options() {
		if path.starts_with('/email-otp/')
			|| path in ['/sign-in/email-otp', '/forget-password/email-otp'] {
			rule = RateLimitRule{
				max:    if options.rate_limit.max != 0 { options.rate_limit.max } else { 3 }
				window: if options.rate_limit.window != 0 { options.rate_limit.window } else { 60 }
			}
		}
		if options.rate_limit.window > longest_window { longest_window = options.rate_limit.window }
	}
	if a.two_factor_options() != none && path.starts_with('/two-factor/') {
		rule = RateLimitRule{
			max:    3
			window: 10
		}
	}
	mut matched := false
	for pattern, custom in a.config.rate_limit_rules {
		if custom.window > longest_window { longest_window = custom.window }
		if !matched && origin_glob_segment(pattern, path) {
			rule = custom
			matched = true
		}
	}
	if rule.disabled { return Lookup[Response]{} }
	if rule.window <= 0 || rule.max < 0 { return error('invalid rate limit rule') }
	normalized_path := if path.starts_with('/callback/') {
		'/callback/:provider'
	} else if path.starts_with('/reset-password/') {
		'/reset-password/:token'
	} else {
		path
	}
	ip := if a.config.trust_proxy_ip_headers {
		a.operation.request.headers['x-forwarded-for'].split(',').last().trim_space()
	} else {
		''
	}
	key := (if ip != '' { ip } else { 'no-trusted-ip' }) + '|' + normalized_path
	input := RateLimitInput{
		key:          key
		now:          now
		window:       rule.window
		max:          rule.max
		prune_before: now - longest_window * 1000
	}
	mut decision := RateLimitDecision{}
	if a.config.rate_limit_storage == 'database' {
		mut database := a.storage
		if mut database is RateLimitDatabase {
			decision = database.consume_rate_limit(input)!
		} else {
			return error('database adapter does not implement atomic rate limits')
		}
	} else {
		for bucket_key, bucket in a.limits {
			if now - bucket.start >= bucket.window_millis { a.limits.delete(bucket_key) }
		}
		mut previous := ?RateLimitRecord(none)
		if bucket := a.limits[key] { previous = RateLimitRecord{
				key:          key
				count:        bucket.count
				last_request: bucket.start
			} }
		decision = decide_rate_limit(previous, input)
		if decision.allowed {
			a.limits[key] = RateBucket{
				start:         decision.next.last_request
				count:         int(decision.next.count)
				window_millis: rule.window * 1000
			}
			if a.limits.len > 100000 { a.limits.delete(a.limits.keys()[0]) }
		}
	}
	if decision.allowed { return Lookup[Response]{} }
	return Lookup[Response]{
		value: Response{
			status:  429
			headers: [Header{'content-type', 'application/json'},
				Header{'x-retry-after', decision.retry_after.str()}]
			body:    '{"message":"Too many requests. Please try again later."}'
		}
	}
}
