module better_auth

pub fn (mut storage MemoryStorage) consume_rate_limit(input RateLimitInput) !RateLimitDecision {
	storage.check_write()!
	previous := if record := storage.rate_limits[input.key] {
		?RateLimitRecord(record)
	} else {
		none
	}
	decision := decide_rate_limit(previous, input)
	if decision.allowed { storage.rate_limits[input.key] = decision.next }
	if decision.reset {
		for key, record in storage.rate_limits {
			if record.last_request < input.prune_before { storage.rate_limits.delete(key) }
		}
	}
	return decision
}
