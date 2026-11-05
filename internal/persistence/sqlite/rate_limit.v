module better_auth

pub fn (mut storage SQLiteStorage) consume_rate_limit(input RateLimitInput) !RateLimitDecision {
	storage.begin()!
	mut committed := false
	defer {
		if !committed { storage.rollback() or {} }
	}
	rows := storage.db.exec_param('SELECT count,last_request FROM auth_rate_limit WHERE key=?',
		input.key)!
	previous := if rows.len > 0 { ?RateLimitRecord(RateLimitRecord{
			key:          input.key
			count:        rows[0].vals[0].i64()
			last_request: rows[0].vals[1].i64()
		}) } else { none }
	decision := decide_rate_limit(previous, input)
	if decision.allowed {
		storage.db.exec_param_many('INSERT INTO auth_rate_limit (key,count,last_request) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET count=excluded.count,last_request=excluded.last_request', [
			input.key,
			decision.next.count.str(),
			decision.next.last_request.str(),
		])!
	}
	if decision.reset {
		storage.db.exec_param('DELETE FROM auth_rate_limit WHERE last_request < ?',
			input.prune_before.str())!
	}
	storage.commit()!
	committed = true
	return decision
}
