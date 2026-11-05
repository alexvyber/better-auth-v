module better_auth

import os

fn concurrent_rate_request(mut auth Auth, responses chan Response) {
	responses <- auth.handle(Request{ url: 'http://localhost:3000/api/auth/get-session' })
}

fn test_database_rate_limit_serializes_independent_connections_and_survives_auth_rollback() ! {
	path := os.join_path(os.temp_dir(), 'better-auth-rate-' + random_token()! + '.sqlite')
	defer { os.rm(path) or {} }
	mut storage := open_sqlite(path)!
	storage.migrate()!
	configuration := Config{
		secret:             'native-database-rate-limit-secret-1234'
		rate_limit_storage: 'database'
		rate_limit_max:     1
		rate_limit_window:  10
	}
	mut first := new(configuration, storage)!
	defer { first.close() or {} }
	mut second := new(configuration, open_sqlite(path)!)!
	defer { second.close() or {} }
	responses := chan Response{cap: 2}
	go concurrent_rate_request(mut first, responses)
	go concurrent_rate_request(mut second, responses)
	a := <-responses
	b := <-responses
	assert (a.status == 200 && b.status == 429) || (a.status == 429 && b.status == 200)
	// Trusted server API calls bypass the public HTTP limiter.
	assert second.call(Request{ url: '/api/auth/get-session' }).status == 200
	assert first.handle(Request{ url: 'http://localhost:3000/api/auth/get-session' }).status == 429
}

fn test_database_rate_limit_rolling_window_exact_boundary_and_pruning() ! {
	mut storage := open_sqlite(':memory:')!
	storage.migrate()!
	assert storage.consume_rate_limit(RateLimitInput{
		key:    'long-lived'
		now:    1000
		window: 3600
		max:    10
	})!.allowed
	assert storage.consume_rate_limit(RateLimitInput{ key: 'active', now: 1000, window: 10, max: 2 })!.allowed
	// Allowed traffic updates lastRequest: this is a rolling inactivity window.
	assert storage.consume_rate_limit(RateLimitInput{ key: 'active', now: 9000, window: 10, max: 2 })!.allowed
	blocked := storage.consume_rate_limit(RateLimitInput{
		key:    'active'
		now:    11000
		window: 10
		max:    2
	})!
	assert !blocked.allowed
	assert blocked.retry_after == 8
	assert storage.consume_rate_limit(RateLimitInput{
		key:          'active'
		now:          19000
		window:       10
		max:          2
		prune_before: -3581000
	})!.allowed
	assert storage.db.q_int('SELECT count(*) FROM auth_rate_limit')! == 2
}
