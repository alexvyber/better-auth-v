module ratelimit

fn test_rate_limit_rolls_window_on_allowed_requests_and_resets_at_boundary() {
	input := Input{
		key:    'k'
		now:    1000
		window: 2
		max:    2
	}
	first := decide(none, input)
	assert first.allowed && first.next.count == 1 && !first.reset
	second := decide(first.next, Input{ ...input, now: 2000 })
	assert second.allowed && second.next.count == 2 && second.next.last_request == 2000
	denied := decide(second.next, Input{ ...input, now: 2500 })
	assert !denied.allowed && denied.retry_after == 2 && denied.next == second.next
	reset := decide(second.next, Input{ ...input, now: 4000 })
	assert reset.allowed && reset.reset && reset.next.count == 1
}
