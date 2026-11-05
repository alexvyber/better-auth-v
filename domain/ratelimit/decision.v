module ratelimit

import math

pub struct Record {
pub:
	key          string
	count        i64
	last_request i64 @[json: lastRequest]
}

pub struct Input {
pub:
	key          string
	now          i64
	window       i64
	max          int
	prune_before i64
}

pub struct Decision {
pub:
	allowed     bool
	retry_after i64
	next        Record
	reset       bool
}

pub fn decide(previous ?Record, input Input) Decision {
	if record := previous {
		if input.now - record.last_request < input.window * 1000 {
			if record.count >= input.max {
				return Decision{
					retry_after: i64(math.ceil(f64(record.last_request + input.window * 1000 -
						input.now) / 1000))
					next:        record
				}
			}
			return Decision{
				allowed: true
				next:    Record{
					key:          input.key
					count:        record.count + 1
					last_request: input.now
				}
			}
		}
		return Decision{
			allowed: true
			reset:   true
			next:    Record{
				key:          input.key
				count:        1
				last_request: input.now
			}
		}
	}
	return Decision{
		allowed: true
		next:    Record{
			key:          input.key
			count:        1
			last_request: input.now
		}
	}
}
