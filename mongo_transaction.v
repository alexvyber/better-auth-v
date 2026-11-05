module better_auth

import x.json2

pub interface ManagedTransactionStorage {
mut:
	run_managed_transaction(operation fn () !string) !string
}

@[heap]
struct MongoTransactionAttempt {
mut:
	operation  fn () !string @[required]
	result     string
	failure    ?IError
	error_json string
}

fn mongo_transaction_callback(data voidptr) &char {
	mut attempt := unsafe { &MongoTransactionAttempt(data) }
	attempt.failure = none
	attempt.result = attempt.operation() or {
		attempt.failure = err
		mut labels := []json2.Any{}
		if err is MongoDriverError {
			for label in err.labels {
				labels << json2.Any(label)
			}
		}
		attempt.error_json = json2.Any({
			'errmsg':      json2.Any(err.msg())
			'errorLabels': json2.Any(labels)
		}).json_str()
		return attempt.error_json.str
	}
	return unsafe { nil }
}

pub fn (mut storage MongoStorage) run_managed_transaction(operation fn () !string) !string {
	if storage.transaction || storage.managed {
		return error('MongoDB transaction is already active')
	}
	storage.managed = true
	defer {
		storage.managed = false
		storage.transaction = false
		storage.snapshots.clear()
	}
	mut attempt := &MongoTransactionAttempt{
		operation: operation
	}
	mongo_driver_reply(C.ba_mongo_managed(storage.client.handle, mongo_transaction_callback,
		attempt)) or {
		if cause := attempt.failure { return cause }
		return err
	}
	return attempt.result
}
