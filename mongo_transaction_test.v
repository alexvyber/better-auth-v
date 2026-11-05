module better_auth

fn test_mongo_error_labels_and_primary_error_survive_cleanup_failures() ! {
	mut rejected := false
	decode_mongo_driver_reply('{"ok":false,"code":112,"message":"original transaction failure","reply":{"errorLabels":["TransientTransactionError"],"abortCleanupError":"secondary abort failure"}}') or {
		rejected = true
		assert err is MongoDriverError
		if err is MongoDriverError {
			assert err.code == 112
			assert err.msg() == 'original transaction failure'
			assert err.labels == ['TransientTransactionError']
			assert err.cleanup_error == 'secondary abort failure'
		}
	}
	assert rejected
	rejected = false
	decode_mongo_driver_reply('{"ok":true,"reply":{"writeErrors":[{"code":112,"errmsg":"write conflict"}],"errorLabels":["TransientTransactionError"]}}') or {
		rejected = true
		assert err is MongoDriverError
		if err is MongoDriverError { assert err.labels == [
				'TransientTransactionError',
			]
		 }
	}
	assert rejected
}
