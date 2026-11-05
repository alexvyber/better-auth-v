module better_auth

import x.json2

fn (storage &MongoStorage) organization_lock_collection() string {
	return '_ba_organization_lock_' + digest(storage.collection('organization'))[..16]
}

fn (mut storage MongoStorage) initialize_organization_lock() ! {
	collection := storage.organization_lock_collection()
	storage.client.command(storage.options.database, {
		'create': BSONValue(collection)
	}, 2, false) or {
		if err is MongoDriverError {
			if err.code != 48 { return err }
		} else {
			return err
		}
		map[string]json2.Any{}
	}
	storage.client.command(storage.options.database, {
		'update':  BSONValue(collection)
		'updates': BSONValue([
			BSONValue({
				'q':      BSONValue({
					'_id': BSONValue('global')
				})
				'u':      BSONValue({
					'$setOnInsert': BSONValue({
						'revision': BSONValue(i64(0))
					})
				})
				'upsert': BSONValue(true)
			}),
		])
	}, 2, false)!
	storage.organization_lock_ready = true
}

pub fn (mut storage MongoStorage) lock_organization_mutations() ! {
	if !storage.transaction { return error('organization locking requires a transaction') }
	collection := storage.organization_lock_collection()
	if !storage.organization_lock_ready {
		// A cold instance can use an already migrated store without changing its
		// schema. Missing coordination data is an explicit migration requirement.
		reply := storage.client.command(storage.options.database, {
			'find':   BSONValue(collection)
			'filter': BSONValue({
				'_id': BSONValue('global')
			})
			'limit':  BSONValue(1)
		}, 1, false)!
		cursor := (reply['cursor'] or { return error('missing organization lock cursor') }).as_map()
		if (cursor['firstBatch'] or { json2.Any([]json2.Any{}) }).as_array().len != 1 {
			return error('MongoDB organization locking requires running native migrations')
		}
		storage.organization_lock_ready = true
	}
	result := storage.command({
		'update':  BSONValue(collection)
		'updates': BSONValue([
			BSONValue({
				'q': BSONValue({
					'_id': BSONValue('global')
				})
				'u': BSONValue({
					'$inc': BSONValue({
						'revision': BSONValue(i64(1))
					})
				})
			}),
		])
	}, 2)!
	if (result['n'] or { json2.Any(0) }).int() != 1 {
		storage.organization_lock_ready = false
		return MongoDriverError{
			code:    112
			message: 'Organization coordination changed; retry the transaction'
			labels:  ['TransientTransactionError']
		}
	}
}
