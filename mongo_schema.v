module better_auth

import x.json2

fn (mut storage MongoStorage) index(model string, fields []string, unique bool, ttl bool, optional_type string) ! {
	mut key := map[string]BSONValue{}
	for field in fields {
		key[storage.column(model, field)] = BSONValue(1)
	}
	mut definition := {
		'key':  BSONValue(key)
		'name': BSONValue('ba_' + fields.join('_') + if unique { '_unique' } else { '' })
	}
	if unique { definition['unique'] = BSONValue(true) }
	if ttl { definition['expireAfterSeconds'] = BSONValue(0) }
	if optional_type != '' { definition['partialFilterExpression'] = BSONValue({
			storage.column(model, fields[0]): BSONValue({
				'$type': BSONValue(optional_type)
			})
		}) }
	// Nabu creates equivalent indexes under MongoDB's default names. Reuse them
	// instead of attempting an identical index under our migration-owned name.
	listed := storage.client.command(storage.options.database, {
		'listIndexes': BSONValue(storage.collection(model))
	}, 1, false)!
	cursor := (listed['cursor'] or { return error('missing MongoDB index cursor') }).as_map()
	for entry in (cursor['firstBatch'] or { json2.Any([]json2.Any{}) }).as_array() {
		index := entry.as_map()
		existing_key := (index['key'] or { json2.Any(map[string]json2.Any{}) }).as_map()
		if existing_key.keys() != key.keys() { continue
		 }
		mut same := true
		for name, _ in key {
			if (existing_key[name] or { json2.Any(0) }).int() != 1 { same = false }
		}
		if !same || (index['unique'] or { json2.Any(false) }).bool() != unique { continue
		 }
		if (index['sparse'] or { json2.Any(false) }).bool() || 'collation' in index { continue
		 }
		if ttl != ('expireAfterSeconds' in index) { continue
		 }
		if ttl && (index['expireAfterSeconds'] or { json2.Any(-1) }).i64() != 0 { continue
		 }
		if optional_type == '' {
			if 'partialFilterExpression' !in index { return }
		} else if filter := index['partialFilterExpression'] {
			expected := json2.Any({
				storage.column(model, fields[0]): json2.Any({
					'$type': json2.Any(optional_type)
				})
			})
			if filter.json_str() == expected.json_str() { return }
		}
	}
	storage.client.command(storage.options.database, {
		'createIndexes': BSONValue(storage.collection(model))
		'indexes':       BSONValue([BSONValue(definition)])
	}, 2, false)!
}

// Explicit migration keeps application startup in control of index creation.
pub fn (mut storage MongoStorage) migrate() ! {
	if storage.transaction { return error('cannot migrate active MongoDB transaction') }
	// Create every collection before a transaction can touch it.
	for model, _ in postgres_core_fields {
		storage.client.command(storage.options.database, {
			'create': BSONValue(storage.collection(model))
		}, 2, false) or {
			if err is MongoDriverError {
				if err.code != 48 { return err }
			} else {
				return err
			}
			map[string]json2.Any{}
		}
	}
	storage.index('user', ['email'], true, false, '')!
	storage.index('session', ['token'], true, false, '')!
	storage.index('session', ['userId'], false, false, '')!
	storage.index('session', ['expiresAt'], false, true, '')!
	storage.index('account', ['providerId', 'accountId'], true, false, '')!
	storage.index('account', ['userId'], false, false, '')!
	storage.index('verification', ['identifier'], false, false, '')!
	storage.index('rateLimit', ['key'], true, false, '')!
	storage.index('twoFactor', ['userId'], false, false, '')!
	for model in ['user', 'session'] {
		for field, definition in storage.additional(model) {
			if definition.unique {
				kind := match definition.field_type {
					'string' { 'string' }
					'number' { 'number' }
					'boolean' { 'bool' }
					'date' { 'date' }
					else { return error('MongoDB unique additional field requires a scalar type') }
				}

				storage.index(model, [field], true, false, kind)!
			}
		}
	}
}

fn bson_array(values ...BSONValue) BSONValue {
	return BSONValue(values)
}

fn bson_expr(name string, values ...BSONValue) BSONValue {
	return BSONValue({
		name: bson_array(...values)
	})
}

pub fn (mut storage MongoStorage) consume_rate_limit(input RateLimitInput) !RateLimitDecision {
	count := storage.column('rateLimit', 'count')
	last := storage.column('rateLimit', 'lastRequest')
	key := storage.column('rateLimit', 'key')
	expired := bson_expr('$or', bson_expr('$eq', BSONValue({
		'$type': BSONValue('$' + count)
	}), BSONValue('missing')), bson_expr('$lte', BSONValue('$' + last),
		BSONValue(input.now - input.window * 1000)))
	permitted := bson_expr('$or', expired, bson_expr('$lt', BSONValue('$' + count),
		BSONValue(input.max)))
	updated_count := bson_expr('$cond', expired, BSONValue(1), bson_expr('$cond', permitted, bson_expr('$add', BSONValue(
		'$' + count), BSONValue(1)), BSONValue('$' + count)))
	updated_last := bson_expr('$cond', permitted, BSONValue(input.now), BSONValue('$' + last))
	update := BSONValue([
		BSONValue({
			'$set': BSONValue({
				count: updated_count
				last:  updated_last
			})
		}),
	])
	command := {
		'findAndModify': BSONValue(storage.collection('rateLimit'))
		'query':         BSONValue({
			key: BSONValue(input.key)
		})
		'update':        update
		'upsert':        BSONValue(true)
		'new':           BSONValue(false)
	}
	reply := storage.command(command, 3) or {
		if err is MongoDriverError {
			if err.code == 11000 { storage.command(command, 3)! } else { return err }
		} else {
			return err
		}
	}
	mut previous := ?RateLimitRecord(none)
	if value := reply['value'] {
		if value !is json2.Null {
			row := value.as_map()
			previous = RateLimitRecord{
				key:          input.key
				count:        (row[count] or { json2.Any(0) }).i64()
				last_request: (row[last] or { json2.Any(0) }).i64()
			}
		}
	}
	decision := decide_rate_limit(previous, input)
	if decision.reset { storage.delete_rows('rateLimit', {
			last: BSONValue({
				'$lt': BSONValue(input.prune_before)
			})
		})! }
	return decision
}
