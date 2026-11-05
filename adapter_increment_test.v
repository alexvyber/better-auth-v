module better_auth

import math
import x.json2

fn test_native_compare_exchange_rejects_stale_guards_and_preserves_unwatched_fields() ! {
	for backend in 0 .. 2 {
		mut storage := Storage(MemoryStorage{})
		if backend == 1 { storage = open_sqlite(':memory:')! }
		mut auth := new(Config{
			secret:      'native-atomic-test-secret-with-at-least-32-bytes'
			user_fields: {
				'credits': AdditionalField{
					field_type: 'number'
				}
			}
		}, storage)!
		auth.migrate_storage()!
		adapter_increment_test_query(mut auth,
			'["create",{"model":"user","forceAllowId":true,"data":{"id":"u","name":"Original","email":"atomic@native.example","credits":0}}]')!
		auth.with_internal(fn (mut context EndpointContext) !string {
			original := (context.auth.storage.user('u')!).value or { return error('user missing') }
			context.auth.storage.update_user(User{ ...original, name: 'Concurrent edit' })!
			mut target := context.auth.storage
			if mut target is AtomicAdapterStorage {
				assert !target.compare_exchange_adapter('user', 'u', {
					'name': json2.Any('Original')
				}, {
					'name': json2.Any('Incorrect')
				})!
				assert target.compare_exchange_adapter('user', 'u', {
					'credits': json2.Any(0)
				}, {
					'credits': json2.Any(1)
				})!
			} else {
				return error('atomic implementation missing')
			}
			mut backend := context.auth.storage
			if mut backend is SQLiteStorage {
				backend.unique_fields_ready = false
				mut rejected := false
				backend.compare_exchange_adapter('user', 'u', {
					'credits': json2.Any(1)
				}, {
					'credits': json2.Any(2)
				}) or { rejected = true }
				backend.unique_fields_ready = true
				assert rejected
			}
			return ''
		})!
		row := adapter_increment_test_query(mut auth,
			'["findOne",{"model":"user","where":[{"field":"credits","value":1.0}]}]')!
		assert row.as_map()['name']!.str() == 'Concurrent edit'
		assert row.as_map()['credits']!.int() == 1
		auth.close()!
	}
}

fn test_atomic_increment_rejects_nonfinite_and_unrepresentable_deltas() ! {
	mut auth := new(Config{
		secret:      'native-atomic-test-secret-with-at-least-32-bytes'
		user_fields: {
			'credits': AdditionalField{
				field_type: 'number'
			}
		}
	}, MemoryStorage{})!
	defer { auth.close() or {} }
	adapter_increment_test_query(mut auth,
		'["create",{"model":"user","forceAllowId":true,"data":{"id":"u","name":"Counter","email":"precision@native.example","credits":9007199254740992}}]')!
	for delta in [math.inf(1), f64(1)] {
		mut rejected := false
		auth.with_internal(fn [delta] (mut context EndpointContext) !string {
			mut query :=
				json2.decode[map[string]json2.Any]('{"model":"user","where":[{"field":"id","value":"u"}],"increment":{}}')!
			query['increment'] = json2.Any({
				'credits': json2.Any(delta)
			})
			return context.adapter_increment(query)
		}) or { rejected = true }
		assert rejected
	}
	assert adapter_increment_test_query(mut auth,
		'["findOne",{"model":"user","where":[{"field":"id","value":"u"}]}]')!.as_map()['credits']!.i64() == i64(9007199254740992)
}

fn adapter_increment_test_query(mut auth Auth, query string) !json2.Any {
	encoded := auth.with_internal(fn [query] (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery', query)
	})!
	return json2.decode[json2.Any](encoded)
}
