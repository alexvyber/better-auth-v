module better_auth

import x.json2

fn adapter_model_test_query(mut auth Auth, query string) !json2.Any {
	encoded := auth.with_internal(fn [query] (mut context EndpointContext) !string {
		return context.invoke_internal('adapterQuery', query)
	})!
	return json2.decode[json2.Any](encoded)
}

fn test_custom_adapter_schema_validation_uniqueness_joins_and_rollback() ! {
	for backend in 0 .. 2 {
		mut storage := Storage(MemoryStorage{})
		if backend == 1 { storage = open_sqlite(':memory:')! }
		mut auth := new(Config{
			secret:         'custom-adapter-test-secret-at-least-32-bytes'
			adapter_models: {
				'profile': AdapterModel{
					name:   'profile_record'
					fields: {
						'owner':   AdditionalField{
							field_type: 'string'
							required:   true
							unique:     true
							field_name: 'owner_email'
							references: AdapterReference{
								model: 'user'
								field: 'email'
							}
						}
						'payload': AdditionalField{
							field_type: 'json'
						}
						'labels':  AdditionalField{
							field_type: 'string[]'
						}
						'score':   AdditionalField{
							field_type:    'number'
							default_value: json2.Any(0)
						}
					}
				}
			}
		}, storage)!
		auth.migrate_storage()!
		adapter_model_test_query(mut auth,
			'["create",{"model":"user","forceAllowId":true,"data":{"id":"owner","email":"owner@example.com","name":"Owner"}}]')!
		created := adapter_model_test_query(mut auth,
			'["create",{"model":"profile","forceAllowId":true,"data":{"id":"p","owner":"owner@example.com","labels":["a","b"],"payload":{"createdAt":"literal","nested":[1,true,null]}}}]')!
		assert created.as_map()['score']!.int() == 0
		assert created.as_map()['payload']!.as_map()['createdAt']!.str() == 'literal'
		for query in [
			'["create",{"model":"profile","data":{"owner":"missing@example.com"}}]',
			'["create",{"model":"profile","data":{"owner":"owner@example.com"}}]',
			'["create",{"model":"profile","data":{"owner":null}}]',
			'["updateMany",{"model":"profile","update":{"labels":[1]}}]',
			'["deleteMany",{"model":"profile","where":[{"field":"typo","value":"x"}]}]',
		] {
			mut rejected := false
			adapter_model_test_query(mut auth, query) or { rejected = true }
			assert rejected, query
		}
		joined := adapter_model_test_query(mut auth,
			'["findOne",{"model":"user","where":[{"field":"id","value":"owner"}],"select":["name"],"join":{"profile":true}}]')!
		assert joined.as_map()['profile']!.json_str() == created.json_str()
		mut rolled_back := false
		auth.with_transaction(fn (mut context EndpointContext) !string {
			context.invoke_internal('adapterQuery',
				'["update",{"model":"profile","where":[{"field":"id","value":"p"}],"update":{"score":7}}]')!
			context.invoke_internal('adapterQuery',
				'["create",{"model":"profile","data":{"owner":"owner@example.com"}}]')!
			return error('must roll back')
		}) or { rolled_back = true }
		assert rolled_back
		assert adapter_model_test_query(mut auth,
			'["findOne",{"model":"profile","where":[{"field":"id","value":"p"}]}]')!.json_str() == created.json_str()
		assert adapter_model_test_query(mut auth, '["count",{"model":"profile"}]')!.int() == 1
		adapter_model_test_query(mut auth,
			'["delete",{"model":"profile","where":[{"field":"id","value":"p"}]}]')!
		assert adapter_model_test_query(mut auth, '["count",{"model":"profile"}]')!.int() == 0
		auth.close()!
	}
}

fn test_custom_adapter_rejects_ambiguous_joins_even_without_base_rows() ! {
	mut auth := new(Config{
		secret:         'custom-adapter-test-secret-at-least-32-bytes'
		adapter_models: {
			'edge': AdapterModel{
				fields: {
					'from': AdditionalField{
						field_type: 'string'
						references: AdapterReference{
							model: 'user'
						}
					}
					'to':   AdditionalField{
						field_type: 'string'
						references: AdapterReference{
							model: 'user'
						}
					}
				}
			}
		}
	}, MemoryStorage{})!
	defer { auth.close() or {} }
	mut rejected := false
	adapter_model_test_query(mut auth, '["findMany",{"model":"user","join":{"edge":true}}]') or {
		rejected = true
	}
	assert rejected
}
