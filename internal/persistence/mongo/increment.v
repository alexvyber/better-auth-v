module better_auth

import x.json2

pub fn (mut s MongoStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	mut guard := map[string]BSONValue{}
	for field, value in s.physical(model, expected)! {
		guard[field] = BSONValue({
			'$eq': value
		})
	}
	guard[s.column(model, 'id')] = s.id_value(id)!
	reply := s.command({
		'findAndModify': BSONValue(s.collection(model))
		'query':         BSONValue(guard)
		'update':        BSONValue({
			'$set': BSONValue(s.physical(model, patch)!)
		})
		'new':           BSONValue(true)
	}, 3)!
	value := reply['value'] or { return false }
	return value !is json2.Null
}
