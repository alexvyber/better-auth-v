module better_auth

import encoding.hex
import x.json2

fn test_bson_spec_scalar_encoding() ! {
	// BSON specification example: { "hello": "world" }.
	assert hex.encode(encode_bson({
		'hello': BSONValue('world')
	})!) == '160000000268656c6c6f0006000000776f726c640000'
	// Distinct wire tags for ObjectId, Date, binary UUID and signed integer.
	assert hex.encode(encode_bson({
		'id': BSONValue(BSONObjectID{ hex: '0123456789abcdef01234567' })
	})!) == '15000000076964000123456789abcdef0123456700'
	assert hex.encode(encode_bson({
		'date': BSONValue(BSONDate{ millis: -1 })
	})!) == '13000000096461746500ffffffffffffffff00'
	assert hex.encode(encode_bson({
		'n': BSONValue(i64(-1))
	})!) == '10000000126e00ffffffffffffffff00'
}

fn test_bson_literal_ejson_objects_are_documents() ! {
	fields := json2.decode[map[string]json2.Any]('{"value":{"$oid":"0123456789abcdef01234567"}}')!
	value := bson_from_json(json2.Any(fields))!
	if value is map[string]BSONValue {
		bytes := encode_bson(value)!
		assert bytes[4] == 3 // Embedded document, never ObjectId (wire tag 7).
	} else {
		assert false
	}
}

fn test_bson_rejects_invalid_structural_values() ! {
	if _ := encode_bson({
		'bad\x00key': BSONValue(true)
	})
	{
		assert false
	}
	if _ := encode_bson({
		'id': BSONValue(BSONObjectID{ hex: 'not-an-objectid' })
	})
	{
		assert false
	}
	if _ := encode_bson({
		'id': BSONValue(BSONObjectID{ hex: 'xxxxxxxxxxxxxxxxxxxxxxxx' })
	})
	{
		assert false
	}
	if _ := encode_bson({
		'binary': BSONValue(BSONBinary{ subtype: 2 })
	})
	{
		assert false
	}
	mut document := {
		'leaf': BSONValue(true)
	}
	for _ in 0 .. 102 {
		document = {
			'nested': BSONValue(document.clone())
		}
	}
	if _ := encode_bson(document) { assert false
	 }
}
