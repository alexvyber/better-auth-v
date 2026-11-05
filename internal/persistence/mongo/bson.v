module better_auth

import encoding.hex
import math
import x.json2

pub struct BSONNull {}

pub struct BSONDate {
pub:
	millis i64
}

pub struct BSONObjectID {
pub:
	hex string
}

pub struct BSONBinary {
pub:
	subtype u8
	data    []u8
}

pub type BSONValue = BSONNull
	| BSONDate
	| BSONObjectID
	| BSONBinary
	| bool
	| int
	| i64
	| f64
	| string
	| []BSONValue
	| map[string]BSONValue

fn bson_integer(mut bytes []u8, value u64, width int) {
	for i in 0 .. width {
		bytes << u8(value >> (i * 8))
	}
}

fn bson_document(document map[string]BSONValue, depth int) ![]u8 {
	if depth > 100 { return error('BSON nesting exceeds 100 levels') }
	mut bytes := []u8{len: 4}
	for key, value in document {
		if key.contains('\x00') { return error('BSON keys cannot contain NUL') }
		kind := match value {
			f64 { u8(1) }
			string { u8(2) }
			map[string]BSONValue { u8(3) }
			[]BSONValue { u8(4) }
			BSONBinary { u8(5) }
			BSONObjectID { u8(7) }
			bool { u8(8) }
			BSONDate { u8(9) }
			BSONNull { u8(10) }
			int { u8(16) }
			i64 { u8(18) }
		}

		bytes << kind
		bytes << key.bytes()
		bytes << u8(0)
		match value {
			f64 {
				bson_integer(mut bytes, math.f64_bits(value), 8)
			}
			string {
				bson_integer(mut bytes, u64(value.len + 1), 4)
				bytes << value.bytes()
				bytes << u8(0)
			}
			map[string]BSONValue {
				bytes << bson_document(value, depth + 1)!
			}
			[]BSONValue {
				mut array := map[string]BSONValue{}
				for i, item in value {
					array[i.str()] = item
				}
				bytes << bson_document(array, depth + 1)!
			}
			BSONBinary {
				if value.subtype == 2 { return error('legacy BSON binary subtype is unsupported') }
				bson_integer(mut bytes, u64(value.data.len), 4)
				bytes << value.subtype
				bytes << value.data
			}
			BSONObjectID {
				if value.hex.len != 24 {
					return error('ObjectId must have 24 hexadecimal characters')
				}
				bytes << hex.decode(value.hex)!
			}
			bool {
				bytes << u8(value)
			}
			BSONDate {
				bson_integer(mut bytes, u64(value.millis), 8)
			}
			BSONNull {}
			int {
				bson_integer(mut bytes, u64(i64(value)), 4)
			}
			i64 {
				bson_integer(mut bytes, u64(value), 8)
			}
		}

		if bytes.len > 48 * 1024 * 1024 { return error('BSON document exceeds command size limit') }
	}
	bytes << u8(0)
	for i in 0 .. 4 {
		bytes[i] = u8(u32(bytes.len) >> (i * 8))
	}
	return bytes
}

pub fn encode_bson(document map[string]BSONValue) ![]u8 {
	return bson_document(document, 0)
}

// JSON-looking Extended JSON wrappers are ordinary application objects here.
// Only explicit BSONDate/ObjectID/Binary values introduce database types.
pub fn bson_from_json(value json2.Any) !BSONValue {
	return match value {
		json2.Null {
			BSONValue(BSONNull{})
		}
		bool {
			BSONValue(value)
		}
		int {
			BSONValue(value)
		}
		i64 {
			BSONValue(value)
		}
		f64 {
			BSONValue(value)
		}
		string {
			BSONValue(value)
		}
		[]json2.Any {
			mut array := []BSONValue{}
			for item in value {
				array << bson_from_json(item)!
			}
			BSONValue(array)
		}
		map[string]json2.Any {
			mut document := map[string]BSONValue{}
			for key, item in value {
				document[key] = bson_from_json(item)!
			}
			BSONValue(document)
		}
		else {
			return error('unsupported JSON value for BSON')
		}
	}
}
