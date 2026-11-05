module better_auth

import x.json2

$if mongodb ? {
	#flag -DBA_ENABLE_MONGODB -DMONGOC_STATIC -DBSON_STATIC
	#flag -I @VMODROOT/build/deps/mongoc/include/mongoc-2.5.8
	#flag -I @VMODROOT/build/deps/mongoc/include/bson-2.5.8
	#flag @VMODROOT/build/deps/mongoc/lib/libmongoc2.a
	#flag @VMODROOT/build/deps/mongoc/lib/libbson2.a
	#flag -lresolv -lssl -lcrypto
	$if darwin {
		#flag -I /opt/homebrew/opt/openssl@3/include
		#flag -L /opt/homebrew/opt/openssl@3/lib
	}
}
#include "@VMODROOT/mongo_driver.h"

@[typedef]
struct C.ba_mongo {}

fn C.ba_mongo_open(&char) &C.ba_mongo
fn C.ba_mongo_close(&C.ba_mongo)
fn C.ba_mongo_command(&C.ba_mongo, &char, &u8, usize, int, int) &char
fn C.ba_mongo_transaction(&C.ba_mongo, int) &char
fn C.ba_mongo_oid(&u8)
fn C.ba_mongo_free(&char)

pub struct MongoDriverError {
	Error
pub:
	code    int
	message string
}

pub fn (error MongoDriverError) msg() string {
	return error.message
}

@[heap]
pub struct MongoClient {
mut:
	handle &C.ba_mongo = unsafe { nil }
	closed bool
}

pub fn open_mongo_client(uri string) !&MongoClient {
	$if !mongodb ? {
		return error('MongoDB requires a build with -d mongodb and the native driver dependency')
	}
	if uri == '' || uri.contains('\x00') { return error('invalid MongoDB connection configuration') }
	handle := C.ba_mongo_open(&char(uri.str))
	if isnil(handle) { return error('invalid MongoDB connection configuration') }
	return &MongoClient{
		handle: handle
	}
}

fn mongo_driver_reply(encoded &char) !map[string]json2.Any {
	if isnil(encoded) { return error('MongoDB driver response is unavailable') }
	data := unsafe { encoded.vstring().clone() }
	C.ba_mongo_free(encoded)
	envelope := json2.decode[map[string]json2.Any](data)!
	if !(envelope['ok'] or { json2.Any(false) }).bool() {
		return MongoDriverError{
			code:    (envelope['code'] or { json2.Any(0) }).int()
			message: (envelope['message'] or { json2.Any('MongoDB operation failed') }).str()
		}
	}
	mut reply := (envelope['reply'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	if cursor_id := envelope['cursorId'] {
		mut cursor := (reply['cursor'] or { json2.Any(map[string]json2.Any{}) }).as_map()
		cursor['id'] = cursor_id
		reply['cursor'] = json2.Any(cursor)
	}
	if errors := reply['writeErrors'] {
		list := errors.as_array()
		if list.len > 0 {
			item := list[0].as_map()
			return MongoDriverError{
				code:    (item['code'] or { json2.Any(0) }).int()
				message: (item['errmsg'] or { json2.Any('MongoDB write failed') }).str()
			}
		}
	}
	if item := reply['writeConcernError'] {
		fields := item.as_map()
		return MongoDriverError{
			code:    (fields['code'] or { json2.Any(0) }).int()
			message: (fields['errmsg'] or { json2.Any('MongoDB write concern failed') }).str()
		}
	}
	return reply
}

// Trusted raw database commands. BSON values preserve literal JSON objects and
// make ObjectId, binary UUID and Date conversion explicit at the model boundary.
pub fn (mut client MongoClient) command(database string, command map[string]BSONValue, mode int, attach_session bool) !map[string]json2.Any {
	if client.closed { return error('MongoDB client is closed') }
	if database == '' || database.contains('\x00') { return error('invalid MongoDB database') }
	encoded := encode_bson(command)!
	return mongo_driver_reply(C.ba_mongo_command(client.handle, &char(database.str), encoded.data,
		usize(encoded.len), mode, int(attach_session)))
}

fn (mut client MongoClient) transaction(action int) ! {
	if client.closed { return error('MongoDB client is closed') }
	mongo_driver_reply(C.ba_mongo_transaction(client.handle, action))!
}

pub fn (mut client MongoClient) close() ! {
	if client.closed { return }
	C.ba_mongo_close(client.handle)
	client.closed = true
}

fn mongo_object_id() string {
	mut bytes := []u8{len: 25}
	C.ba_mongo_oid(bytes.data)
	return bytes[..24].bytestr()
}
