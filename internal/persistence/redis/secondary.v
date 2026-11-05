module better_auth

import sync
import x.json2

// A client moves Redis commands and replies. Prefixing, atomic scripts, fallback
// policy and scans belong to this native store.
pub interface RedisClient {
mut:
	execute(method string, arguments []json2.Any) !json2.Any
}

pub struct RedisStorageOptions {
pub:
	key_prefix string = 'better-auth:' @[json: keyPrefix]
}

@[heap]
pub struct RedisStorage {
mut:
	client          RedisClient
	options         RedisStorageOptions
	supports_getdel bool        = true
	mutex           &sync.Mutex = sync.new_mutex()
}

pub fn redis_storage(client RedisClient, options RedisStorageOptions) RedisStorage {
	return RedisStorage{
		client:  client
		options: options
	}
}

const redis_getdel_script = '\nlocal value = redis.call("GET", KEYS[1])\nif value ~= false then\n  redis.call("DEL", KEYS[1])\nend\nreturn value\n'
const redis_increment_script = '\nlocal value = redis.call("INCR", KEYS[1])\nif value == 1 then\n  redis.call("EXPIRE", KEYS[1], ARGV[1])\nend\nreturn value\n'

fn redis_string_result(value json2.Any) !Lookup[string] {
	if value is json2.Null { return Lookup[string]{} }
	if value !is string { return error('Redis returned a non-string value') }
	return Lookup[string]{
		value: value.str()
	}
}

pub fn (mut storage RedisStorage) get(key string) !Lookup[string] {
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	return redis_string_result(storage.client.execute('get', [
		json2.Any(storage.options.key_prefix + key),
	])!)
}

pub fn (mut storage RedisStorage) get_and_delete(key string) !Lookup[string] {
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	prefixed := storage.options.key_prefix + key
	if storage.supports_getdel {
		result := storage.client.execute('call', [json2.Any('GETDEL'), json2.Any(prefixed)]) or {
			if !err.msg().to_lower().contains('unknown command') { return err }
			storage.supports_getdel = false
			json2.Any(json2.Null{})
		}
		if storage.supports_getdel { return redis_string_result(result) }
	}
	return redis_string_result(storage.client.execute('eval', [
		json2.Any(redis_getdel_script),
		json2.Any(1),
		json2.Any(prefixed),
	])!)
}

pub fn (mut storage RedisStorage) increment(key string, ttl i64) !i64 {
	if ttl <= 0 { return error('Redis storage increment ttl must be a positive integer') }
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	value := storage.client.execute('eval', [json2.Any(redis_increment_script), json2.Any(1),
		json2.Any(storage.options.key_prefix + key), json2.Any(ttl)])!
	return value.i64()
}

pub fn (mut storage RedisStorage) set(key string, value string, ttl i64) ! {
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	if ttl > 0 {
		storage.client.execute('setex', [json2.Any(storage.options.key_prefix + key), json2.Any(ttl),
			json2.Any(value)])!
	} else {
		storage.client.execute('set',
			[json2.Any(storage.options.key_prefix + key), json2.Any(value)])!
	}
}

pub fn (mut storage RedisStorage) delete(key string) ! {
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	storage.client.execute('del', [json2.Any(storage.options.key_prefix + key)])!
}

fn (storage &RedisStorage) redis_scan_pattern() string {
	mut result := ''
	for byte in storage.options.key_prefix.bytes() {
		if byte in [`\\`, `*`, `?`, `[`, `]`] { result += '\\' }
		result += byte.ascii_str()
	}
	return result + '*'
}

fn (mut storage RedisStorage) scan_page(cursor string) !(string, []json2.Any) {
	page := storage.client.execute('scan', [json2.Any(cursor), json2.Any('MATCH'),
		json2.Any(storage.redis_scan_pattern()), json2.Any('COUNT'), json2.Any(100)])!
	if page !is []json2.Any { return error('invalid Redis SCAN response') }
	items := page.as_array()
	if items.len != 2 { return error('invalid Redis SCAN response') }
	if items[0] !is string || items[1] !is []json2.Any {
		return error('invalid Redis SCAN response')
	}
	return items[0].str(), items[1].as_array()
}

pub fn (mut storage RedisStorage) list_keys() ![]string {
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	mut cursor := '0'
	mut keys := map[string]bool{}
	for {
		next, batch := storage.scan_page(cursor)!
		for value in batch {
			raw := value.str()

			keys[if raw.len >= storage.options.key_prefix.len {
				raw[storage.options.key_prefix.len..]
			} else {
				''
			}] = true
		}
		cursor = next
		if cursor == '0' { break
		 }
	}
	return keys.keys()
}

pub fn (mut storage RedisStorage) clear() ! {
	storage.mutex.@lock()
	defer { storage.mutex.unlock() }
	mut cursor := '0'
	for {
		next, batch := storage.scan_page(cursor)!
		if batch.len > 0 { storage.client.execute('del', batch)! }
		cursor = next
		if cursor == '0' { break
		 }
	}
}
