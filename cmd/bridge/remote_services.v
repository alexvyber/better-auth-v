module main

import better_auth
import json
import x.json2

struct RemoteSecondaryStorage {}

fn (mut _ RemoteSecondaryStorage) get(key string) !better_auth.Lookup[string] {
	encoded := callback_rpc('secondary.get', json.encode({
		'key': key
	}))!
	if encoded == 'null' { return better_auth.Lookup[string]{} }
	value := json2.decode[json2.Any](encoded)!
	return better_auth.Lookup[string]{
		value: if value is string { value } else { value.json_str() }
	}
}

fn (mut _ RemoteSecondaryStorage) get_and_delete(key string) !better_auth.Lookup[string] {
	encoded := callback_rpc('secondary.getAndDelete', json.encode({
		'key': key
	}))!
	if encoded == 'null' { return better_auth.Lookup[string]{} }
	value := json2.decode[json2.Any](encoded)!
	return better_auth.Lookup[string]{
		value: if value is string { value } else { value.json_str() }
	}
}

fn (mut _ RemoteSecondaryStorage) set(key string, value string, ttl i64) ! {
	callback_rpc('secondary.set',
		'{"key":${json.encode(key)},"value":${json.encode(value)},"ttl":${ttl}}')!
}

fn (mut _ RemoteSecondaryStorage) delete(key string) ! {
	callback_rpc('secondary.delete', json.encode({
		'key': key
	}))!
}

fn (mut _ RemoteSecondaryStorage) increment(key string, ttl i64) !i64 {
	return json2.decode[i64](callback_rpc('secondary.increment',
		'{"key":${json.encode(key)},"ttl":${ttl}}')!)
}

struct RemoteDatabaseHook {
	methods []string
}

fn (h RemoteDatabaseHook) run(mut context better_auth.EndpointContext, event better_auth.DatabaseEvent) !better_auth.HookResult {
	method := 'db.' + event.model + '.' + event.operation + '.' + event.phase
	if method !in h.methods { return better_auth.HookResult{} }
	encoded := callback_with_context(method, event.data_json, mut context)!
	if encoded == 'false' { return better_auth.HookResult{
			cancel: true
		} }
	if encoded == 'null' { return better_auth.HookResult{} }
	value := json2.decode[map[string]json2.Any](encoded)!
	if data := value['data'] { return better_auth.HookResult{
			data_json: data.json_str()
		} }
	return better_auth.HookResult{}
}

struct RemoteHasher {
	fallback better_auth.PasswordHasher
}

fn (h RemoteHasher) hash(password string) !string {
	encoded := callback_rpc('password.hash', json.encode(password))!
	if encoded == 'null' { return h.fallback.hash(password) }
	return json2.decode[string](encoded)
}

fn (h RemoteHasher) verify(password string, hash string) !bool {
	encoded := callback_rpc('password.verify', json.encode({
		'password': password
		'hash':     hash
	}))!
	if encoded == 'null' { return h.fallback.verify(password, hash) }
	return json2.decode[bool](encoded)
}
