module main

import better_auth
import json
import math
import os
import x.json2

struct RemoteRedisClient {}

fn (mut _ RemoteRedisClient) execute(method string, arguments []json2.Any) !json2.Any {
	return json2.decode[json2.Any](callback_rpc('redis.command',
		'{"method":${json.encode(method)},"arguments":${json2.Any(arguments).json_str()}}')!)
}

struct RedisBridgeCommand {
	id             int
	op             string
	method         string
	arguments_json string = '[]'
	options        better_auth.RedisStorageOptions
	tcp            ?better_auth.RedisTCPOptions
}

fn redis_bridge_operation(mut storage better_auth.RedisStorage, command RedisBridgeCommand) !string {
	args := json2.decode[[]json2.Any](command.arguments_json)!
	match command.method {
		'get', 'getAndDelete' {
			result := if command.method == 'get' {
				storage.get(args[0].str())!
			} else {
				storage.get_and_delete(args[0].str())!
			}
			return if value := result.value { json.encode(value) } else { 'null' }
		}
		'increment' {
			ttl := args[1]
			if ttl !is int && ttl !is i64 && ttl !is f64 {
				return error('Redis storage increment ttl must be a positive integer')
			}
			number := ttl.f64()
			if number <= 0 || math.is_nan(number) || math.is_inf(number, 0)
				|| math.floor(number) != number {
				return error('Redis storage increment ttl must be a positive integer')
			}
			return storage.increment(args[0].str(), i64(number))!.str()
		}
		'set' {
			storage.set(args[0].str(), args[1].str(), if args.len > 2 && args[2] !is json2.Null {
				args[2].i64()
			} else {
				0
			})!
			return 'null'
		}
		'delete' {
			storage.delete(args[0].str())!
			return 'null'
		}
		'listKeys' {
			return json.encode(storage.list_keys()!)
		}
		'clear' {
			storage.clear()!
			return 'null'
		}
		else {
			return error('unknown native Redis method')
		}
	}
}

fn redis_bridge() ! {
	first := json.decode(RedisBridgeCommand, os.get_raw_line())!
	if first.op != 'init' { return error('Redis bridge must be initialized') }
	client := if options := first.tcp { better_auth.RedisClient(better_auth.RedisTCPClient{
			options: options
		}) } else { better_auth.RedisClient(RemoteRedisClient{}) }
	mut storage := better_auth.redis_storage(client, first.options)
	emit(Reply{ id: first.id })
	for {
		line := os.get_raw_line()
		if line == '' { break
		 }
		command := json.decode(RedisBridgeCommand, line)!
		if command.op == 'close' {
			emit(Reply{ id: command.id })
			break
		}
		result := redis_bridge_operation(mut storage, command) or {
			emit(Reply{ id: command.id, error: err.msg() })
			continue
		}
		emit(Reply{ id: command.id, value_json: result })
	}
}
