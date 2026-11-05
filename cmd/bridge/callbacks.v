module main

import better_auth
import json
import os
import x.json2
import crypto.rand
import encoding.hex
import time

struct CallbackReply {
	op                 string
	value_json         string
	error              ?string
	callback_id        string
	error_status       int
	error_is_api       bool
	error_code         string
	error_mongo        bool
	error_mongo_code   int
	error_mongo_labels []string
}

fn callback_error(reply CallbackReply) IError {
	message := reply.error or { 'callback failed' }
	if reply.error_is_api && reply.error_status >= 400 && reply.error_status < 600 { return better_auth.APIError{
			status:  reply.error_status
			code:    reply.error_code
			message: message
		} }
	if reply.error_mongo { return better_auth.MongoDriverError{
			code:    reply.error_mongo_code
			message: message
			labels:  reply.error_mongo_labels
		} }
	return error(message)
}

// Synchronous inside V; the TS peer awaits the supplied callback before replying.
// Only one top-level command is in flight, so callback replies cannot be confused
// with another request. This channel is available only to this test executable.
fn callback_rpc(method string, payload string) !string {
	callback_id := hex.encode(rand.bytes(8)!)
	println('{"callback":${json.encode(method)},"callback_id":${json.encode(callback_id)},"payload":${payload}}')
	flush_stdout()
	line := os.get_raw_line()
	if line == '' { return error('callback peer disconnected') }
	reply := json.decode(CallbackReply, line)!
	if reply.op != 'callback-result' { return error('unexpected callback protocol frame') }
	if reply.callback_id != callback_id { return error('callback correlation mismatch') }
	if reply.error != none { return callback_error(reply) }
	return reply.value_json
}

fn invoke_bridge_internal(mut context better_auth.EndpointContext, command Command) !string {
	if command.jwt_options_json == ''
		|| command.method !in ['signJWTWith', 'verifyJWTWithOptions', 'jwkLookupWithOptions'] {
		return context.invoke_internal(command.method, command.arguments_json)
	}
	mut options := json.decode(better_auth.JWTOptions, command.jwt_options_json)!
	if command.jwt_expiration_json != '' {
		value := json2.decode[json2.Any](command.jwt_expiration_json)!
		expiration := if value is string {
			better_auth.JWTExpiration(value)
		} else if value is map[string]json2.Any {
			millis := value['$jwtDateMillis'] or { return error('invalid JWT expiration Date') }
			if millis !is i64 && millis !is int && millis !is f64 {
				return error('invalid JWT expiration Date')
			}
			better_auth.JWTExpiration(time.unix_milli(millis.i64()))
		} else {
			if value !is i64 && value !is int && value !is f64 {
				return error('invalid JWT expiration')
			}
			better_auth.JWTExpiration(value.f64())
		}
		options = better_auth.JWTOptions{
			...options
			expiration_time: expiration
		}
	}
	if command.jwt_callback_prefix + '.getJwks' in command.jwt_callback_methods
		|| command.jwt_callback_prefix + '.createJwk' in command.jwt_callback_methods {
		options = better_auth.JWTOptions{
			...options
			key_store: RemoteJWKStore{
				prefix:  command.jwt_callback_prefix
				methods: command.jwt_callback_methods
			}
		}
	}
	method := command.jwt_callback_prefix + '.sign'
	if method in command.jwt_callback_methods {
		options = better_auth.JWTOptions{
			...options
			sign_with: fn [method] (payload string, header string, config better_auth.JWTSigningConfig) !string {
				return json2.decode[string](callback_rpc(method, '{"payload":' + payload +
					',"header":' + header + ',"config":' + json.encode(config) + '}')!)
			}
		}
	}
	args := json2.decode[[]json2.Any](command.arguments_json)!
	if command.method == 'jwkLookupWithOptions' {
		if args.len != 2 { return error('jwkLookupWithOptions requires method and value') }
		return context.jwk_lookup_with_options(args[0].str(), args[1].str(), options)
	}
	if command.method == 'verifyJWTWithOptions' {
		if args.len != 1 { return error('verifyJWTWithOptions requires a token') }
		return (context.verify_jwt_with_options(args[0].str(), options)!).value or { 'null' }
	}
	if args.len != 2 { return error('signJWTWith requires payload and signing config') }
	config := better_auth.jwt_signing_config_from_json(args[1].json_str())!
	return json.encode(context.sign_jwt_with(args[0].json_str(), better_auth.JWTSigningConfig{
		...config
		options: options
	})!)
}

fn callback_with_context(method string, payload string, mut context better_auth.EndpointContext) !string {
	callback_id := hex.encode(rand.bytes(8)!)
	println('{"callback":${json.encode(method)},"callback_id":${json.encode(callback_id)},"context":true,"transaction":${context.has_active_transaction()},"payload":${payload}}')
	flush_stdout()
	for {
		line := os.get_raw_line()
		if line == '' { return error('callback peer disconnected') }
		frame := json.decode(CallbackReply, line)!
		if frame.op == 'callback-result' {
			if frame.callback_id != callback_id { return error('callback correlation mismatch') }
			if frame.error != none { return callback_error(frame) }
			return frame.value_json
		}
		command := json.decode(Command, line)!
		if command.op == 'internal' {
			value := invoke_bridge_internal(mut context, command) or {
				emit_failure(command.id, err)
				continue
			}
			emit(Reply{ id: command.id, value_json: value })
		} else if command.op == 'transaction' {
			value := context.with_transaction(fn [command] (mut nested better_auth.EndpointContext) !string {
				return callback_with_context(command.method, '{}', mut nested)
			}) or {
				emit_failure(command.id, err)
				continue
			}
			emit(Reply{ id: command.id, value_json: value })
		} else if command.op == 'inspect' {
			mut encoded := ''
			if command.model == 'user' {
				users := context.users()!
				encoded = '[' + users.map(better_auth.encode_user(it)).join(',') + ']'
			} else if command.model == 'account' {
				encoded = better_auth.encode_accounts(context.accounts('')!)
			} else {
				emit(Reply{ id: command.id, error: 'unsupported inspection model' })
				continue
			}
			filtered := filter_inspection(encoded, command.where_json) or {
				emit_failure(command.id, err)
				continue
			}
			emit(Reply{ id: command.id, records_json: filtered })
		} else {
			emit(Reply{ id: command.id, error: 'unsupported nested operation' })
		}
	}
	return error('callback peer disconnected')
}
