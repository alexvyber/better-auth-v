module main

import better_auth
import json
import os
import x.json2

fn serve_commands(mut auth better_auth.Auth, mut state State, mut storage better_auth.Storage, fallback_hasher better_auth.PasswordHasher) {
	for {
		line := os.get_raw_line()
		if line == '' { break
		 }
		command := json.decode(Command, line) or {
			emit(Reply{ error: 'invalid command' })
			continue
		}
		auth.set_adapter_transactions(command.transactions) or {
			emit_failure(command.id, err)
			continue
		}
		state.now = command.now
		state.now_millis = command.now_millis
		match command.op {
			'migrate' {
				auth.migrate_storage() or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id })
			}
			'mongo-transaction-stats' {
				if mut storage is better_auth.MongoStorage {
					stats := storage.transaction_stats() or {
						emit_failure(command.id, err)
						continue
					}
					emit(Reply{ id: command.id, value_json: json2.Any(stats).json_str() })
				} else {
					emit(Reply{ id: command.id, error: 'MongoDB diagnostics require MongoDB storage' })
				}
			}
			'transaction' {
				value := auth.with_transaction(fn [command] (mut context better_auth.EndpointContext) !string {
					return callback_with_context(command.method, '{}', mut context)
				}) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: value })
			}
			'internal' {
				log_start := state.logs.len
				value := auth.with_internal(fn [command] (mut context better_auth.EndpointContext) !string {
					return invoke_bridge_internal(mut context, command)
				}) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: value, logs: state.logs[log_start..].clone() })
			}
			'configured-password-hash' {
				value := fallback_hasher.hash(command.password) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'configured-password-verify' {
				value := fallback_hasher.verify(command.password, command.hash) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'password-hash' {
				value := better_auth.ScryptHasher{}.hash(command.password) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'password-verify' {
				value := better_auth.ScryptHasher{}.verify(command.password, command.hash) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(value) })
			}
			'prepare-request' {
				prepared := auth.prepare_request(command.request, command.direct) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, value_json: json.encode(prepared) })
			}
			'complete-request' {
				prepared := json.decode(better_auth.PreparedRequest, command.prepared_json) or {
					emit_failure(command.id, err)
					continue
				}
				actual := better_auth.PreparedRequest{
					...prepared
					request:  command.hook_request or { prepared.request }
					response: command.hook_response
				}
				email_start := state.emails.len
				log_start := state.logs.len
				response := auth.handle_prepared(actual)
				emit(Reply{
					id:       command.id
					response: response
					emails:   state.emails[email_start..].clone()
					logs:     state.logs[log_start..].clone()
				})
			}
			'request' {
				start := state.emails.len
				log_start := state.logs.len
				mut response := better_auth.Response{}
				if command.direct {
					response = auth.call_result(command.request) or {
						message := 'Internal server error'
						emit(Reply{
							id:           command.id
							error:        message
							error_status: 500
							error_code:   'INTERNAL_SERVER_ERROR'
						})
						continue
					}
				} else {
					response = auth.handle(command.request)
				}

				emit(Reply{
					id:       command.id
					response: response
					emails:   state.emails[start..].clone()
					logs:     state.logs[log_start..].clone()
				})
			}
			'inspect' {
				if command.model == 'session' {
					mut records := []better_auth.Session{}
					users := storage.users() or {
						emit_failure(command.id, err)
						continue
					}
					for user in users {
						records << storage.sessions(user.id) or { []better_auth.Session{} }
					}
					encoded := filter_inspection('[' +
						records.map(better_auth.encode_session(it)).join(',') + ']',
						command.where_json) or {
						emit_failure(command.id, err)
						continue
					}
					emit(Reply{ id: command.id, records_json: encoded })
					continue
				}
				if command.model == 'twoFactor' {
					if mut storage is better_auth.TwoFactorStorage {
						records := storage.two_factors('') or {
							emit_failure(command.id, err)
							continue
						}
						encoded := filter_inspection('[' +
							records.map(better_auth.encode_two_factor(it)).join(',') + ']',
							command.where_json) or {
							emit_failure(command.id, err)
							continue
						}
						emit(Reply{ id: command.id, records_json: encoded })
						continue
					}
				}
				if command.model == 'verification' {
					records := storage.verifications() or {
						emit_failure(command.id, err)
						continue
					}
					encoded := filter_inspection('[' +
						records.map(better_auth.encode_verification(it)).join(',') + ']',
						command.where_json) or {
						emit_failure(command.id, err)
						continue
					}
					emit(Reply{ id: command.id, records_json: encoded })
					continue
				}
				if command.model == 'account' {
					records := storage.accounts('') or {
						emit_failure(command.id, err)
						continue
					}
					encoded := filter_inspection(json.encode(records), command.where_json) or {
						emit_failure(command.id, err)
						continue
					}
					emit(Reply{ id: command.id, records_json: encoded })
					continue
				} else if command.model != 'user' {
					emit(Reply{ id: command.id, error: 'unsupported inspection model' })
					continue
				}
				records := storage.users() or {
					emit_failure(command.id, err)
					continue
				}
				encoded := filter_inspection('[' +
					records.map(better_auth.encode_user(it)).join(',') + ']', command.where_json) or {
					emit_failure(command.id, err)
					continue
				}
				emit(Reply{ id: command.id, records_json: encoded })
			}
			'close' {
				emit(Reply{ id: command.id })
				break
			}
			else {
				emit(Reply{ id: command.id, error: 'unsupported command' })
			}
		}
	}
}
