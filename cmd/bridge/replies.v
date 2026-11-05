module main

import better_auth
import json

fn emit(reply Reply) {
	base := json.encode(reply)
	encoded := reply.emails.map(better_auth.encode_email(it)).join(',')
	println(base[..base.len - 1] + ',"emails":[' + encoded + ']}')
	flush_stdout()
}

fn emit_failure(id int, reason IError) {
	emit(Reply{
		id:                 id
		error:              reason.msg()
		error_is_api:       reason is better_auth.APIError
		error_status:       if reason is better_auth.APIError { reason.status } else { 500 }
		error_code:         if reason is better_auth.APIError {
			reason.code
		} else {
			'INTERNAL_SERVER_ERROR'
		}
		error_mongo:        reason is better_auth.MongoDriverError
		error_mongo_code:   if reason is better_auth.MongoDriverError { reason.code } else { 0 }
		error_mongo_labels: if reason is better_auth.MongoDriverError {
			reason.labels
		} else {
			[]string{}
		}
	})
}
