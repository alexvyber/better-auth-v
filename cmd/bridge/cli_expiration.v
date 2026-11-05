module main

import better_auth
import json
import os
import x.json2
import time

fn expiration_command() ! {
	fields := json2.decode[map[string]json2.Any](os.get_raw_line())!
	value := fields['value'] or { return error('missing expiration') }
	kind := fields['kind'] or { return error('missing expiration type') }
	iat := (fields['iat'] or { return error('missing issue time') }).f64()
	expiration := if kind.str() == 'date' {
		better_auth.JWTExpiration(time.unix_milli(value.i64()))
	} else if value is string {
		better_auth.JWTExpiration(value)
	} else {
		better_auth.JWTExpiration(value.f64())
	}
	println(json.encode(better_auth.jwt_expiration_at(expiration, iat)!))
}
