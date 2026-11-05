// Trusted test/development command runner; configuration arrives on stdin.
module main

import better_auth
import os
import x.json2

fn main() {
	input := json2.decode[map[string]json2.Any](os.get_raw_line()) or {
		eprintln('invalid MongoDB command input')
		exit(1)
	}
	uri := (input['uri'] or { json2.Any('') }).str()
	database := (input['database'] or { json2.Any('admin') }).str()
	command := better_auth.bson_from_json(input['command'] or { json2.Any(map[string]json2.Any{}) }) or {
		eprintln(err)
		exit(1)
	}
	if command is map[string]better_auth.BSONValue {
		mut client := better_auth.open_mongo_client(uri) or {
			eprintln(err)
			exit(1)
		}
		reply := client.command(database, command, 0, false) or {
			eprintln(err)
			exit(1)
		}
		client.close() or {}
		println(json2.Any(reply).json_str())
	} else {
		eprintln('command must be an object')
		exit(1)
	}
}
