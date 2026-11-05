// Test-only JSON-lines process. It is never part of the HTTP server.
module main

import better_auth
import json
import os
import x.json2

fn main() {
	if os.args.len == 2 && os.args[1] == '--id-field' {
		id_field_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--redis' {
		redis_bridge() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--oauth-token' {
		oauth_token_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--oauth-assertion' {
		oauth_assertion_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}

	if os.args.len == 2 && os.args[1] == '--oauth-helpers' {
		oauth_helper_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}

	if os.args.len == 2 && os.args[1] == '--provider-id-token' {
		provider_id_token_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--google' {
		google_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--cookies' {
		cookie_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--crypto' {
		crypto_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--jwt-expiration' {
		expiration_command() or {
			eprintln(err.msg())
			exit(1)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--trusted-origins' {
		input := json2.decode[map[string]json2.Any](os.get_raw_line()) or {
			eprintln(err.msg())
			exit(1)
		}
		origins := better_auth.get_trusted_origins((input['options'] or {
			json2.Any(map[string]json2.Any{})
		}).json_str(), (input['request_url'] or { json2.Any('') }).str(),
			os.getenv('BETTER_AUTH_TRUSTED_ORIGINS')) or {
			eprintln(err.msg())
			exit(1)
		}
		println(json.encode(origins))
		return
	}
	first := os.get_raw_line()
	if first == '' { return }
	init := json.decode(Command, first) or {
		emit(Reply{ error: 'invalid initialization' })
		return
	}
	if init.op != 'init' {
		emit(Reply{ id: init.id, error: 'first command must be init' })
		return
	}
	serve_bridge(init)
}
