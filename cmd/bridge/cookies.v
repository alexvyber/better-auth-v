module main

import better_auth
import json
import os
import x.json2

fn bridge_cookie_attributes(encoded string) !map[string]map[string]json2.Any {
	fields := json2.decode[map[string]json2.Any](encoded)!
	mut result := map[string]map[string]json2.Any{}
	for key, value in fields {
		result[key] = value.as_map().clone()
	}
	return result
}

fn bridge_auth_cookie(cookie better_auth.AuthCookie) json2.Any {
	return json2.Any({
		'name':       json2.Any(cookie.name)
		'attributes': json2.Any(cookie.attributes)
	})
}

fn cookie_command() ! {
	input := json2.decode[map[string]json2.Any](os.get_raw_line())!
	op := (input['op'] or { json2.Any('') }).str()
	header := (input['header'] or { json2.Any('') }).str()
	name := (input['name'] or { json2.Any('') }).str()
	value := (input['value'] or { json2.Any('') }).str()
	match op {
		'get-cookies', 'create-cookie' {
			factory := better_auth.create_cookie_getter((input['options'] or {
				json2.Any(map[string]json2.Any{})
			}).json_str(), os.getenv('NODE_ENV') == 'production')!
			if op == 'get-cookies' {
				mut cookies := map[string]json2.Any{}
				for kind, cookie in factory.get_cookies() {
					cookies[kind] = bridge_auth_cookie(cookie)
				}
				println(json2.Any(cookies).json_str())
			} else {
				println(bridge_auth_cookie(factory.create_cookie(name, (input['attributes'] or {
					json2.Any(map[string]json2.Any{})
				}).as_map())).json_str())
			}
		}
		'cache-open' {
			config := json.decode(better_auth.CookieCacheReadConfig, (input['config'] or {
				json2.Any(map[string]json2.Any{})
			}).json_str())!
			now := (input['now_millis'] or { json2.Any(i64(0)) }).i64()
			opened := better_auth.open_cookie_cache(header, config, now)!
			if snapshot := opened.value {
				println(json.encode(snapshot))
			} else {
				println('null')
			}
		}
		'cache-finish' {
			snapshot := json.decode(better_auth.CookieCacheSnapshot, (input['snapshot'] or {
				return error('missing snapshot')
			}).json_str())!
			expected := if raw := input['expected_version'] {
				if raw is string { ?string(raw) } else { none }
			} else {
				none
			}
			finished := better_auth.finish_cookie_cache(snapshot, expected, (input['now_millis'] or {
				json2.Any(i64(0))
			}).i64())!
			if payload := finished.value {
				println(json.encode(payload))
			} else {
				println('null')
			}
		}
		'parse' {
			mut entries := []json2.Any{}
			for key, val in better_auth.parse_cookies(header) {
				entries << json2.Any([json2.Any(key), json2.Any(val)])
			}
			println(json2.Any(entries).json_str())
		}
		'split' {
			println(json.encode(better_auth.split_set_cookie_header(header)))
		}
		'strip' {
			println(json.encode(better_auth.strip_secure_cookie_prefix(name)))
		}
		'parse-set' {
			mut entries := []json2.Any{}
			for key, cookie in better_auth.parse_set_cookie_header(header) {
				mut attrs := cookie.attributes.clone()
				attrs['value'] = cookie.value
				if cookie.expires_present {
					attrs['expires'] = {
						'$date': if millis := cookie.expires_at {
							json2.Any(millis)
						} else {
							json2.Any(json2.Null{})
						}
					}
				}
				if cookie.invalid_max_age { attrs['max-age'] = {
						'$nan': json2.Any(true)
					} }
				entries << json2.Any([json2.Any(key), json2.Any(attrs)])
			}
			println(json2.Any(entries).json_str())
		}
		'options' {
			attrs := (input['attributes'] or { json2.Any(map[string]json2.Any{}) }).as_map()
			println(json2.Any(better_auth.to_cookie_options(attrs)).json_str())
		}
		'set-request' {
			println(json.encode(better_auth.set_request_cookie(header, name, value)))
		}
		'apply', 'remove' {
			values := (input['values'] or { json2.Any([]json2.Any{}) }).as_array().map(it.str())
			if op == 'apply' {
				println(json.encode(better_auth.apply_set_cookies(header, values)))
			} else {
				println(json.encode(better_auth.remove_set_cookie_entries(values, name)))
			}
		}
		'session', 'chunks' {
			result := if op == 'session' {
				better_auth.get_session_cookie(header, (input['prefix'] or {
					json2.Any('better-auth')
				}).str(), name)
			} else {
				direct := if raw := input['value'] {
					if raw is string { ?string(raw) } else { none }
				} else {
					none
				}
				better_auth.get_chunked_cookie(header, name, direct)
			}
			if found := result {
				println(json.encode(found))
			} else {
				println('null')
			}
		}
		'expire-options' {
			attrs := (input['attributes'] or { json2.Any(map[string]json2.Any{}) }).as_map()
			println(json2.Any(better_auth.expire_cookie_attributes(attrs)).json_str())
		}
		else {
			return error('unknown cookie operation')
		}
	}
}
