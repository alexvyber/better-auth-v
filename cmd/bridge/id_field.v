module main

import better_auth
import json
import os
import x.json2

fn id_field_command() ! {
	fields := json2.decode[map[string]json2.Any](os.get_raw_line())!
	options := json.decode(better_auth.IDFieldOptions, (fields['options'] or {
		json2.Any(map[string]json2.Any{})
	}).json_str())!
	mut state := json.decode(better_auth.IDFieldState, (fields['state'] or {
		json2.Any(map[string]json2.Any{})
	}).json_str())!
	mut warnings := []string{}
	mut defined := true
	mut value := json2.Any(json2.Null{})
	operation := fields['op']!.str()
	match operation {
		'descriptor' {
			value = json2.decode[json2.Any](json.encode(better_auth.id_field_descriptor(options)))!
		}
		'random' {
			value = better_auth.generate_auth_id(32)!
		}
		'uuid' {
			value = better_auth.generate_uuid()!
		}
		'input' {
			result := better_auth.id_field_input(fields['value'] or { json2.Any(json2.Null{}) },
				options)!
			if actual := result.value {
				value = actual
			} else {
				defined = false
			}
		}
		'output' {
			result := better_auth.id_field_output(fields['value'] or { json2.Any(json2.Null{}) })
			if actual := result.value {
				value = actual
			} else {
				defined = false
			}
		}
		'deterministic' {
			digest := json.decode([]u8, fields['digest']!.json_str())!
			result := state.deterministic_id(digest, options.strategy)!
			warnings = result.warnings.clone()
			value = result.value
		}
		else {
			return error('unknown ID field operation')
		}
	}

	println('{"defined":${defined},"value":${value.json_str()},"state":${json.encode(state)},"warnings":${json.encode(warnings)}}')
}
