module better_auth

import math
import strconv
import x.json2

pub struct IDFieldOptions {
pub:
	strategy              string = 'random'
	model                 string = 'user'
	disable_id_generation bool
	supports_uuids        bool
	force_allow_id        bool
	adapter_generator     bool
}

pub struct IDFieldDescriptor {
pub:
	field_type   string @[json: type]
	required     bool
	has_default  bool
	default_kind string
	model        string
}

pub struct IDFieldState {
pub mut:
	warned_serial bool
}

fn id_field_should_generate(options IDFieldOptions) bool {
	if options.disable_id_generation { return false }
	if options.strategy == 'serial' && !options.force_allow_id { return false }
	if options.strategy == 'uuid' { return !options.supports_uuids }
	return true
}

pub fn id_field_descriptor(options IDFieldOptions) IDFieldDescriptor {
	generate := id_field_should_generate(options)
	kind := if options.disable_id_generation || options.strategy in ['disabled', 'serial'] {
		'undefined'
	} else if options.strategy == 'function' {
		'configured'
	} else if options.strategy == 'uuid' {
		'uuid'
	} else if options.adapter_generator {
		'adapter'
	} else {
		'random'
	}
	return IDFieldDescriptor{
		field_type:   if options.strategy == 'serial' { 'number' } else { 'string' }
		required:     generate
		has_default:  generate
		default_kind: kind
		model:        options.model
	}
}

fn valid_forced_uuid(value string) bool {
	if value.len != 36 || value[8] != `-` || value[13] != `-` || value[18] != `-`
		|| value[23] != `-` || value[14] !in [`1`, `2`, `3`, `4`, `5`]
		|| value[19].ascii_str().to_lower() !in ['8', '9', 'a', 'b'] {
		return false
	}
	for index, byte in value.bytes() {
		if index in [8, 13, 18, 23] { continue
		 }
		if !((byte >= `0` && byte <= `9`) || (byte >= `a` && byte <= `f`)
			|| (byte >= `A` && byte <= `F`)) {
			return false
		}
	}
	return true
}

pub fn id_field_input(value json2.Any, options IDFieldOptions) !Lookup[json2.Any] {
	if !js_truthy(value) { return Lookup[json2.Any]{} }
	if options.strategy == 'serial' {
		number := if value is bool {
			if value { f64(1) } else { f64(0) }
		} else if value is string {
			text := value.trim_space()
			if text == '' {
				f64(0)
			} else {
				strconv.atof64(text) or { return Lookup[json2.Any]{} }
			}
		} else {
			value.f64()
		}
		if math.is_nan(number) { return Lookup[json2.Any]{} }
		return Lookup[json2.Any]{
			value: json2.Any(number)
		}
	}
	if options.strategy == 'uuid' {
		if id_field_should_generate(options) && !options.force_allow_id { return Lookup[json2.Any]{
				value: value
			} }
		if options.disable_id_generation { return Lookup[json2.Any]{} }
		if options.force_allow_id && value is string {
			if valid_forced_uuid(value.str()) { return Lookup[json2.Any]{
					value: value
				} }
		}
		if options.supports_uuids { return Lookup[json2.Any]{} }
		if value !is string { return Lookup[json2.Any]{
				value: json2.Any(generate_uuid()!)
			} }
		return Lookup[json2.Any]{}
	}
	return Lookup[json2.Any]{
		value: value
	}
}

pub fn id_field_output(value json2.Any) Lookup[string] {
	if !js_truthy(value) { return Lookup[string]{} }
	return Lookup[string]{
		value: value.str()
	}
}

pub struct DeterministicIDResult {
pub:
	value    string
	warnings []string
}

pub fn (mut state IDFieldState) deterministic_id(digest []u8, strategy string) !DeterministicIDResult {
	mut warnings := []string{}
	if strategy == 'serial' && !state.warned_serial {
		state.warned_serial = true
		warnings << 'Single-use checks need string ids and are not enforced with advanced.database.generateId: "serial".'
	}
	return DeterministicIDResult{
		value:    encode_deterministic_id(digest, strategy)!
		warnings: warnings
	}
}
