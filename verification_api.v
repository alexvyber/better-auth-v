module better_auth

import crypto.sha256
import json
import x.json2

pub struct VerificationOptions {
pub:
	store_in_database bool   @[json: storeInDatabase]
	disable_cleanup   bool   @[json: disableCleanup]
	store_identifier  string = 'plain' @[json: storeIdentifier]
	overrides         map[string]string
	hash_identifier   fn (string) !string = no_verification_identifier_hasher @[skip]
}

fn no_verification_identifier_hasher(_ string) !string {
	return error('custom verification identifier hashing is not configured')
}

pub fn encode_verification(value Verification) string {
	return '{"id":${json.encode(value.id)},"identifier":${json.encode(value.identifier)},"value":${json.encode(value.value)},"expiresAt":${json.encode(stamp_millis(verification_expiry_millis(value)))},"createdAt":${json.encode(value.created_at)},"updatedAt":${json.encode(value.updated_at)}}'
}

fn decode_verification_record(encoded string) !Verification {
	fields := json2.decode[map[string]json2.Any](encoded)!
	expires :=
		epoch_millis((fields['expiresAt'] or { return error('expiresAt is required') }).str())!
	return Verification{
		id:                (fields['id'] or { json2.Any('') }).str()
		identifier:        (fields['identifier'] or { return error('identifier is required') }).str()
		value:             (fields['value'] or { return error('value is required') }).str()
		created_at:        (fields['createdAt'] or { json2.Any('') }).str()
		updated_at:        (fields['updatedAt'] or { json2.Any('') }).str()
		expires_at:        expires / 1000
		expires_at_millis: expires
	}
}

fn (a &Auth) verification_identifiers(identifier string) ![]string {
	mut mode := a.config.verification.store_identifier
	for prefix, override in a.config.verification.overrides {
		if identifier.starts_with(prefix) {
			mode = override
			break
		}
	}
	if mode == 'plain' { return [identifier] }
	if mode !in ['hashed', 'custom'] { return error('unsupported verification identifier storage') }
	stored := if mode == 'custom' {
		a.config.verification.hash_identifier(identifier)!
	} else {
		default_one_time_token_hasher(identifier)!
	}
	return [stored, identifier]
}

pub fn (mut context EndpointContext) create_verification_value(input Verification) !Verification {
	identifiers := context.auth.verification_identifiers(input.identifier)!
	value := Verification{
		...input
		identifier: identifiers[0]
		id:         if input.id == '' { random_token()! } else { input.id }
		created_at: if input.created_at == '' {
			stamp_millis(context.auth.clock_millis())
		} else {
			input.created_at
		}
		updated_at: if input.updated_at == '' {
			stamp_millis(context.auth.clock_millis())
		} else {
			input.updated_at
		}
	}
	encoded := (context.auth.before_record('verification', 'create', encode_verification(value))!).value or {
		return fail(400, 'FAILED_TO_CREATE_VERIFICATION', 'Unable to create verification')
	}

	actual := decode_verification_record(encoded)!
	if !context.auth.has_secondary() || context.auth.config.verification.store_in_database {
		context.auth.storage.create_verification(actual)!
	}
	if context.auth.has_secondary() {
		ttl := (verification_expiry_millis(actual) - context.auth.clock_millis()) / 1000
		if ttl > 0 {
			context.auth.secondary.set('verification:' + identifiers[0],
				encode_verification(actual), ttl)!
		}
	}
	context.auth.after_record('verification', 'create', encode_verification(actual))!
	return actual
}

fn (mut context EndpointContext) latest_verification(identifiers []string) !Lookup[Verification] {
	for identifier in identifiers {
		mut latest := ?Verification(none)
		for value in context.auth.storage.verifications()! {
			if value.identifier != identifier { continue
			 }
			if previous := latest {
				if value.created_at <= previous.created_at { continue
				 }
			}
			latest = value
		}
		if value := latest { return Lookup[Verification]{
				value: value
			} }
	}
	return Lookup[Verification]{}
}

pub fn (mut context EndpointContext) find_verification_value(identifier string) !Lookup[Verification] {
	identifiers := context.auth.verification_identifiers(identifier)!
	if context.auth.has_secondary() {
		for candidate in identifiers {
			if encoded := (context.auth.secondary.get('verification:' + candidate)!).value {
				if record := decode_verification_record(encoded) { return Lookup[Verification]{
						value: record
					} }
			}
		}
		if !context.auth.config.verification.store_in_database { return Lookup[Verification]{} }
	}
	result := context.latest_verification(identifiers)!
	// Upstream returns the captured row once, then cleans all expired DB rows.
	if !context.auth.config.verification.disable_cleanup {
		for record in context.auth.storage.verifications()! {
			if verification_expiry_millis(record) < context.auth.clock_millis() {
				context.auth.remove_verification(record.id)!
			}
		}
	}
	return result
}

pub fn (mut context EndpointContext) consume_verification_value(identifier string) !Lookup[Verification] {
	identifiers := context.auth.verification_identifiers(identifier)!
	mut consumed := ?Verification(none)
	if context.auth.has_secondary() && !context.auth.config.verification.store_in_database {
		for candidate in identifiers {
			encoded := (context.auth.secondary.get_and_delete('verification:' + candidate)!).value or {
				continue
			}

			record := decode_verification_record(encoded) or { continue }
			consumed = record
			for other in identifiers {
				if other != candidate { context.auth.secondary.delete('verification:' + other)! }
			}
			break
		}
	} else {
		if latest := (context.latest_verification(identifiers)!).value {
			if (context.auth.before_record('verification', 'delete', encode_verification(latest))!).value == none {
				return Lookup[Verification]{}
			}
			for record in context.auth.storage.verifications()! {
				if record.identifier == latest.identifier {
					context.auth.storage.delete_verification(record.id)!
				}
			}
			context.auth.after_record('verification', 'delete', encode_verification(latest))!
			consumed = latest
			if context.auth.has_secondary() {
				for candidate in identifiers {
					context.auth.secondary.delete('verification:' + candidate)!
				}
			}
		}
	}
	if record := consumed {
		if verification_expiry_millis(record) >= context.auth.clock_millis() { return Lookup[Verification]{
				value: record
			} }
	}
	return Lookup[Verification]{}
}

fn (mut context EndpointContext) verification_internal(name string, args []json2.Any) !string {
	if name == 'updateVerificationByIdentifier' {
		if args.len != 2 {
			return error('updateVerificationByIdentifier requires an identifier and patch')
		}
		result := context.update_verification_by_identifier(args[0].str(), args[1].json_str())!
		return if value := result.value { encode_verification(value) } else { 'null' }
	}
	if args.len != 1 { return error('${name} requires one argument') }
	if name == 'deleteVerificationByIdentifier' {
		context.delete_verification_by_identifier(args[0].str())!
		return 'null'
	}
	if name == 'reserveVerificationValue' {
		return json.encode(context.reserve_verification_value(decode_verification_record(args[0].json_str())!)!)
	}
	if name == 'createVerificationValue' {
		value := context.create_verification_value(decode_verification_record(args[0].json_str())!)!
		return encode_verification(value)
	}
	result := if name == 'consumeVerificationValue' {
		context.consume_verification_value(args[0].str())!
	} else {
		context.find_verification_value(args[0].str())!
	}
	return if value := result.value { encode_verification(value) } else { 'null' }
}

pub fn (mut context EndpointContext) delete_verification_by_identifier(identifier string) ! {
	identifiers := context.auth.verification_identifiers(identifier)!
	if context.auth.has_secondary() {
		context.auth.secondary.delete('verification:' + identifiers[0])!
	}
	if !context.auth.has_secondary() || context.auth.config.verification.store_in_database {
		if record := (context.latest_verification([identifiers[0]])!).value {
			if (context.auth.before_record('verification', 'delete', encode_verification(record))!).value == none {
				return
			}
			for stale in context.auth.storage.verifications()! {
				if stale.identifier == record.identifier {
					context.auth.storage.delete_verification(stale.id)!
				}
			}
			context.auth.after_record('verification', 'delete', encode_verification(record))!
		}
	}
}

pub fn (mut context EndpointContext) update_verification_by_identifier(identifier string, patch_json string) !Lookup[Verification] {
	original := (context.find_verification_value(identifier)!).value or {
		return Lookup[Verification]{}
	}

	patch := (context.auth.before_record('verification', 'update', patch_json)!).value or {
		return Lookup[Verification]{}
	}

	merged := merge_record_json(encode_verification(original), patch)!
	updated := decode_verification_record(merged)!
	if !context.auth.has_secondary() || context.auth.config.verification.store_in_database {
		context.auth.storage.delete_verification(original.id)!
		context.auth.storage.create_verification(updated)!
	}
	if context.auth.has_secondary() {
		identifiers := context.auth.verification_identifiers(identifier)!
		ttl := (verification_expiry_millis(updated) - context.auth.clock_millis()) / 1000
		if ttl > 0 {
			context.auth.secondary.set('verification:' + identifiers[0],
				encode_verification(updated), ttl)!
		}
	}
	context.auth.after_record('verification', 'update', encode_verification(updated))!
	return Lookup[Verification]{
		value: updated
	}
}

// Call inside with_internal or a native endpoint transaction. The primary key is
// the cross-connection first-writer-wins gate; hooks cannot replace that key.
pub fn (mut context EndpointContext) reserve_verification_value(input Verification) !bool {
	if context.auth.has_secondary() && !context.auth.config.verification.store_in_database {
		return error('reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.')
	}
	identifiers := context.auth.verification_identifiers(input.identifier)!
	id := base64url(sha256.sum(('reserve:' + input.identifier).bytes()))
	now := stamp_millis(context.auth.clock_millis())
	value := Verification{
		...input
		id:         id
		identifier: identifiers[0]
		created_at: now
		updated_at: now
	}
	context.auth.storage.create_verification(value) or {
		if (context.auth.storage.verification(id)!).value != none { return false }
		return err
	}
	if context.auth.has_secondary() {
		ttl := (verification_expiry_millis(value) - context.auth.clock_millis()) / 1000
		if ttl > 0 {
			context.auth.secondary.set('verification:' + identifiers[0],
				encode_verification(value), ttl)!
		}
	}
	return true
}
