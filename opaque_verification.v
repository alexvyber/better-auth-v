module better_auth

fn opaque_verification_identifier(token string, kind string) string {
	return if kind.starts_with('delete-account-') { kind } else { kind + ':' + token }
}

fn (mut a Auth) persist_opaque_verification(token string, input Verification) ! {
	mut context := EndpointContext{
		auth: a
	}
	context.create_verification_value(Verification{
		...input
		id:         ''
		identifier: opaque_verification_identifier(token, input.identifier)
	})!
}

fn (mut a Auth) find_opaque_verification(token string, kind string) !Lookup[Verification] {
	mut context := EndpointContext{
		auth: a
	}
	if record := (context.find_verification_value(opaque_verification_identifier(token, kind))!).value {
		return Lookup[Verification]{
			value: Verification{
				...record
				identifier: kind
			}
		}
	}
	// Native records predating the verification API used the lookup digest as ID.
	if legacy := (a.storage.verification(digest(token))!).value {
		if legacy.identifier == kind { return Lookup[Verification]{
				value: legacy
			} }
	}
	return Lookup[Verification]{}
}

fn (mut a Auth) consume_opaque_verification(token string, kind string) !Lookup[Verification] {
	mut context := EndpointContext{
		auth: a
	}
	if record := (context.consume_verification_value(opaque_verification_identifier(token, kind))!).value {
		return Lookup[Verification]{
			value: Verification{
				...record
				identifier: kind
			}
		}
	}
	if legacy := (a.storage.verification(digest(token))!).value {
		if legacy.identifier == kind {
			a.remove_verification(legacy.id)!
			return Lookup[Verification]{
				value: legacy
			}
		}
	}
	return Lookup[Verification]{}
}
