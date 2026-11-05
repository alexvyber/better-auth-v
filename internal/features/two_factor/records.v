module better_auth

import json
import x.json2

pub struct TwoFactorRecord {
pub:
	id                        string
	user_id                   string @[json: userId]
	secret                    string
	backup_codes              string @[json: backupCodes]
	verified                  ?bool
	failed_verification_count int     @[json: failedVerificationCount]
	locked_until              ?string @[json: lockedUntil]
}

pub fn encode_two_factor(record TwoFactorRecord) string {
	mut fields := json2.decode[map[string]json2.Any](json.encode(record)) or { return '{}' }
	if record.verified == none { fields['verified'] = json2.Null{} }
	if record.locked_until == none { fields['lockedUntil'] = json2.Null{} }
	return json2.Any(fields).json_str()
}

pub fn (mut context EndpointContext) two_factors(user_id string) ![]TwoFactorRecord {
	mut storage := context.auth.storage
	if mut storage is TwoFactorStorage { return storage.two_factors(user_id) }
	return error('two-factor storage is not supported by this adapter')
}

fn (mut context EndpointContext) save_two_factor(record TwoFactorRecord, create bool) ! {
	mut storage := context.auth.storage
	if mut storage is TwoFactorStorage {
		if create {
			storage.create_two_factor(record)!
		} else {
			storage.update_two_factor(record)!
		}
		return
	}
	return error('two-factor storage is not supported by this adapter')
}

fn (mut context EndpointContext) delete_two_factors(user_id string) ! {
	mut storage := context.auth.storage
	if mut storage is TwoFactorStorage {
		storage.delete_two_factors(user_id)!
		return
	}
	return error('two-factor storage is not supported by this adapter')
}
