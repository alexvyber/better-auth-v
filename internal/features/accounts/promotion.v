module better_auth

import json
import time

// The reservation primary key and the enclosing database transaction coordinate
// promotion across connections. Re-read under the gate before removing access.
fn (mut context EndpointContext) revoke_unproven_account_access(user_id string) !Lookup[User] {
	identifier := 'revoke-unproven-account-access:' + user_id
	expires := context.auth.clock_millis() + 5000
	acquired := context.reserve_verification_value(Verification{
		identifier:        identifier
		value:             user_id
		expires_at:        expires / 1000
		expires_at_millis: expires
	}) or {
		if context.auth.has_secondary() && !context.auth.config.verification.store_in_database {
			true
		} else {
			return err
		}
	}
	if !acquired {
		deadline := time.sys_mono_now() + 2 * time.second
		for time.sys_mono_now() < deadline {
			reservation := (context.find_verification_value(identifier)!).value or { break }
			if verification_expiry_millis(reservation) <= context.auth.clock_millis() {
				context.delete_verification_by_identifier(identifier)!
				break
			}
			// Release the transaction before polling so another connection can finish.
			context.auth.commit_transaction()!
			time.sleep(250 * time.millisecond)
			context.auth.begin_transaction(false)!
		}
		return context.auth.storage.user(user_id)
	}
	defer { context.delete_verification_by_identifier(identifier) or {} }
	user := (context.auth.storage.user(user_id)!).value or { return Lookup[User]{} }
	if user.email_verified { return Lookup[User]{
			value: user
		} }
	for account in context.auth.storage.accounts(user_id)! {
		if (context.auth.before_record('account', 'delete', json.encode(account))!).value != none {
			context.auth.storage.delete_account(account.id)!
			context.auth.after_record('account', 'delete', json.encode(account))!
		}
	}
	context.auth.remove_user_sessions(user_id, '')!
	updated := context.auth.update_user_record(User{
		...user
		email_verified: true
		updated_at:     stamp_millis(context.auth.clock_millis())
	})!
	return Lookup[User]{
		value: updated
	}
}
