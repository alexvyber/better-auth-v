module better_auth

import x.json2

// Scoped persistence for organization models. This is not the general upstream
// adapter query language: filters are ANDed field equalities on a known schema.
pub interface OrganizationStorage {
mut:
	organization_rows(model string, filter map[string]string) ![]string
	organization_create(model string, encoded string) !
	organization_update(model string, encoded string) !
	organization_delete(model string, id string) !
	organization_claim_invitation(id string, from_status string, status string) !bool
}

pub interface ConfigurableModelStorage {
mut:
	configure_model_fields(fields map[string]map[string]AdditionalField) !
}

// Organization limits and last-owner/assigned-role rules span multiple rows.
// The initial portable barrier serializes mutations per physical organization
// store, including user-wide organization counts. Raw application writes must
// participate separately; this is a transaction barrier, not a distributed lease.
pub interface OrganizationLockingStorage {
mut:
	lock_organization_mutations() !
}

pub interface TwoFactorStorage {
mut:
	two_factors(user_id string) ![]TwoFactorRecord
	create_two_factor(record TwoFactorRecord) !
	update_two_factor(record TwoFactorRecord) !
	delete_two_factors(user_id string) !
}

pub interface AdapterModelStorage {
mut:
	configure_adapter_models(models map[string]AdapterModel) !
	adapter_model_rows(string) ![]string
	adapter_model_write(string, string, bool) !
	adapter_model_delete(string, string) !
}

// Native conditional writes, independent of ordinary adapter update semantics.
pub interface AtomicAdapterStorage {
mut:
	compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool
}

pub interface ProfileSyncStorage {
mut:
	start_profile_sync() !
	finish_profile_sync(success bool) !
}

pub interface MigratingStorage {
mut:
	migrate() !
}

pub interface ConfigurableStorage {
mut:
	configure_fields(user_fields map[string]AdditionalField, session_fields map[string]AdditionalField) !
}

pub interface UserUpdateReturningStorage {
mut:
	update_user_returning(user User) !User
}

pub interface PlainSessionTokenStorage {
	stores_plain_session_tokens() bool
}

pub interface AtomicVerificationStorage {
mut:
	take_verification(id string, identifier string) !Lookup[Verification]
}

pub interface ConfigurableIDStorage {
mut:
	configure_ids(strategy string, custom bool) !
}

pub interface StorageIDGenerator {
	generate_storage_id(model string) !string
}

pub interface TokenLookupStorage {
mut:
	session_by_token(token string) !Lookup[Session]
}

pub interface ManagedTransactionStorage {
mut:
	run_managed_transaction(operation fn () !string) !string
}

pub interface RateLimitDatabase {
mut:
	consume_rate_limit(input RateLimitInput) !RateLimitDecision
}
