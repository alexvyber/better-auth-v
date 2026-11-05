module better_auth

fn (mut context EndpointContext) organization_lock_mutations() ! {
	if !context.auth.transactions_enabled { return }
	mut storage := context.auth.storage
	if mut storage is OrganizationLockingStorage { storage.lock_organization_mutations()! }
}
