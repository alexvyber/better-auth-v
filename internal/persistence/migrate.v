module better_auth

pub fn (mut a Auth) migrate_storage() ! {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed || a.operation.attempt.transaction.active {
		return error('cannot migrate active or closed auth storage')
	}
	mut storage := a.storage
	if mut storage is MigratingStorage { storage.migrate()! }
}
