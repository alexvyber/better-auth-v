module better_auth

pub fn (mut storage PostgresStorage) start_profile_sync() ! {
	storage.profile_snapshots = storage.snapshots.clone()
	if storage.transaction { storage.connection.savepoint('better_auth_profile_sync')! }
}

pub fn (mut storage PostgresStorage) finish_profile_sync(success bool) ! {
	if storage.transaction {
		if !success {
			storage.connection.rollback_to('better_auth_profile_sync')!
			storage.snapshots = storage.profile_snapshots.clone()
		}
		storage.connection.release_savepoint('better_auth_profile_sync')!
	}
	storage.profile_snapshots.clear()
}
