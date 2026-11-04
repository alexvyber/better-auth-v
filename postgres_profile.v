module better_auth

pub interface ProfileSyncStorage {
mut:
	start_profile_sync() !
	finish_profile_sync(success bool) !
}

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

fn (mut a Auth) try_sync_oauth_profile(user User, identity OAuthIdentity) !User {
	mut storage := a.storage
	if mut storage is ProfileSyncStorage {
		storage.start_profile_sync()!
		tasks := a.pending_tasks.len
		updated := a.sync_oauth_profile(user, identity) or {
			storage.finish_profile_sync(false)!
			a.pending_tasks = a.pending_tasks[..tasks].clone()
			a.config.log('warn', 'Could not update user info on account link')
			return user
		}
		storage.finish_profile_sync(true)!
		return updated
	}
	return a.sync_oauth_profile(user, identity) or {
		a.config.log('warn', 'Could not update user info on account link')
		user
	}
}
