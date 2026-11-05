module better_auth

fn (mut a Auth) try_sync_oauth_profile(user User, identity OAuthIdentity) !User {
	mut storage := a.storage
	if mut storage is ProfileSyncStorage {
		storage.start_profile_sync()!
		tasks := a.operation.attempt.transaction.pending_tasks.len
		updated := a.sync_oauth_profile(user, identity) or {
			storage.finish_profile_sync(false)!
			a.operation.attempt.transaction.pending_tasks = a.operation.attempt.transaction.pending_tasks[..tasks].clone()
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
