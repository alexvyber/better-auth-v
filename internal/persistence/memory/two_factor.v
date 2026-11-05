module better_auth

pub fn (mut storage MemoryStorage) two_factors(user_id string) ![]TwoFactorRecord {
	storage.check_open()!
	return storage.records.two_factors.values().filter(user_id == '' || it.user_id == user_id)
}

pub fn (mut storage MemoryStorage) create_two_factor(record TwoFactorRecord) ! {
	storage.check_write()!
	if record.id in storage.records.two_factors { return error('duplicate two-factor id') }
	if (storage.user(record.user_id)!).value == none {
		return error('two-factor user does not exist')
	}
	storage.records.two_factors[record.id] = record
}

pub fn (mut storage MemoryStorage) update_two_factor(record TwoFactorRecord) ! {
	storage.check_write()!
	if record.id in storage.records.two_factors { storage.records.two_factors[record.id] = record }
}

pub fn (mut storage MemoryStorage) delete_two_factors(user_id string) ! {
	storage.check_write()!
	for record in storage.two_factors(user_id)! {
		storage.records.two_factors.delete(record.id)
	}
}
