module better_auth

pub fn (mut storage MemoryStorage) configure_fields(users map[string]AdditionalField, sessions map[string]AdditionalField) ! {
	storage.user_fields = users.clone()
	storage.session_fields = sessions.clone()
}

fn (storage &MemoryStorage) unique_user_fields(user User) ! {
	for name, field in storage.user_fields {
		if !field.unique { continue
		 }
		value := user.additional_fields[name] or { continue }
		for _, existing in storage.records.users {
			if existing.id == user.id { continue
			 }
			if other := existing.additional_fields[name] {
				if unique_field_equal(field, value, other) {
					return error('duplicate unique user field')
				}
			}
		}
	}
}

fn (storage &MemoryStorage) unique_session_fields(session Session) ! {
	for name, field in storage.session_fields {
		if !field.unique { continue
		 }
		value := session.additional_fields[name] or { continue }
		for _, existing in storage.records.sessions {
			if existing.id == session.id { continue
			 }
			if other := existing.additional_fields[name] {
				if unique_field_equal(field, value, other) {
					return error('duplicate unique session field')
				}
			}
		}
	}
}
