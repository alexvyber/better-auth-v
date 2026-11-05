module better_auth

import x.json2

pub fn (mut storage MemoryStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
}

pub fn (mut storage MemoryStorage) organization_rows(model string, filter map[string]string) ![]string {
	storage.check_open()!
	organization_model(model)!
	mut result := []string{}
	for key, encoded in storage.records.organizations {
		if key.starts_with(model + '|')
			&& organization_row_matches(org_json_fields(encoded)!, filter) {
			result << encoded
		}
	}
	return result
}

fn (mut storage MemoryStorage) check_organization_write(model string, encoded string, creating bool) !string {
	storage.check_write()!
	organization_model(model)!
	fields := org_json_fields(encoded)!
	id := (fields['id'] or { return error('organization record requires id') }).str()
	if creating && model + '|' + id in storage.records.organizations {
		return error('duplicate organization record id')
	}
	if model != 'organization' {
		org_id := (fields['organizationId'] or {
			return error('organization reference is required')
		}).str()
		if (storage.organization_rows('organization', {
			'id': org_id
		})!).len == 0 {
			return error('organization does not exist')
		}
	}
	if model == 'member' || model == 'invitation' {
		field := if model == 'member' { 'userId' } else { 'inviterId' }
		if (storage.user((fields[field] or { json2.Any('') }).str())!).value == none {
			return error('organization user does not exist')
		}
	}
	for other in storage.organization_rows(model, {})! {
		row := org_json_fields(other)!
		if (row['id'] or { json2.Any('') }).str() == id { continue
		 }
		if model == 'organization' && (row['slug'] or { json2.Any('') }).str() == (fields['slug'] or {
			json2.Any('')
		}).str() {
			return error('duplicate organization slug')
		}
		if model in ['member', 'organizationRole'] && (row['organizationId'] or { json2.Any('') }).str() == (fields['organizationId'] or {
			json2.Any('')
		}).str() {
			field := if model == 'member' { 'userId' } else { 'role' }
			if (row[field] or { json2.Any('') }).str() == (fields[field] or { json2.Any('') }).str() {
				return error('duplicate organization association')
			}
		}
		for field, definition in storage.model_fields[model] or {
			map[string]AdditionalField{}
		} {
			if !definition.unique { continue
			 }
			value := fields[field] or { continue }
			if value is json2.Null { continue
			 }
			if previous := row[field] {
				if previous.json_str() == value.json_str() {
					return error('duplicate unique organization field')
				}
			}
		}
	}
	return id
}

pub fn (mut storage MemoryStorage) organization_create(model string, encoded string) ! {
	id := storage.check_organization_write(model, encoded, true)!
	storage.records.organizations[model + '|' + id] = encoded
}

pub fn (mut storage MemoryStorage) organization_update(model string, encoded string) ! {
	id := storage.check_organization_write(model, encoded, false)!
	if model + '|' + id in storage.records.organizations {
		storage.records.organizations[model + '|' + id] = encoded
	}
}

pub fn (mut storage MemoryStorage) organization_delete(model string, id string) ! {
	storage.check_write()!
	organization_model(model)!
	if model == 'organization' {
		for child in ['member', 'invitation', 'organizationRole'] {
			for row in storage.organization_rows(child, {
				'organizationId': id
			})! {
				fields := org_json_fields(row)!
				storage.records.organizations.delete(child + '|' + (fields['id'] or {
					json2.Any('')
				}).str())
			}
		}
	}
	storage.records.organizations.delete(model + '|' + id)
}

pub fn (mut storage MemoryStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	storage.check_write()!
	key := 'invitation|' + id
	encoded := storage.records.organizations[key] or { return false }
	mut row := org_json_fields(encoded)!
	if (row['status'] or { json2.Any('') }).str() != from_status { return false }
	row['status'] = status
	storage.records.organizations[key] = json2.Any(row).json_str()
	return true
}
