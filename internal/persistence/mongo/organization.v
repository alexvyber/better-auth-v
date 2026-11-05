module better_auth

import x.json2

pub fn (mut storage MongoStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
	storage.configure_fields(storage.user_fields, storage.session_fields)!
}

pub fn (mut storage MongoStorage) organization_rows(model string, filter map[string]string) ![]string {
	organization_model(model)!
	mut physical := map[string]BSONValue{}
	for field, value in filter {
		if field !in storage.logical_fields(model) {
			return error('unknown organization filter field')
		}
		physical[storage.column(model, field)] = if field in ['id', 'userId', 'organizationId',
			'inviterId'] {
			storage.id_value(value)!
		} else {
			BSONValue(value)
		}
	}
	return storage.select_rows(model, physical)
}

pub fn (mut storage MongoStorage) organization_create(model string, encoded string) ! {
	organization_model(model)!
	storage.create_row(model, encoded)!
}

pub fn (mut storage MongoStorage) organization_update(model string, encoded string) ! {
	organization_model(model)!
	storage.update_row(model, encoded)!
}

pub fn (mut storage MongoStorage) organization_delete(model string, id string) ! {
	organization_model(model)!
	if model == 'organization' {
		for child in ['member', 'invitation', 'organizationRole'] {
			storage.delete_rows(child, {
				storage.column(child, 'organizationId'): storage.id_value(id)!
			})!
		}
	}
	storage.delete_row(model, id)!
}

pub fn (mut storage MongoStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	reply := storage.command({
		'findAndModify': BSONValue(storage.collection('invitation'))
		'query':         BSONValue({
			storage.column('invitation', 'id'):     storage.id_value(id)!
			storage.column('invitation', 'status'): BSONValue(from_status)
		})
		'update':        BSONValue({
			'$set': BSONValue({
				storage.column('invitation', 'status'): BSONValue(status)
			})
		})
		'new':           BSONValue(true)
	}, 3)!
	value := reply['value'] or { return false }
	return value !is json2.Null
}
