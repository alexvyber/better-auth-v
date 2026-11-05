module better_auth

pub fn (mut storage PostgresStorage) configure_model_fields(fields map[string]map[string]AdditionalField) ! {
	validate_organization_fields(fields)!
	storage.model_fields = fields.clone()
	storage.configure_fields(storage.user_fields, storage.session_fields)!
}

pub fn (mut storage PostgresStorage) organization_rows(model string, filter map[string]string) ![]string {
	organization_model(model)!
	mut clauses := []string{}
	mut parameters := []string{}
	for field, value in filter {
		if field !in storage.logical_fields(model) {
			return error('unknown organization filter field')
		}
		if storage.sql_type(model, field)! == 'uuid' && !postgres_uuid_identifier(value) {
			return []string{}
		}
		parameters << value
		clauses << storage.column_sql(model, field) + '=$' + parameters.len.str()
	}
	where := if clauses.len > 0 { 'WHERE ' + clauses.join(' AND ') } else { '' }
	return storage.select_rows(model, where, parameters)
}

pub fn (mut storage PostgresStorage) organization_create(model string, encoded string) ! {
	organization_model(model)!
	storage.create_row(model, encoded)!
}

pub fn (mut storage PostgresStorage) organization_update(model string, encoded string) ! {
	organization_model(model)!
	storage.update_row(model, encoded)!
}

pub fn (mut storage PostgresStorage) organization_delete(model string, id string) ! {
	organization_model(model)!
	storage.delete_row(model, id)!
}

pub fn (mut storage PostgresStorage) organization_claim_invitation(id string, from_status string, status string) !bool {
	if storage.sql_type('invitation', 'id')! == 'uuid' && !postgres_uuid_identifier(id) {
		return false
	}
	rows := storage.connection.exec_param_many('UPDATE ${storage.table('invitation')} SET ${storage.column_sql('invitation',
		'status')}=$1 WHERE ${storage.column_sql('invitation', 'id')}=$2 AND ${storage.column_sql('invitation',
		'status')}=$3 RETURNING ${storage.column_sql('invitation', 'id')}',
		[status, id, from_status])!
	return rows.len == 1
}
