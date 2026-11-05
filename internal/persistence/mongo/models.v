module better_auth

import better_auth.schema as model_schema

pub fn (mut s MongoStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	validate_mongo_adapter_columns(models)!
	s.adapter_models = models.clone()
	mut names := map[string]bool{}
	mut all := model_schema.core_models()
	all << models.keys()
	for model in all {
		name := s.collection(model)
		if name in names {
			return error('adapter collection mapping collides with an existing model')
		}
		names[name] = true
	}
}

fn validate_mongo_adapter_columns(models map[string]AdapterModel) ! {
	for _, definition in models {
		for field, attribute in definition.fields {
			column := if attribute.field_name == '' { field } else { attribute.field_name }
			if column.starts_with('$') || column.contains('.') {
				return error('MongoDB adapter fields require literal column names without dots or a leading dollar sign')
			}
		}
	}
}

fn (storage &MongoStorage) identifier_field(model string, field string) bool {
	if reference := (storage.additional(model)[field] or { AdditionalField{} }).references {
		return reference.field == 'id'
	}
	return field == 'id'
		|| (model_schema.is_core_model(model) && field in ['userId', 'organizationId', 'inviterId'])
}

pub fn (mut s MongoStorage) adapter_model_rows(model string) ![]string {
	require_adapter_model(s.adapter_models, model)!
	return s.select_rows(model, {})
}

pub fn (mut s MongoStorage) adapter_model_write(model string, encoded string, creating bool) ! {
	require_adapter_model(s.adapter_models, model)!
	if creating {
		s.create_row(model, encoded)!
	} else {
		s.update_row(model, encoded)!
	}
}

pub fn (mut s MongoStorage) adapter_model_delete(model string, id string) ! {
	require_adapter_model(s.adapter_models, model)!
	s.delete_row(model, id)!
}
