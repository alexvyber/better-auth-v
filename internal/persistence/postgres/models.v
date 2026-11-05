module better_auth

import better_auth.schema as model_schema

pub fn (mut s PostgresStorage) configure_adapter_models(models map[string]AdapterModel) ! {
	validate_adapter_models(models)!
	s.adapter_models = models.clone()
	mut names := map[string]bool{}
	mut all := model_schema.core_models()
	all << models.keys()
	for model in all {
		name := s.table(model)
		if name in names { return error('adapter table mapping collides with an existing model') }
		names[name] = true
	}
}

pub fn (mut s PostgresStorage) adapter_model_rows(model string) ![]string {
	require_adapter_model(s.adapter_models, model)!
	return s.select_rows(model, '', [])
}

pub fn (mut s PostgresStorage) adapter_model_write(model string, encoded string, creating bool) ! {
	require_adapter_model(s.adapter_models, model)!
	if creating {
		s.create_row(model, encoded)!
	} else {
		s.update_row(model, encoded)!
	}
}

pub fn (mut s PostgresStorage) adapter_model_delete(model string, id string) ! {
	require_adapter_model(s.adapter_models, model)!
	s.delete_row(model, id)!
}
