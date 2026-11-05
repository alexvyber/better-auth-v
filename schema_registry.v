module better_auth

import better_auth.schema as model_schema

// Compiled once per Auth. It owns logical fields and relation topology; storage
// adapters remain responsible for physical aliases, indexes and serialization.
struct ModelRegistry {
	fields     map[string][]string
	references []model_schema.Reference
}

fn compile_model_registry(config Config) !ModelRegistry {
	validate_organization_fields(config.model_fields)!
	validate_adapter_models(config.adapter_models)!
	mut fields := map[string][]string{}
	for model in model_schema.core_models() {
		fields[model] = model_schema.core_fields(model)
	}
	for model, additional in config.model_fields {
		fields[model] << additional.keys()
	}
	fields['user'] << config.user_fields.keys()
	fields['session'] << config.session_fields.keys()
	mut references := model_schema.core_references()
	for model, definition in config.adapter_models {
		mut names := ['id']
		names << definition.fields.keys()
		fields[model] = names
		for field, attribute in definition.fields {
			if reference := attribute.references { references << model_schema.Reference{
					source_model: model
					source_field: field
					target_model: reference.model
					target_field: reference.field
					unique:       attribute.unique
				} }
		}
	}
	return ModelRegistry{
		fields:     fields
		references: references
	}
}

fn (registry &ModelRegistry) require_field(model string, field string) ! {
	if names := registry.fields[model] {
		if field in names { return }
		return error('unknown adapter field: ${field}')
	}
	return error('unsupported adapter model')
}

fn (registry &ModelRegistry) relation(model string, target string) !AdapterRelation {
	mut relations := []AdapterRelation{}
	for reference in registry.references {
		if reference.source_model == model && reference.target_model == target { relations << AdapterRelation{
				base_field:   reference.source_field
				target_field: reference.target_field
				single:       true
			} }
		if reference.target_model == model && reference.source_model == target { relations << AdapterRelation{
				base_field:   reference.target_field
				target_field: reference.source_field
				single:       reference.unique
			} }
	}
	if relations.len != 1 { return error('unknown or ambiguous adapter relation') }
	return relations[0]
}
