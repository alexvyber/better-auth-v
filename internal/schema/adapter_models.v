module better_auth

import better_auth.schema as model_schema

pub struct AdapterReference {
pub:
	model string
	field string = 'id'
}

pub struct AdapterModel {
pub:
	name   string @[json: modelName]
	fields map[string]AdditionalField
}

fn validate_adapter_models(models map[string]AdapterModel) ! {
	mut names := map[string]bool{}
	for model, definition in models {
		name := if definition.name == '' { model } else { definition.name }
		if model == '' || model_schema.is_core_model(model)
			|| model in ['__proto__', 'constructor', 'prototype'] || model.contains('\x00')
			|| model.contains('|') || name == '' || name.contains('\x00')
			|| name.to_lower() in names || model_schema.is_core_model(name) {
			return error('invalid or colliding adapter model name')
		}
		names[name.to_lower()] = true
		mut columns := {
			'id':  true
			'_id': true
		}
		for field, attribute in definition.fields {
			column := if attribute.field_name == '' { field } else { attribute.field_name }
			if field == '' || field in ['id', '__proto__', 'constructor', 'prototype']
				|| field.contains('\x00') || column == '' || column.contains('\x00')
				|| column in columns {
				return error('invalid or colliding adapter field')
			}
			columns[column] = true
			if attribute.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
				'number[]'] {
				return error('unsupported adapter field type')
			}
			if reference := attribute.references {
				if !model_schema.is_core_model(reference.model) && reference.model !in models {
					return error('unknown adapter reference model')
				}
				if reference.field != 'id' && reference.field !in model_schema.core_fields(reference.model) && reference.field !in (models[reference.model] or {
					AdapterModel{}
				}).fields {
					return error('unknown adapter reference field')
				}
			}
		}
	}
}

fn require_adapter_model(models map[string]AdapterModel, model string) ! {
	if model !in models { return error('unknown adapter model') }
}
