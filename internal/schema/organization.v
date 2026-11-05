module better_auth

import better_auth.schema as model_schema

const organization_models = ['organization', 'member', 'invitation', 'organizationRole']

fn validate_organization_fields(fields map[string]map[string]AdditionalField) ! {
	for model, schema in fields {
		if model !in organization_models { return error('unsupported additional model schema') }
		for field, definition in schema {
			if field in model_schema.core_fields(model)
				|| field in ['__proto__', 'constructor', 'prototype'] || field == ''
				|| field.contains('\x00') {
				return error('additional model field collides with a reserved name')
			}
			if definition.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
				'number[]'] {
				return error('unsupported additional model field type')
			}
		}
	}
}

fn organization_model(model string) ! {
	if model !in organization_models { return error('unsupported organization model') }
}
