module better_auth

import x.json2

struct AdapterRelation {
	base_field   string
	target_field string
	single       bool
}

fn (c &EndpointContext) adapter_relation(model string, target string) !AdapterRelation {
	c.adapter_field(target, 'id')!
	mut relations := []AdapterRelation{}
	if model == 'user' && target in ['session', 'account'] { relations << AdapterRelation{
			base_field:   'id'
			target_field: 'userId'
		} }
	if target == 'user' && model in ['session', 'account'] { relations << AdapterRelation{
			base_field:   'userId'
			target_field: 'id'
			single:       true
		} }
	for child, references in {
		'member':           {
			'userId':         'user'
			'organizationId': 'organization'
		}
		'invitation':       {
			'inviterId':      'user'
			'organizationId': 'organization'
		}
		'organizationRole': {
			'organizationId': 'organization'
		}
	} {
		for field, parent in references {
			if model == parent && target == child { relations << AdapterRelation{
					base_field:   'id'
					target_field: field
				} }
			if model == child && target == parent { relations << AdapterRelation{
					base_field:   field
					target_field: 'id'
					single:       true
				} }
		}
	}
	for field, definition in (c.auth.config.adapter_models[model] or { AdapterModel{} }).fields {
		if reference := definition.references {
			if reference.model == target { relations << AdapterRelation{
					base_field:   field
					target_field: reference.field
					single:       true
				} }
		}
	}
	for field, definition in (c.auth.config.adapter_models[target] or { AdapterModel{} }).fields {
		if reference := definition.references {
			if reference.model == model { relations << AdapterRelation{
					base_field:   reference.field
					target_field: field
					single:       definition.unique
				} }
		}
	}
	if relations.len != 1 { return error('unknown or ambiguous adapter relation') }
	return relations[0]
}

fn (mut c EndpointContext) adapter_validate_model(model string, row map[string]json2.Any) ! {
	definition := c.auth.config.adapter_models[model] or { return error('unknown adapter model') }
	for field, attribute in definition.fields {
		value := row[field] or { json2.Any(json2.Null{}) }
		if value is json2.Null {
			if attribute.required { return error('required adapter field: ' + field) }
			continue
		}
		validate_field(attribute, value)!
		if reference := attribute.references {
			mut found := false
			for other in c.adapter_rows(reference.model)! {
				if key := other.as_map()[reference.field] {
					if adapter_equal(key, value, false) {
						found = true
						break
					}
				}
			}
			if !found { return error('adapter reference does not exist') }
		}
	}
}
