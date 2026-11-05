module better_auth

import x.json2

struct AdapterRelation {
	base_field   string
	target_field string
	single       bool
}

fn (c &EndpointContext) adapter_relation(model string, target string) !AdapterRelation {
	c.adapter_field(target, 'id')!
	return c.auth.models.relation(model, target)
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
