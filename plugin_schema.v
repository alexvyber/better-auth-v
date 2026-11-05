module better_auth

import x.json2

// Schema contributions are independently useful before the complete admin and
// organization endpoint sets are implemented. These types advertise that scope.
pub struct AdminSchemaPlugin {
pub:
	default_role string = 'user'
}

pub fn (_ AdminSchemaPlugin) id() string {
	return 'admin'
}

pub fn (_ AdminSchemaPlugin) endpoints() []Endpoint {
	return []Endpoint{}
}

pub fn (_ AdminSchemaPlugin) schema() PluginFields {
	return PluginFields{
		user:    {
			'role':       AdditionalField{
				field_type: 'string'
				input:      false
			}
			'banned':     AdditionalField{
				field_type:    'boolean'
				input:         false
				default_value: json2.Any(false)
			}
			'banReason':  AdditionalField{
				field_type: 'string'
				input:      false
			}
			'banExpires': AdditionalField{
				field_type: 'date'
				input:      false
			}
		}
		session: {
			'impersonatedBy': AdditionalField{
				field_type: 'string'
				input:      false
			}
		}
	}
}

pub fn (p AdminSchemaPlugin) prepare_user(user User) !User {
	mut fields := user.additional_fields.clone()
	if 'role' !in fields { fields['role'] = p.default_role }
	if 'banned' !in fields { fields['banned'] = false }
	if 'banReason' !in fields { fields['banReason'] = json2.Null{} }
	if 'banExpires' !in fields { fields['banExpires'] = json2.Null{} }
	return User{
		...user
		additional_fields: fields
	}
}

pub struct OrganizationSchemaPlugin {
pub:
	teams_enabled bool
}

pub fn (_ OrganizationSchemaPlugin) id() string {
	return 'organization'
}

pub fn (_ OrganizationSchemaPlugin) endpoints() []Endpoint {
	return []Endpoint{}
}

pub fn (p OrganizationSchemaPlugin) schema() PluginFields {
	mut fields := {
		'activeOrganizationId': AdditionalField{
			field_type: 'string'
			input:      false
		}
	}
	if p.teams_enabled { fields['activeTeamId'] = AdditionalField{
			field_type: 'string'
			input:      false
		} }
	return PluginFields{
		session: fields
	}
}

fn resolve_plugin_fields(config Config) Config {
	mut models := config.model_fields.clone()
	mut users := config.user_fields.clone()
	mut sessions := config.session_fields.clone()
	for plugin in config.plugins {
		if plugin is SchemaPlugin {
			fields := plugin.schema()
			for model, schema in fields.models {
				mut merged := (models[model] or {
					map[string]AdditionalField{}
				}).clone()
				for key, definition in schema {
					merged[key] = definition
				}
				models[model] = merged.clone()
			}
			for key, field in fields.user {
				users[key] = field
			}
			for key, field in fields.session {
				sessions[key] = field
			}
		}
	}
	return Config{
		...config
		model_fields:   models
		user_fields:    users
		session_fields: sessions
	}
}

fn (a &Auth) synthetic_user(user User) !User {
	mut proposed := user
	if a.config.custom_synthetic_user != default_synthetic_user {
		mut additional := map[string]json2.Any{}
		for key in a.user_defined_fields {
			if value := user.additional_fields[key] { additional[key] = value }
		}
		proposed = a.config.custom_synthetic_user(SyntheticUserInput{
			core_fields:       User{
				...user
				id:                ''
				additional_fields: map[string]json2.Any{}
			}
			additional_fields: additional
			id:                user.id
		})!
	}
	mut fields := map[string]json2.Any{}
	for key, field in a.config.user_fields {
		if value := proposed.additional_fields[key] {
			fields[key] = value
		} else if value := field.default_value {
			fields[key] = value
		} else if !field.required {
			fields[key] = json2.Null{}
		}
	}
	return User{
		...proposed
		additional_fields: fields
	}
}
