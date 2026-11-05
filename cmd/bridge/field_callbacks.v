module main

import better_auth
import json
import x.json2

fn otp_callback(method string, data string, mut context better_auth.EndpointContext) !string {
	request := context.request_context()
	encoded_request := if value := request.request { json.encode(value) } else { 'null' }
	session := if value := context.session {
		'{"session":${better_auth.encode_session(value.session)},"user":${better_auth.encode_user(value.user)}}'
	} else {
		'null'
	}
	return callback_with_context(method,
		'{"data":${data},"request":${encoded_request},"headers":${json.encode(request.headers)},"session":${session}}', mut
		context)
}

fn field_schema(encoded string, model string, callbacks []string) !map[string]better_auth.AdditionalField {
	mut fields := json2.decode[map[string]better_auth.AdditionalField](encoded)!
	for name, field in fields.clone() {
		mut configured := field
		validation := 'field.' + model + '.' + name + '.validate'
		transformation := 'field.' + model + '.' + name + '.transform'
		factory := 'field.' + model + '.' + name + '.default'
		if factory in callbacks { configured = better_auth.AdditionalField{
				...configured
				default_factory: fn [factory] () !better_auth.FieldInputResult {
					return json2.decode[better_auth.FieldInputResult](callback_rpc(factory, 'null')!)!}
			} }
		if validation in callbacks { configured = better_auth.AdditionalField{
				...configured
				validate_input: fn [validation] (value json2.Any) !better_auth.FieldInputResult {
					return json2.decode[better_auth.FieldInputResult](callback_rpc(validation, value.json_str())!)}
			} }
		if transformation in callbacks { configured = better_auth.AdditionalField{
				...configured
				transform_input: fn [transformation] (value json2.Any) !better_auth.FieldInputResult {
					return json2.decode[better_auth.FieldInputResult](callback_rpc(transformation, value.json_str())!)}
			} }
		fields[name] = configured
	}
	return fields
}
