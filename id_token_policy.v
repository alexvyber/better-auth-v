module better_auth

import x.json2

pub struct ProviderIDTokenPolicy {
pub:
	disabled           bool
	configured         bool
	allow_opaque_token bool
	config             IDTokenVerifyConfig
	override_verify    fn (string, string) !bool   = no_id_token_override   @[skip]
	custom_verify      fn (string, string) !bool   = no_id_token_override   @[skip]
	resolve_key        fn (string, string) !string = no_id_token_resolver @[skip]
	verify_claims      fn (string) !bool           = accept_id_token_claims           @[skip]
}

fn no_id_token_override(_ string, _ string) !bool {
	return false
}

fn no_id_token_resolver(_ string, _ string) !string {
	return error('ID token key resolver is not configured')
}

fn accept_id_token_claims(_ string) !bool {
	return true
}

pub fn (policy ProviderIDTokenPolicy) supports_sign_in() bool {
	return !policy.disabled && (policy.configured || policy.override_verify != no_id_token_override)
}

// All failure paths, including application callbacks, fail closed. Opaque tokens
// require an explicit opt-in and still need the provider's user-info validation
// before they establish identity; this function alone does not authenticate them.
pub fn (policy ProviderIDTokenPolicy) verify(token string, nonce string, now i64) bool {
	if policy.disabled { return false }
	if policy.override_verify != no_id_token_override { return policy.override_verify(token, nonce) or {
			false} }
	if !policy.configured { return false }
	if policy.custom_verify != no_id_token_override { return policy.custom_verify(token, nonce) or {
			false} }
	if token.split('.').len != 3 { return policy.allow_opaque_token }
	if !policy.config.audiences.any(it != '') { return false }
	header := id_token_header(token) or { return false }
	key := policy.resolve_key(json2.Any(header).json_str(), token) or { return false }
	payload := verify_id_token_with_jwk(token, key, IDTokenVerifyConfig{
		...policy.config
		nonce: nonce
	}, now) or { return false }
	return policy.verify_claims(payload) or { false }
}

pub fn id_token_config_from_json(encoded string) !IDTokenVerifyConfig {
	fields := json2.decode[map[string]json2.Any](encoded)!
	mut maximum := ?f64(none)
	if value := fields['maxTokenAge'] {
		if value is string {
			maximum = f64(duration_seconds(value)!)
		} else if value is i64 || value is int || value is f64 {
			maximum = value.f64()
		} else {
			return error('invalid maximum ID token age')
		}
	}
	mut algorithms := jwt_algorithms.clone()
	algorithms << ['HS256', 'HS384', 'HS512']
	if value := fields['algorithms'] {
		algorithms = id_token_strings(value)
	}
	return IDTokenVerifyConfig{
		issuers:          id_token_strings(fields['issuer'] or { json2.Any(json2.Null{}) })
		audiences:        id_token_strings(fields['audience'] or { json2.Any(json2.Null{}) })
		algorithms:       algorithms
		max_token_age:    maximum
		nonce_comparison: (fields['nonceComparison'] or { json2.Any('exact') }).str()
	}
}

fn id_token_strings(value json2.Any) []string {
	if value is string { return [value] }
	if value is []json2.Any {
		mut strings := []string{}
		for item in value {
			if item is string { strings << item }
		}
		return strings
	}
	return []string{}
}
