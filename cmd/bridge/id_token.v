module main

import better_auth
import json
import os
import x.json2

fn provider_id_token_policy(input map[string]json2.Any) !better_auth.ProviderIDTokenPolicy {
	config_json := (input['config'] or { json2.Any(map[string]json2.Any{}) }).json_str()
	disabled := (input['disabled'] or { json2.Any(false) }).bool()
	configured := (input['configured'] or { json2.Any(false) }).bool()
	override := (input['override'] or { json2.Any(false) }).bool()
	custom := (input['custom'] or { json2.Any(false) }).bool()
	token := (input['token'] or { json2.Any('') }).str()
	config := if !disabled && configured && !override && !custom && token.split('.').len == 3 {
		better_auth.id_token_config_from_json(config_json)!
	} else {
		better_auth.IDTokenVerifyConfig{}
	}
	mut policy := better_auth.ProviderIDTokenPolicy{
		disabled:           disabled
		configured:         configured
		allow_opaque_token: (input['allowOpaqueToken'] or { json2.Any(false) }) == json2.Any(true)
		config:             config
		resolve_key:        fn (header string, token string) !string {
			fields := json2.decode[map[string]json2.Any](header)!
			return better_auth.decode_id_token_resolved_key(callback_rpc('id.key',
				'{"header":${header},"token":${json.encode(token)}}')!, (fields['alg'] or {
				json2.Any('')
			}).str())
		}
	}
	if (input['override'] or { json2.Any(false) }).bool() {
		policy = better_auth.ProviderIDTokenPolicy{
			...policy
			override_verify: fn (token string, nonce string) !bool {
				return json2.decode[bool](callback_rpc('id.override', json.encode({
					'token': token
					'nonce': nonce
				}))!)
			}
		}
	}
	if (input['custom'] or { json2.Any(false) }).bool() {
		policy = better_auth.ProviderIDTokenPolicy{
			...policy
			custom_verify: fn (token string, nonce string) !bool {
				return json2.decode[bool](callback_rpc('id.custom', json.encode({
					'token': token
					'nonce': nonce
				}))!)
			}
		}
	}
	if (input['claims'] or { json2.Any(false) }).bool() {
		policy = better_auth.ProviderIDTokenPolicy{
			...policy
			verify_claims: fn (payload string) !bool {
				return json2.decode[bool](callback_rpc('id.claims', payload)!)
			}
		}
	}
	return policy
}

fn provider_id_token_command() ! {
	for {
		line := os.get_raw_line()
		if line == '' { return }
		input := json2.decode[map[string]json2.Any](line)!
		op := (input['op'] or { json2.Any('') }).str()
		if op == 'close' {
			emit(Reply{ id: (input['id'] or { json2.Any(0) }).int() })
			return
		}
		if op == 'verify' {
			value := if policy := provider_id_token_policy(input) {
				policy.verify((input['token'] or { json2.Any('') }).str(), (input['nonce'] or {
					json2.Any('')
				}).str(), (input['now'] or { json2.Any(0) }).i64())
			} else {
				false
			}
			emit(Reply{ id: (input['id'] or { json2.Any(0) }).int(), value_json: json.encode(value) })
			continue
		}
		if op == 'supports' {
			// Capability checking never parses the verification config or runs callbacks.
			configured := (input['configured'] or { json2.Any(false) }).bool()
			disabled := (input['disabled'] or { json2.Any(false) }).bool()
			override := (input['override'] or { json2.Any(false) }).bool()
			policy := better_auth.ProviderIDTokenPolicy{
				disabled:   disabled
				configured: configured || override
			}
			println(json.encode(policy.supports_sign_in()))
			return
		}
		profile := better_auth.id_token_provider_profile((input['provider'] or { json2.Any('') }).str(), (input['options'] or {
			json2.Any(map[string]json2.Any{})
		}).json_str())!
		match op {
			'profile' {
				mut config := {
					'audience':         json2.Any(profile.config.audiences.map(json2.Any(it)))
					'algorithms':       json2.Any(profile.config.algorithms.map(json2.Any(it)))
					'allowOpaqueToken': json2.Any(profile.allow_opaque_token)
					'nonceComparison':  json2.Any(profile.config.nonce_comparison)
				}
				if profile.config.issuers.len > 0 {
					config['issuer'] = profile.config.issuers.map(json2.Any(it))
				}
				if maximum := profile.config.max_token_age { config['maxTokenAge'] = maximum }
				println(json2.Any({
					'configured': json2.Any(profile.configured)
					'config':     json2.Any(config)
					'url':        json2.Any(profile.jwks_url)
				}).json_str())
			}
			'profile-key' {
				println(profile.resolve_key((input['header'] or {
					json2.Any(map[string]json2.Any{})
				}).json_str(), (input['jwks'] or { json2.Any(map[string]json2.Any{}) }).json_str())!)
			}
			'profile-claims' {
				println(json.encode(profile.accepts_claims((input['payload'] or {
					json2.Any(map[string]json2.Any{})
				}).json_str())!))
			}
			else {
				return error('unknown provider ID token fixture operation')
			}
		}

		return
	}
}
