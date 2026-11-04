module main

import better_auth
import json
import os
import x.json2

fn crypto_command() ! {
	fields := json2.decode[map[string]json2.Any](os.get_raw_line())!
	op := fields['op'] or { return error('missing crypto operation') }
	args := (fields['args'] or { return error('missing crypto arguments') }).as_array()
	mut encoded := 'null'
	match op.str() {
		'setTokenUtil' {
			if args[0] is json2.Null {
				encoded = 'null'
			} else if args[0] is map[string]json2.Any {
				encoded = '{"$undefined":true}'
			} else {
				encoded = json.encode(better_auth.encrypt_oauth_token(args[0].str(),
					better_auth.decode_symmetric_secret(args[1])!, args[2].bool())!)
			}
		}
		'decryptOAuthToken' {
			encoded = json.encode(better_auth.decrypt_oauth_token(args[0].str(),
				better_auth.decode_symmetric_secret(args[1])!, args[2].bool())!)
		}
		'oneTimeTokenHash' {
			encoded = json.encode(better_auth.default_one_time_token_hasher(args[0].str())!)
		}
		'parseEnvelope' {
			if envelope := better_auth.parse_secret_envelope(args[0].str()) {
				encoded = json.encode(envelope)
			}
		}
		'formatEnvelope' {
			encoded = json.encode(better_auth.format_secret_envelope(args[0].i64(), args[1].str()))
		}
		'parseSecretsEnv' {
			value := if args[0] is string { args[0].str() } else { '' }
			if value != '' { encoded = json.encode(better_auth.parse_secrets_env(value)!) }
		}
		'validateSecretsArray' {
			entries := better_auth.parse_secret_entries(args[0].json_str())!
			encoded = json.encode(better_auth.secret_config_warnings(entries))
		}
		'buildSecretConfig' {
			entries := better_auth.parse_secret_entries(args[0].json_str())!
			encoded = better_auth.encode_secret_config(better_auth.build_secret_config(entries,
				args[1].str())!)
		}
		'symmetricEncrypt' {
			encoded = json.encode(better_auth.symmetric_encrypt(better_auth.decode_symmetric_secret(args[0])!,
				args[1].str())!)
		}
		'symmetricDecrypt' {
			encoded = json.encode(better_auth.symmetric_decrypt(better_auth.decode_symmetric_secret(args[0])!,
				args[1].str())!)
		}
		'derivePurposeKey' {
			key := better_auth.derive_purpose_key(better_auth.decode_symmetric_secret(args[0])!,
				args[1].str())!
			match key {
				string { encoded = json.encode(key) }
				better_auth.SecretConfig { encoded = better_auth.encode_secret_config(key) }
			}
		}
		'symmetricEncodeJWT' {
			encoded = json.encode(better_auth.symmetric_encode_jwt_rotating_with_lifetime(args[0].json_str(),
				better_auth.decode_symmetric_secret(args[1])!, args[2].str(), args[3].f64(),
				args[4].i64())!)
		}
		'symmetricDecodeJWT' {
			encoded = better_auth.symmetric_decode_jwt_rotating(args[0].str(),
				better_auth.decode_symmetric_secret(args[1])!, args[2].str(), args[3].i64()) or {
				'null'
			}
		}
		'signJWT' {
			encoded = json.encode(better_auth.sign_hmac_jwt_with_lifetime(args[0].json_str(),
				args[1].str(), args[2].f64(), args[3].i64())!)
		}
		'verifyJWT' {
			encoded = better_auth.verify_hmac_jwt_with_algorithms(args[0].str(), args[1].str(),
				args[2].i64(), ['HS256', 'HS384', 'HS512']) or { 'null' }
		}
		else {
			return error('unsupported crypto operation')
		}
	}

	println(encoded)
}
