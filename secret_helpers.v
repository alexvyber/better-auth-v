module better_auth

import math
import x.json2

pub struct SecretEntry {
pub:
	version i64
	value   string
}

pub fn parse_secrets_env(value string) ![]SecretEntry {
	if value == '' { return []SecretEntry{} }
	mut entries := []SecretEntry{}
	for index, item in value.split(',') {
		entry := item.trim_space()
		separator := entry.index(':') or {
			return error('Invalid BETTER_AUTH_SECRETS entry at position ${index + 1}. Expected format: "<version>:<secret>"')
		}
		version := decimal_prefix(entry[..separator]) or {
			return error('Invalid version in BETTER_AUTH_SECRETS entry at position ${index + 1}. Version must be a non-negative integer.')
		}
		if version < 0 {
			return error('Invalid version in BETTER_AUTH_SECRETS entry at position ${index + 1}. Version must be a non-negative integer.')
		}
		secret := entry[separator + 1..].trim_space()
		if secret == '' {
			return error('Empty secret value for version ${version} in BETTER_AUTH_SECRETS.')
		}
		entries << SecretEntry{
			version: version
			value:   secret
		}
	}
	return entries
}

pub fn parse_secret_entries(encoded string) ![]SecretEntry {
	input := json2.decode[[]json2.Any](encoded)!
	if input.len == 0 { return error('`secrets` array must contain at least one entry.') }
	mut entries := []SecretEntry{}
	mut seen := map[i64]bool{}
	for item in input {
		fields := item.as_map()
		raw := fields['version'] or {
			return error('Secret version must be a non-negative integer.')
		}
		text := if raw is string { raw.trim_space() } else { js_json(raw) }
		version := decimal_prefix(text) or {
			return error('Secret version must be a non-negative integer.')
		}
		if version < 0 || version.str() != text {
			return error('Secret version must be a non-negative integer.')
		}
		value := fields['value'] or {
			return error('Empty secret value for version ${version} in `secrets`.')
		}
		if value !is string || value.str() == '' {
			return error('Empty secret value for version ${version} in `secrets`.')
		}
		if version in seen {
			return error('Duplicate version ${version} in `secrets`. Each version must be unique.')
		}
		seen[version] = true
		entries << SecretEntry{
			version: version
			value:   value.str()
		}
	}
	return entries
}

pub fn secret_config_warnings(entries []SecretEntry) []string {
	if entries.len == 0 { return []string{} }
	current := entries[0]
	mut warnings := []string{}
	if utf16_length(current.value) < 32 {
		warnings << '[better-auth] Warning: the current secret (version ${current.version}) should be at least 32 characters long for adequate security.'
	}
	mut unique := map[rune]bool{}
	for codepoint in current.value.runes() {
		unique[codepoint] = true
	}
	entropy := if unique.len == 0 {
		f64(0)
	} else {
		math.log2(f64(unique.len)) * utf16_length(current.value)
	}
	if entropy < 120 {
		warnings << '[better-auth] Warning: the current secret appears low-entropy. Use a randomly generated secret for production.'
	}
	return warnings
}

pub fn build_secret_config(entries []SecretEntry, legacy_secret string) !SecretConfig {
	if entries.len == 0 { return error('`secrets` array must contain at least one entry.') }
	mut keys := map[i64]string{}
	for entry in entries {
		if entry.version < 0 || entry.value == '' || entry.version in keys {
			return error('invalid secret entries')
		}
		keys[entry.version] = entry.value
	}
	return SecretConfig{
		keys:            keys
		current_version: entries[0].version
		legacy_secret:   if legacy_secret == 'better-auth-secret-12345678901234567890' {
			''
		} else {
			legacy_secret
		}
	}
}
