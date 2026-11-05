module better_auth

fn (a &Auth) secret_candidates() []string {
	mut candidates := [a.config.secret]
	config := a.secret_config
	if config is SecretConfig {
		for _, value in config.keys {
			if value != '' && value !in candidates { candidates << value }
		}
		if config.legacy_secret != '' && config.legacy_secret !in candidates {
			candidates << config.legacy_secret
		}
	}
	return candidates
}

// Adapter capabilities are application-owned, never request-controlled HTTP data.
