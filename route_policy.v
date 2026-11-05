module better_auth

// Transaction semantics are operation metadata. Transports do not infer plugin
// retry behavior from a URL prefix.
pub enum TransactionMode {
	single_attempt
	replayable
	read_only
}

fn (a &Auth) route_transaction_mode(path string, method string) TransactionMode {
	for plugin in a.config.plugins {
		for endpoint in plugin.endpoints() {
			if endpoint.path == path && endpoint.method == method {
				return endpoint.transaction_mode
			}
		}
	}
	if path == '/get-session' && method == 'GET' && a.config.defer_session_refresh {
		return .read_only
	}
	return .single_attempt
}
