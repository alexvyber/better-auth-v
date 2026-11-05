module better_auth

fn (a &Auth) base_url() string {
	return if a.config.base_url != '' { a.config.base_url } else { a.operation.request.origin }
}

fn (a &Auth) trusted(origin string) bool {
	return origin != '' && a.is_trusted_origin(origin, false)
}

fn (a &Auth) check_redirect(value string, input_field string) ! {
	field := if input_field == 'redirectTo' { 'redirectURL' } else { input_field }
	if value == '' { return }
	if value.contains_any('\r\n\x00') {
		return fail(403, 'INVALID_CALLBACK_URL', 'Invalid ${field}')
	}
	if a.skip_origin_check() { return }
	if value.contains('\\') || value.starts_with('//') {
		return fail(403, 'INVALID_CALLBACK_URL', 'Invalid ${field}')
	}
	// Trusted server calls have no HTTP origin policy; keep structural header checks.
	if a.operation.request.request == none { return }
	if !a.is_trusted_origin(value, true) {
		return fail(403, 'INVALID_CALLBACK_URL', 'Invalid ${field}')
	}
}
