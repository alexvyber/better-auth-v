module better_auth

fn test_cookie_wire_validation_and_semantic_roundtrip() {
	// Decode failures leave the whole encoding untouched. Encoded controls remain
	// semantic data and must be escaped again when written to a request header.
	header := '2=second;1=first;token=old;token=%E2%82%AC;invalid=%20%FF;escape=%0D%0A;plus=a+b;raw=bad\r'
	cookies := parse_cookies(header)
	assert cookies.keys() == ['2', '1', 'token', 'invalid', 'escape', 'plus']
	assert cookies['token'] == '€'
	assert cookies['invalid'] == '%20%FF'
	assert cookies['escape'] == '\r\n'
	assert cookies['plus'] == 'a+b'
	serialized := set_request_cookie(header, 'new', 'a;=+%€')
	assert !serialized.contains('\r') && !serialized.contains('\n')
	assert serialized.starts_with('2=second; 1=first; token=%E2%82%AC; ')
	assert serialized.ends_with('new=a%3B%3D%2B%25%E2%82%AC')
	roundtrip := parse_cookies(serialized)
	assert roundtrip['new'] == 'a;=+%€'
	assert roundtrip['invalid'] == '%20%FF'
}

fn test_session_selection_and_chunk_expiration_boundaries() {
	assert (get_session_cookie('better-auth.session_token=stale;__Secure-better-auth.session_token=',
		'better-auth', 'session_token') or { 'missing' }) == 'missing'
	assert (get_session_cookie('better-auth.session_token=stale;__Secure-better-auth.session_token=;better-auth-session_token=legacy',
		'better-auth', 'session_token') or { '' }) == 'legacy'
	assert (get_chunked_cookie('cache.10=C;cache.0=A;cache.01=bad;cache.2=B;cache.nested.0=bad',
		'cache', none) or { '' }) == 'ABC'
	assert (get_chunked_cookie('cache.0=stale', 'cache', 'direct') or { '' }) == 'direct'
	assert remove_set_cookie_entries([
		'keep=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, cache=old; Path=/, cache.nested.0=old; Path=/, cache-other=2',
	], 'cache') == ['keep=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT', 'cache-other=2']
}

fn test_cookie_attribute_overrides_and_invalid_metadata() {
	parsed :=
		parse_set_cookie_header('token="a%3Db"; Max-Age=+123junk; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Priority=High, invalid=1; Max-Age=no; Expires=not-a-date, cleared=2; Max-Age=no; Max-Age=; Expires=bad; Expires=')
	assert parsed['token'].value == 'a=b'
	assert (parsed['token'].attributes['max-age'] or { panic('missing max-age') }).f64() == 123
	assert (parsed['token'].expires_at or { i64(0) }) == 1445412480000
	assert (parsed['token'].attributes['priority'] or { panic('missing priority') }).str() == 'High'
	assert parsed['invalid'].invalid_max_age
	assert parsed['invalid'].expires_present
	assert parsed['invalid'].expires_at == none
	assert !parsed['cleared'].invalid_max_age
	assert !parsed['cleared'].expires_present
	assert 'max-age' !in parsed['cleared'].attributes
}
