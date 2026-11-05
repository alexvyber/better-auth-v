module better_auth

import net
import net.urllib
import x.json2

fn origin_has_controls(value string) bool {
	for character in value.runes() {
		if character < 32 || (character >= 127 && character <= 159) { return true }
	}
	return false
}

fn safe_relative_url(value string) bool {
	if !value.starts_with('/') || value.starts_with('//') || value.contains('\\')
		|| origin_has_controls(value) {
		return false
	}
	path := value.all_before('?').all_before('#').to_lower()
	return !path.contains('%2f') && !path.contains('%5c')
}

fn normalized_origin_path(value string) string {
	decoded := urllib.path_unescape(value) or { value }
	mut segments := []string{}
	for segment in decoded.split('/') {
		if segment == '..' {
			if segments.len > 0 { segments.delete_last() }
		} else if segment != '' && segment != '.' {
			segments << segment
		}
	}
	return if segments.len == 0 { '' } else { '/' + segments.join('/') }
}

struct CustomOrigin {
	scheme    string
	authority string
	path      string
}

fn parse_custom_origin(value string) ?CustomOrigin {
	if origin_has_controls(value) { return none }
	colon := value.index(':') or { return none }
	if colon == 0 { return none }
	mut rest := value[colon + 1..]
	mut authority := ''
	if rest.starts_with('//') {
		rest = rest[2..]
		mut end := 0
		for end < rest.len && rest[end] !in [`/`, `?`, `#`] {
			end++
		}
		authority = rest[..end].to_lower()
		rest = rest[end..]
	}
	return CustomOrigin{
		scheme:    value[..colon].to_lower()
		authority: authority
		path:      normalized_origin_path(rest.all_before('?').all_before('#'))
	}
}

fn web_origin(value string) ?string {
	url := urllib.parse(value) or { return none }
	scheme := url.scheme.to_lower()
	if scheme !in ['http', 'https', 'ftp', 'ws', 'wss'] || url.host == '' { return none }
	mut host := url.host.to_lower()
	if (scheme in ['http', 'ws'] && host.ends_with(':80'))
		|| (scheme in ['https', 'wss'] && host.ends_with(':443'))
		|| (scheme == 'ftp' && host.ends_with(':21')) {
		host = host.all_before_last(':')
	}
	return scheme + '://' + host
}

// Match one glob segment. A backslash escapes the next pattern character.
fn origin_glob_segment(pattern string, sample string) bool {
	mut p := 0
	mut s := 0
	mut star := -1
	mut retry := 0
	for s < sample.len {
		if p < pattern.len && pattern[p] == `*` {
			star = p
			p++
			retry = s
			continue
		}
		if p < pattern.len {
			if pattern[p] == `\\` && p + 1 < pattern.len && pattern[p + 1] == sample[s] {
				p += 2
				s++
				continue
			}
			if pattern[p] == `?` || pattern[p] == sample[s] {
				p++
				s++
				continue
			}
		}
		if star < 0 { return false }
		p = star + 1
		retry++
		s = retry
	}
	for p < pattern.len && pattern[p] == `*` {
		p++
	}
	return p == pattern.len
}

fn origin_glob(pattern string, sample string) bool {
	patterns := pattern.split('/').filter(it != '')
	samples := sample.replace('\\', '/').split('/').filter(it != '')
	if pattern.ends_with('/') && !sample.ends_with('/') && !sample.ends_with('\\') { return false }
	mut previous := []bool{len: samples.len + 1}
	previous[0] = true
	for part in patterns {
		mut next := []bool{len: samples.len + 1}
		if part == '**' {
			next[0] = previous[0]
			for i in 1 .. next.len {
				next[i] = previous[i] || next[i - 1]
			}
		} else {
			for i in 1 .. next.len {
				next[i] = previous[i - 1] && origin_glob_segment(part, samples[i - 1])
			}
		}
		previous = next.clone()
	}
	return previous[samples.len]
}

// Observable origin-pattern matching shared by HTTP policy and trusted server APIs.
pub fn matches_origin_pattern(value string, pattern string, allow_relative bool) bool {
	if value.starts_with('/') { return allow_relative && safe_relative_url(value) }
	if pattern.contains('*') || pattern.contains('?') {
		if pattern.contains('://') { return origin_glob(pattern, web_origin(value) or { value }) }
		url := urllib.parse(value) or { return false }
		if url.scheme == '' || url.host == '' { return false }
		return origin_glob(pattern, url.host.to_lower())
	}
	url := urllib.parse(value) or { return false }
	if url.scheme.to_lower() in ['', 'http', 'https'] { return pattern == (web_origin(value) or {
			return false}) }
	parsed := parse_custom_origin(value) or { return false }
	trusted := parse_custom_origin(pattern) or { return false }
	if parsed.scheme != trusted.scheme
		|| (trusted.authority != '' && parsed.authority != trusted.authority) {
		return false
	}
	return trusted.path == '' || parsed.path == trusted.path
		|| parsed.path.starts_with(trusted.path + '/')
}

pub fn parse_trusted_origins(encoded string) ![]string {
	values := json2.decode[[]json2.Any](encoded)!
	mut origins := []string{}
	for value in values {
		if value is string && value != '' { origins << value }
	}
	return origins
}

pub fn (a &Auth) is_trusted_origin(value string, allow_relative bool) bool {
	if a.base_url() != ''
		&& matches_origin_pattern(value, a.base_url().trim_right('/'), allow_relative) {
		return true
	}
	for pattern in a.config.trusted_origins {
		if matches_origin_pattern(value, pattern, allow_relative) { return true }
	}
	if a.operation.request.request == none {
		for pattern in a.initial_trusted_origins {
			if matches_origin_pattern(value, pattern, allow_relative) { return true }
		}
	}
	for pattern in a.operation.request.trusted_origins {
		if matches_origin_pattern(value, pattern, allow_relative) { return true }
	}
	return false
}

pub fn (c &EndpointContext) is_trusted_origin(value string, allow_relative bool) bool {
	return c.auth.is_trusted_origin(value, allow_relative)
}

fn origin_loopback_host(host string) bool {
	mut name := host.trim_space().to_lower()
	if name.starts_with('[') {
		name = name.all_before(']') + ']'
		name = name.trim('[]')
	} else if name.count(':') == 1 {
		name = name.all_before(':')
	}
	name = name.all_before('%').trim_right('.')
	if name == 'localhost' || name.ends_with('.localhost') { return true }
	if canonical := net.canonical_ipv6(name) {
		if canonical == '::1' { return true }
		if canonical.starts_with('::ffff:') {
			name = canonical.all_after('::ffff:')
		} else {
			return false
		}
	}
	parts := name.split('.')
	if parts.len != 4 || parts[0] != '127' { return false }
	for part in parts {
		if part == '' || !part.bytes().all(it.is_digit()) || part.len > 3
			|| (part.len > 1 && part[0] == `0`) || part.int() > 255 {
			return false
		}
	}
	return true
}

// Resolve the standalone upstream helper without opening a database.
// Dynamic baseURL entries expand into origin patterns; resolving a live request's
// base URL against allowedHosts remains an embedding concern for this helper.
pub fn get_trusted_origins(options_json string, request_url string, environment string) ![]string {
	options := json2.decode[map[string]json2.Any](options_json)!
	mut origins := []string{}
	base := options['baseURL'] or { json2.Any(json2.Null{}) }
	if base is map[string]json2.Any {
		protocol := (base['protocol'] or { json2.Any('') }).str()
		hosts := (base['allowedHosts'] or { json2.Any([]json2.Any{}) }).as_array()
		for value in hosts {
			host := value.str()
			if host.contains('://') {
				origins << host
				continue
			}
			if protocol in ['', 'https', 'auto'] { origins << 'https://' + host }
			loopback := origin_loopback_host(host)
			if protocol in ['http', 'auto'] || loopback { origins << 'http://' + host }
		}
		if fallback := base['fallback'] {
			if origin := web_origin(fallback.str()) { origins << origin }
		}
	} else if base is string && base != '' {
		if origin := web_origin(base) { origins << origin }
	} else if request_url != '' {
		if origin := web_origin(request_url) { origins << origin }
	}
	if values := options['trustedOrigins'] { origins << parse_trusted_origins(values.json_str())! }
	if environment != '' {
		for origin in environment.split(',') {
			if origin != '' { origins << origin }
		}
	}
	return origins
}

fn no_trusted_origins(_ RequestContext) ![]string {
	return []string{}
}

fn (a &Auth) skip_origin_check() bool {
	if a.config.disable_origin_check { return true }
	request := a.operation.request.request or { return false }
	url := urllib.parse(request.url) or { return false }
	path := normalized_origin_path(url.path)
	base := a.config.base_path
	current := if path.starts_with(base + '/') { path[base.len..] } else { path }
	for configured in a.config.skip_origin_check_paths {
		pattern := configured.trim_right('/')
		if current == pattern || current.starts_with(pattern + '/') { return true }
	}
	return false
}

pub fn (c &EndpointContext) validate_redirect(value string) ! {
	c.auth.check_redirect(value, 'callbackURL')!
}
