module better_auth

import net.urllib

fn valid_cookie_name(name string) bool {
	if name == '' { return false }
	for value in name.bytes() {
		if value <= 32 || value >= 127
			|| value in [`(`, `)`, `<`, `>`, `@`, `,`, `;`, `:`, `\\`, `"`, `/`, `[`, `]`, `?`, `=`, `{`, `}`] {
			return false
		}
	}
	return true
}

fn validate_cookie_config(config Config) ! {
	if config.cookie_prefix != '' && !valid_cookie_name(config.cookie_prefix) {
		return error('invalid cookie prefix')
	}
	for _, name in config.cookie_names {
		if name != '' && !valid_cookie_name(name) { return error('invalid cookie name') }
	}
	if config.cross_subdomain_cookies {
		if config.cookie_domain == '' && config.base_url == '' {
			return error('baseURL is required when crossSubdomainCookies are enabled.')
		}
		if config.cookie_domain != '' {
			domain := config.cookie_domain.trim_left('.')
			if domain == '' || !domain.bytes().all(it.is_alnum() || it in [`-`, `.`, `:`]) {
				return error('invalid cookie domain')
			}
		}
	}
}

fn (a &Auth) cookie_secure() bool {
	return a.config.secure_cookies or { a.base_url().starts_with('https://') }
}

fn (a &Auth) cookie_name_for(kind string) string {
	prefix := if a.config.cookie_prefix == '' { 'better-auth' } else { a.config.cookie_prefix }
	configured := a.config.cookie_names[kind]
	name := if configured == '' { prefix + '.' + kind } else { configured }
	return if a.cookie_secure() { '__Secure-' + name } else { name }
}

fn (a &Auth) cookie_scope_domain() string {
	if !a.config.cross_subdomain_cookies { return '' }
	if a.config.cookie_domain != '' { return a.config.cookie_domain }
	url := urllib.parse(a.base_url()) or { return '' }
	return url.hostname()
}

fn (a &Auth) cookie_header(name string, value string, path string, max_age ?i64) string {
	mut header := '${name}=${value}; Path=${path}; HttpOnly; SameSite=Lax'
	if age := max_age { header += '; Max-Age=${age}' }
	if a.cookie_secure() { header += '; Secure' }
	domain := a.cookie_scope_domain()
	if domain != '' { header += '; Domain=${domain}' }
	return header
}
