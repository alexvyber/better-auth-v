module main

import better_auth
import net.http
import os

struct ServerHandler {
mut:
	auth &better_auth.Auth
}

fn (mut h ServerHandler) handle(req http.Request) http.Response {
	mut headers := map[string]string{}
	for key in req.header.keys() {
		headers[key] = req.header.get_custom(key) or { '' }
	}
	url := h.auth.config.base_url.trim_right('/') + req.url
	r := h.auth.handle(better_auth.Request{
		method:  req.method.str()
		url:     url
		headers: headers
		body:    req.data
	})
	mut response := http.Response{
		status_code: r.status
		status_msg:  r.status_text
		body:        r.body
	}
	for header in r.headers {
		response.header.add_custom(header.name, header.value) or {}
	}
	return response
}

fn main() {
	mut storage := better_auth.open_sqlite(os.getenv_opt('AUTH_DB') or { 'auth.db' })!
	if '--migrate' in os.args {
		storage.migrate()!
		storage.close()!
		return
	}
	secret := os.getenv_opt('AUTH_SECRET') or {
		panic('AUTH_SECRET is required (at least 32 bytes)')
	}
	base_url := os.getenv_opt('AUTH_BASE_URL') or { 'http://localhost:3000' }
	mut auth := better_auth.new(better_auth.Config{ secret: secret, base_url: base_url }, storage)!
	defer { auth.close() or {} }
	mut server := http.Server{
		addr:    os.getenv_opt('AUTH_LISTEN') or { '127.0.0.1:3000' }
		handler: ServerHandler{
			auth: auth
		}
	}
	server.listen_and_serve()
}
