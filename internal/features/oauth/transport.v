module better_auth

import net.http
import time

// Transports only move HTTP bytes. Grant construction, token parsing and profile
// policy belong to the native provider, including when tests supply a transport.
pub interface OAuthTransport {
	request(Request) !Response
}

pub struct OAuthHTTPTransport {}

pub fn (_ OAuthHTTPTransport) request(request Request) !Response {
	response := http.fetch(
		url:                  request.url
		method:               http.method_from_str(request.method)
		header:               http.new_custom_header_from_map(request.headers)!
		data:                 request.body
		validate:             true
		allow_redirect:       false
		read_timeout:         10 * time.second
		max_retries:          0
		stop_receiving_limit: 1048576
	)!
	return Response{
		status: response.status_code
		body:   response.body
	}
}
