module better_auth

import net.urllib

fn html_entity(text string) bool {
	if text in ['amp', 'lt', 'gt', 'quot', '#39'] { return true }
	if text.starts_with('#x') { return text.len > 2 && text[2..].bytes().all(it.is_hex_digit()) }
	if text.starts_with('#') { return text.len > 1 && text[1..].bytes().all(it.is_digit()) }
	return false
}

fn escape_error_html(input string) string {
	mut result := []u8{cap: input.len}
	for i, value in input.bytes() {
		match value {
			`<` {
				result << '&lt;'.bytes()
			}
			`>` {
				result << '&gt;'.bytes()
			}
			`"` {
				result << '&quot;'.bytes()
			}
			`'` {
				result << '&#39;'.bytes()
			}
			`&` {
				mut end := i + 1
				for end < input.len && (input[end].is_alnum() || input[end] == `#`) {
					end++
				}
				if end < input.len && input[end] == `;` && html_entity(input[i + 1..end]) {
					result << value
				} else {
					result << '&amp;'.bytes()
				}
			}
			else {
				result << value
			}
		}
	}
	return result.bytestr()
}

fn error_page(request_url string) !Response {
	url := urllib.parse(request_url)!
	mut code := url.query().get('error') or { 'UNKNOWN' }
	if code == '' || !code.bytes().all(it.is_alnum() || it in [`'`, `_`, `-`]) { code = 'UNKNOWN' }
	description := url.query().get('error_description') or { '' }
	detail := if description != '' {
		escape_error_html(description)
	} else {
		'We encountered an unexpected error. Please try again or return to the home page.'
	}
	return Response{
		headers: [Header{'content-type', 'text/html; charset=utf-8'}]
		body:    '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Error</title></head><body><main><h1>Something went wrong</h1><p>${escape_error_html(code)}</p><p>${detail}</p><a href="/">Return home</a></main></body></html>'
	}
}
