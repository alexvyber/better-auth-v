module main

import better_auth
import json
import x.json2

struct RemoteJWKStore {
	prefix  string = 'jwt'
	methods []string
}

fn (mut store RemoteJWKStore) get_keys(mut context better_auth.EndpointContext) ![]better_auth.Jwk {
	if store.prefix + '.getJwks' !in store.methods { return context.stored_jwks() }
	encoded := callback_with_context(store.prefix + '.getJwks', '{}', mut context)!
	if encoded == 'null' { return []better_auth.Jwk{} }
	return json.decode([]better_auth.Jwk, encoded)
}

fn (mut store RemoteJWKStore) create_key(key better_auth.Jwk, mut context better_auth.EndpointContext) !better_auth.Jwk {
	if store.prefix + '.createJwk' !in store.methods { return context.store_jwk(key) }
	mut fields := json2.decode[map[string]json2.Any](json.encode(key))!
	fields.delete('id')
	encoded := callback_with_context(store.prefix + '.createJwk', json2.Any(fields).json_str(), mut
		context)!
	return json.decode(better_auth.Jwk, encoded)
}

struct RemoteEndpoint {
	body_schema      string
	query_schema     string
	openapi_metadata string
	hide_from_docs   bool
	name             string
	path             string
	method           string
	require_session  bool
	fresh_session    bool
}

@[heap]
struct RemoteEndpointPlugin {
	name   string
	routes []RemoteEndpoint
}

fn (p RemoteEndpointPlugin) id() string {
	return p.name
}

fn (p RemoteEndpointPlugin) endpoints() []better_auth.Endpoint {
	mut endpoints := []better_auth.Endpoint{}
	for route in p.routes {
		callback_name := 'plugin.' + p.name + '.' + route.name
		endpoints << better_auth.Endpoint{
			body_schema:      route.body_schema
			query_schema:     route.query_schema
			openapi_metadata: route.openapi_metadata
			hide_from_docs:   route.hide_from_docs
			path:             route.path
			method:           route.method
			require_session:  route.require_session
			fresh_session:    route.fresh_session
			handler:          fn [callback_name] (mut context better_auth.EndpointContext, req better_auth.Request) !better_auth.Response {
				session_json := if current := context.session {
					'{"session":${better_auth.encode_session(current.session)},"user":${better_auth.encode_user(current.user)}}'
				} else {
					'null'
				}
				encoded := callback_with_context(callback_name,
					'{"request":${json.encode(req)},"session":${session_json}}', mut context)!
				return json.decode(better_auth.Response, encoded)
			}
		}
	}
	return endpoints
}
