module main

import better_auth
import json

struct RemoteOAuthTransport {}

fn (_ RemoteOAuthTransport) request(request better_auth.Request) !better_auth.Response {
	return json.decode(better_auth.Response, callback_rpc('oauth.fetch', json.encode(request))!)
}
