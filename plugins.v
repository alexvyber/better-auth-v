module better_auth

import json
import net.urllib

// Bearer is opt-in because cookie and bearer credentials have different exposure
// and browser security properties.
pub struct BearerPlugin {}

pub fn (_ BearerPlugin) id() string {
	return 'bearer'
}

pub fn (_ BearerPlugin) endpoints() []Endpoint {
	return []Endpoint{}
}

pub struct MagicLinkPlugin {}

pub fn (_ MagicLinkPlugin) id() string {
	return 'magic-link'
}

pub fn (_ MagicLinkPlugin) endpoints() []Endpoint {
	return [
		Endpoint{
			path:    '/sign-in/magic-link'
			handler: magic_link_send
		},
		Endpoint{
			path:    '/magic-link/verify'
			method:  'GET'
			handler: magic_link_verify
		},
	]
}

fn magic_link_send(mut context EndpointContext, req Request) !Response {
	mut a := context.auth
	p := json.decode(Payload, req.body)!
	email := normalize_email(p.email)!
	a.check_redirect(p.callback_url, 'callbackURL')!
	// Existing users only: automatic registration needs an explicit product
	// policy and is not silently enabled by this plugin.
	if user := (a.storage.user_by_email(email)!).value {
		token := random_token()!
		a.persist_opaque_verification(token, Verification{
			id:                digest(token)
			identifier:        'magic-link'
			value:             user.id
			expires_at:        a.config.clock() + a.config.verification_expires_in
			expires_at_millis: a.clock_millis() + a.config.verification_expires_in * 1000
		})!
		url := a.base_url().trim_right('/') + a.config.base_path + '/magic-link/verify?token=' +
			token + '&callbackURL=' + urllib.query_escape(p.callback_url)
		a.config.send_email(EmailMessage{
			kind:    'magic-link'
			user:    user
			token:   token
			url:     url
			request: a.operation.request.request
		})!
	}
	return json_response({
		'status': true
	})
}

fn magic_link_verify(mut context EndpointContext, req Request) !Response {
	mut a := context.auth
	u := urllib.parse(req.url)!
	callback := u.query().get('callbackURL') or { '' }
	a.check_redirect(callback, 'callbackURL')!
	user := a.consume_token(u.query().get('token') or { '' }, 'magic-link')!
	a.commit_transaction()!
	a.begin_transaction(false)!
	updated := if !user.email_verified { (context.revoke_unproven_account_access(user.id)!).value or {
			return fail(400, 'INVALID_TOKEN', 'Invalid token')} } else { user }
	session := a.make_session(user.id, a.operation.request, true)!
	response := if callback != '' {
		Response{
			status:  302
			headers: [Header{'location', callback}]
		}
	} else {
		a.session_response(SessionResult{ user: updated, session: session })
	}
	return a.set_session_cookies(response, SessionResult{ user: updated, session: session })
}
