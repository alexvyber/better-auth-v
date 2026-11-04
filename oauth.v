module better_auth

import crypto.hmac
import crypto.sha256
import encoding.base64
import json
import net.urllib
import x.json2

// Code exchanges obtain identity from the provider's authenticated token/profile
// transport. Direct ID-token credentials need a separate issuer/audience/nonce/
// signature/expiry verification path; they must not enter exchange().
pub interface OAuthProvider {
	id() string
	authorization_url(string, string, string) !string
	exchange(string, string, string) !OAuthIdentity
}

pub interface OAuthIDTokenProvider {
	supports_id_token() bool
	verify_id_token(string, string) Lookup[string]
	user_info(OAuthTokens) !Lookup[OAuthIdentity]
}

pub interface OAuthAuthorizationProvider {
	authorization_request(input OAuthAuthorizationRequest, challenge string) !string
}

struct OAuthAccountIdentity {
	new_user bool
	user     User
	account  Account
}

struct DirectIDToken {
	token         string
	nonce         string
	access_token  ?string @[json: accessToken]
	refresh_token ?string @[json: refreshToken]
	expires_at    ?f64    @[json: expiresAt]
}

pub struct OAuthIdentity {
pub:
	id                string
	email             string
	email_verified    bool
	name              string
	image             ?string
	additional_fields map[string]json2.Any
	profile           map[string]json2.Any
	tokens            OAuthTokens
}

pub struct OAuthTokens {
pub:
	access_token             ?string
	refresh_token            ?string
	id_token                 string
	access_token_expires_at  ?string
	refresh_token_expires_at ?string
	scope                    ?string
}

struct OAuthState {
	nonce                 string
	new_user_callback_url string
	error_callback_url    string
	request_sign_up       bool
	anonymous_user_id     string
	provider              string
	verifier              string
	callback_url          string
}

fn (a &Auth) oauth_provider(id string) !OAuthProvider {
	for provider in a.config.social_providers {
		if provider.id() == id { return provider }
	}
	return fail(400, 'PROVIDER_NOT_FOUND', 'Provider not found')
}

fn (a &Auth) oauth_cookie_name() string {
	return a.cookie_name_for('oauth_state')
}

fn (a &Auth) oauth_cookie(r Response, state string, clear bool) Response {
	age := if clear { i64(0) } else { i64(600) }
	value := if clear { '' } else { urllib.query_escape(a.sign_cookie(state)) }
	return with_header(r, 'set-cookie', a.cookie_header(a.oauth_cookie_name(), value,
		a.config.base_path, age))
}

fn (mut a Auth) start_oauth(p Payload) !Response {
	provider := a.oauth_provider(p.provider)!
	if input := p.id_token {
		if provider is OAuthIDTokenProvider {
			if !provider.supports_id_token() {
				return fail(404, 'ID_TOKEN_NOT_SUPPORTED',
					'Provider does not support id token sign-in')
			}
			if provider.verify_id_token(input.token, input.nonce).value == none {
				return fail(401, 'INVALID_TOKEN', 'Invalid token')
			}
			info := (provider.user_info(OAuthTokens{
				id_token:      input.token
				access_token:  input.access_token
				refresh_token: input.refresh_token
			})!).value or { return fail(401, 'FAILED_TO_GET_USER_INFO', 'Failed to get user info') }
			if info.email == '' { return fail(401, 'USER_EMAIL_NOT_FOUND', 'User email not found') }
			if info.id == '' {
				return fail(401, 'FAILED_TO_GET_USER_INFO', 'Failed to get user info')
			}
			// The pinned direct-token branch persists access/ID tokens; its refresh
			// token and expiresAt inputs are not included in the account write.
			identity := OAuthIdentity{
				...info
				tokens: OAuthTokens{
					id_token:     input.token
					access_token: input.access_token
				}
			}
			account := a.oauth_identity_account_with_signup(identity, p.provider, false, if provider is GenericOAuthProvider {
				provider.sign_up_allowed(p.request_sign_up)
			} else {
				true
			})!
			session := a.make_session(account.user.id, a.request_context, true)!
			mut response := Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"redirect":false,"token":${json.encode(session.token)},"user":${a.user_json(account.user)}}'
			}
			if a.config.store_account_cookie {
				response = a.set_account_cookie(response, json.encode(account.account))!
			}
			return a.set_session_cookies(response, SessionResult{
				session: session
				user:    account.user
			})
		}
		return fail(404, 'ID_TOKEN_NOT_SUPPORTED', 'Provider does not support id token sign-in')
	}
	nonce := if provider is GenericOAuthProvider {
		if a.oauth_nonce_requirements[provider.id()] or { provider.requires_nonce() } {
			random_token()!
		} else {
			''
		}
	} else {
		''
	}
	state := random_token()!
	verifier := random_token()!
	challenge := base64.url_encode(sha256.sum(verifier.bytes())).trim_right('=')
	redirect_uri := a.base_url().trim_right('/') + a.config.base_path + '/callback/' + provider.id()
	url := if provider is OAuthAuthorizationProvider {
		provider.authorization_request(OAuthAuthorizationRequest{
			state:             state
			nonce:             nonce
			redirect_uri:      redirect_uri
			scopes:            p.scopes
			login_hint:        p.login_hint
			additional_params: p.additional_params
		}, challenge)!
	} else {
		provider.authorization_url(state, challenge, redirect_uri)!
	}
	callback := if p.callback_url == '' { a.base_url() } else { p.callback_url }
	a.persist_verification(Verification{
		id:                digest(state)
		identifier:        'oauth-state'
		value:             json.encode(OAuthState{
			nonce:                 nonce
			new_user_callback_url: p.new_user_callback_url
			error_callback_url:    p.error_callback_url
			request_sign_up:       p.request_sign_up
			provider:              provider.id()
			verifier:              verifier
			callback_url:          callback
			anonymous_user_id:     if source := a.anonymous_link_session {
				source.user.id
			} else {
				''
			}
		})
		expires_at:        a.config.clock() + 600
		expires_at_millis: a.clock_millis() + 600000
	})!
	mut response := Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"redirect":${!p.disable_redirect},"url":${json.encode(url)}}'
	}
	if !p.disable_redirect { response = with_header(response, 'location', url) }
	return a.oauth_cookie(response, state, false)
}

fn (mut a Auth) finish_oauth(req Request, provider_id string) !Response {
	provider := a.oauth_provider(provider_id)!
	u := urllib.parse(req.url)!
	state := u.query().get('state') or { return fail(400, 'INVALID_STATE', 'Invalid OAuth state') }
	if state.len != 64 { return fail(400, 'INVALID_STATE', 'Invalid OAuth state') }
	mut bound := false
	for item in req.headers['cookie'].split(';') {
		name, raw := item.trim_space().split_once('=') or { continue }
		if name == a.oauth_cookie_name() {
			value := urllib.path_unescape(raw) or { continue }
			cookie_state := a.verify_cookie(value) or { continue }
			bound = hmac.equal(cookie_state.bytes(), state.bytes())
		}
	}
	if !bound { return fail(403, 'STATE_MISMATCH', 'OAuth state does not match this browser') }
	record := (a.storage.verification(digest(state))!).value or {
		return fail(400, 'INVALID_STATE', 'Invalid OAuth state')
	}

	if record.identifier != 'oauth-state' || verification_expiry_millis(record) < a.clock_millis() {
		return fail(400, 'INVALID_STATE', 'Invalid OAuth state')
	}
	stored := json.decode(OAuthState, record.value)!
	if stored.provider != provider_id { return fail(400, 'INVALID_STATE', 'Invalid OAuth state') }
	a.check_redirect(stored.callback_url, 'callbackURL')!
	a.restore_anonymous_oauth_source(stored.anonymous_user_id)!
	code := u.query().get('code') or {
		return fail(400, 'INVALID_CODE', 'Missing authorization code')
	}
	if code == '' || code.len > 4096 {
		return fail(400, 'INVALID_CODE', 'Invalid authorization code')
	}
	redirect_uri := a.base_url().trim_right('/') + a.config.base_path + '/callback/' + provider_id
	identity := if provider is GenericOAuthProvider {
		provider.exchange_bound(code, stored.verifier, redirect_uri, stored.nonce) or {
			return a.generic_oauth_error(stored, record.id, err)
		}
	} else {
		provider.exchange(code, stored.verifier, redirect_uri)!
	}
	allowed_signup := if provider is GenericOAuthProvider {
		provider.sign_up_allowed(stored.request_sign_up)
	} else {
		true
	}
	account := a.oauth_identity_account_with_signup(identity, provider_id,

		provider !is GoogleProvider && provider !is GenericOAuthProvider, allowed_signup) or {
		if provider is GenericOAuthProvider { return a.generic_oauth_error(stored, record.id, err) }
		return err
	}
	a.remove_verification(record.id)!
	session := a.make_session(account.user.id, RequestContext{ headers: req.headers }, true)!
	mut response := Response{
		status:  302
		headers: [
			Header{'location', if account.new_user && stored.new_user_callback_url != '' {
				stored.new_user_callback_url
			} else {
				stored.callback_url
			}},
		]
	}
	if a.config.store_account_cookie {
		response = a.set_account_cookie(response, json.encode(account.account))!
	}
	response =
		a.set_session_cookies(response, SessionResult{ session: session, user: account.user })!
	return a.oauth_cookie(response, '', true)
}

fn (mut a Auth) generic_oauth_error(stored OAuthState, record_id string, reason IError) !Response {
	a.remove_verification(record_id)!
	callback := if stored.error_callback_url != '' {
		stored.error_callback_url
	} else {
		a.base_url().trim_right('/') + a.config.base_path + '/error'
	}
	code := if reason is APIError { reason.code.to_lower() } else { 'unable_to_get_user_info' }
	separator := if callback.contains('?') { '&' } else { '?' }
	return a.oauth_cookie(Response{
		status:  302
		headers: [
			Header{'location', callback + separator + 'error=' + urllib.query_escape(code)},
		]
	}, '', true)
}

fn (mut a Auth) oauth_identity_account(identity OAuthIdentity, provider_id string, require_verified bool) !OAuthAccountIdentity {
	return a.oauth_identity_account_with_signup(identity, provider_id, require_verified, true)
}

fn (mut a Auth) oauth_identity_account_with_signup(identity OAuthIdentity, provider_id string, require_verified bool, allow_signup bool) !OAuthAccountIdentity {
	if identity.id == '' || (require_verified && !identity.email_verified) {
		return fail(403, 'EMAIL_NOT_VERIFIED', 'Email not verified')
	}
	email := normalize_email(identity.email)!
	mut user := User{}
	mut selected_account := Account{}
	mut new_user := false
	if account := (a.storage.account_by_provider(provider_id, identity.id)!).value {
		user = (a.storage.user(account.user_id)!).value or {
			return fail(400, 'USER_NOT_FOUND', 'User not found')
		}

		patch := a.oauth_account_patch(identity.tokens, account.scope or { '' })!
		if patch.len > 0 { a.update_account_record(account, json2.Any(patch).json_str())! }
		selected_account = (a.storage.account_by_id(account.id)!).value or {
			return fail(400, 'ACCOUNT_NOT_FOUND', 'Account not found')
		}
	} else {
		if existing := (a.storage.user_by_email(email)!).value {
			if !a.config.account_linking_enabled
				|| provider_id !in a.config.trusted_linking_providers {
				return fail(409, 'ACCOUNT_NOT_LINKED',
					'Sign in to your existing account to link this provider')
			}
			user = existing
		} else {
			if !allow_signup { return fail(403, 'SIGNUP_DISABLED', 'Sign up is disabled') }
			new_user = true
			now := stamp_millis(a.clock_millis())
			user = User{
				additional_fields: a.parse_user_fields(identity.additional_fields,
					map[string]json2.Any{}, true)!
				id:                random_token()!
				email:             email
				email_verified:    identity.email_verified
				name:              identity.name
				image:             identity.image
				created_at:        now
				updated_at:        now
			}
			decision := a.config.validate_user_info(user, UserInfoSource{
				method: 'oauth'
				oauth:  OAuthUserInfoSource{
					provider_id: provider_id
					profile:     identity.profile
				}
			})!
			if decision.error != '' { return fail(403, decision.error, if decision.error_description != '' {
					decision.error_description
				} else {
					decision.error
				})
			 }
			user = a.persist_user(user)!
		}
		base_account := Account{
			id:          random_token()!
			user_id:     user.id
			provider_id: provider_id
			account_id:  identity.id
		}
		patch := a.oauth_account_patch(identity.tokens, '')!
		selected_account = a.persist_account(decode_account(merge_record_json(json.encode(base_account),
			json2.Any(patch).json_str())!)!)!
	}
	if selected_account.account_id != identity.id || selected_account.provider_id != provider_id
		|| selected_account.user_id != user.id {
		return fail(409, 'account_hook_binding_conflict',
			'Account hook changed the selected authentication binding')
	}
	return OAuthAccountIdentity{
		new_user: new_user
		user:     user
		account:  selected_account
	}
}
