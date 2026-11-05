module better_auth

import json
import net.urllib
import time

// Providers can add logout support independently of their sign-in implementation.
pub interface OAuthLogoutProvider {
	id() string
	end_session_url(string, string, string, string) !Lookup[string]
}

// The generic provider's explicit endpoint configuration. Discovery and generic
// OAuth sign-in/token exchange are separate capabilities, not supplied by this type.
@[heap]
pub struct GenericOAuthLogoutProvider {
pub:
	provider_id              string @[json: providerId]
	client_id                string @[json: clientId]
	end_session_endpoint     string @[json: endSessionEndpoint]
	post_logout_redirect_uri string @[json: postLogoutRedirectURI]
	disable_provider_logout  bool   @[json: disableProviderLogout]
}

pub fn (p GenericOAuthLogoutProvider) id() string {
	return p.provider_id
}

pub fn (p GenericOAuthLogoutProvider) end_session_url(id_token string, redirect_uri string, state string, base_url string) !Lookup[string] {
	if p.disable_provider_logout || p.end_session_endpoint == '' { return Lookup[string]{} }
	mut url := urllib.parse(p.end_session_endpoint) or { return Lookup[string]{} }
	if url.scheme == '' { return Lookup[string]{} }
	mut query := url.query()
	if id_token != '' { query.set('id_token_hint', id_token) }
	configured_redirect := if redirect_uri != '' { redirect_uri } else { p.post_logout_redirect_uri }
	if configured_redirect != '' {
		base := urllib.parse(base_url)!
		resolved := base.parse(configured_redirect)!
		query.set('post_logout_redirect_uri', resolved.str())
		query.set('client_id', p.client_id)
		if state != '' { query.set('state', state) }
	} else if id_token == '' {
		query.set('client_id', p.client_id)
	}
	url.raw_query = query.encode()
	return Lookup[string]{
		value: url.str()
	}
}

fn (mut a Auth) provider_logout(user_id string, p Payload) !Lookup[string] {
	mut accounts := []Account{}
	if encoded := (a.intercept_internal('findAccounts', '[${json.encode(user_id)}]')!).value {
		accounts = json.decode([]Account, encoded)!
	} else {
		accounts = a.storage.accounts(user_id)!
	}
	// RFC3339 values can have different fractional precision: compare timestamps.
	for i in 1 .. accounts.len {
		mut j := i
		for j > 0
			&& time.parse_rfc3339(accounts[j].updated_at)!.unix_milli() > time.parse_rfc3339(accounts[j - 1].updated_at)!.unix_milli() {
			accounts[j], accounts[j - 1] = accounts[j - 1], accounts[j]
			j--
		}
	}
	mut seen := map[string]bool{}
	for account in accounts {
		if account.provider_id in seen { continue
		 }
		seen[account.provider_id] = true
		for provider in a.config.logout_providers {
			if provider.id() != account.provider_id { continue
			 }
			result := provider.end_session_url(account.id_token, p.callback_url, p.state,
				a.base_url()) or {
				a.config.log('error',
					'Failed to create logout URL for provider "${account.provider_id}"')
				continue
			}
			if result.value != none { return result }
		}
	}
	return Lookup[string]{}
}

fn (mut a Auth) sign_out_request(p Payload, ctx RequestContext) !Response {
	mut current := Lookup[SessionResult]{}
	if token := a.context_token(ctx) {
		current = a.find_session_record(token) or {
			a.config.log('error', 'Failed to read session from database')
			Lookup[SessionResult]{}
		}
		a.remove_session(token) or {
			a.config.log('error', 'Failed to delete session from database')
		}
	}
	// Local sign-out must clear cookies even when persistence or after-hooks fail.
	a.commit_transaction() or {
		a.rollback_transaction()
		a.config.log('error', 'Failed to delete session from database')
	}
	if session := current.value {
		result := a.provider_logout(session.user.id, p) or {
			a.config.log('error', 'Failed to create provider logout URL')
			Lookup[string]{}
		}
		if url := result.value {
			mut response := Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"success":true,"redirect":${!p.disable_redirect},"url":${json.encode(url)}}'
			}
			if !p.disable_redirect { response = with_header(response, 'location', url) }
			return a.clear_cookie(response)
		}
	}
	return a.clear_cookie(json_response({
		'success': true
	}))
}
