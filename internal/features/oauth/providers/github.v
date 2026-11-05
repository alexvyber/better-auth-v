module better_auth

import json
import net.http
import net.urllib
import time
import x.json2

pub struct GitHubProvider {
pub:
	client_id     string
	client_secret string
}

pub fn (_ GitHubProvider) id() string {
	return 'github'
}

pub fn (_ GitHubProvider) name() string {
	return 'GitHub'
}

pub fn (p GitHubProvider) authorization_url(state string, challenge string, redirect_uri string) !string {
	if p.client_id == '' || p.client_secret == '' {
		return error('GitHub client credentials are required')
	}
	mut query := urllib.new_values()
	for key, value in {
		'client_id':             p.client_id
		'redirect_uri':          redirect_uri
		'scope':                 'read:user user:email'
		'state':                 state
		'code_challenge':        challenge
		'code_challenge_method': 'S256'
	} {
		query.set(key, value)
	}
	return 'https://github.com/login/oauth/authorize?' + query.encode()
}

struct GitHubToken {
	access_token string
}

struct GitHubUser {
	id         i64
	login      string
	name       string
	avatar_url string
}

struct GitHubEmail {
	email    string
	primary  bool
	verified bool
}

pub fn (p GitHubProvider) exchange(code string, verifier string, redirect_uri string) !OAuthIdentity {
	mut values := urllib.new_values()
	for key, value in {
		'client_id':     p.client_id
		'client_secret': p.client_secret
		'code':          code
		'redirect_uri':  redirect_uri
		'code_verifier': verifier
	} {
		values.set(key, value)
	}
	mut header := http.new_header_from_map({
		http.CommonHeader.accept: 'application/json'
		.content_type:            'application/x-www-form-urlencoded'
	})
	response := http.fetch(
		url:                  'https://github.com/login/oauth/access_token'
		method:               .post
		header:               header
		data:                 values.encode()
		validate:             true
		allow_redirect:       false
		read_timeout:         10 * time.second
		max_retries:          0
		stop_receiving_limit: 1048576
	)!
	if response.status_code != 200 {
		return fail(502, 'OAUTH_TOKEN_ERROR', 'Provider token exchange failed')
	}
	token := json.decode(GitHubToken, response.body)!
	tokens := parse_oauth_tokens(response.body, time.now().unix_milli())!
	if token.access_token == '' {
		return fail(400, 'OAUTH_TOKEN_ERROR', 'Provider rejected the authorization code')
	}
	header.set(.authorization, 'Bearer ' + token.access_token)
	header.set(.content_type, 'application/json')
	profile_response := http.fetch(
		url:                  'https://api.github.com/user'
		header:               header
		user_agent:           'better-auth-v'
		validate:             true
		allow_redirect:       false
		read_timeout:         10 * time.second
		max_retries:          0
		stop_receiving_limit: 1048576
	)!
	if profile_response.status_code != 200 {
		return fail(502, 'OAUTH_PROFILE_ERROR', 'Failed to get provider profile')
	}
	profile := json.decode(GitHubUser, profile_response.body)!
	email_response := http.fetch(
		url:                  'https://api.github.com/user/emails'
		header:               header
		user_agent:           'better-auth-v'
		validate:             true
		allow_redirect:       false
		read_timeout:         10 * time.second
		max_retries:          0
		stop_receiving_limit: 1048576
	)!
	if email_response.status_code != 200 {
		return fail(502, 'OAUTH_PROFILE_ERROR', 'Failed to get verified provider email')
	}
	emails := json.decode([]GitHubEmail, email_response.body)!
	mut selected := ''
	for email in emails {
		if email.verified && (selected == '' || email.primary) { selected = email.email }
		if email.verified && email.primary { break
		 }
	}
	if selected == '' || profile.id <= 0 {
		return fail(403, 'EMAIL_NOT_VERIFIED', 'Email not verified')
	}
	return OAuthIdentity{
		tokens:         tokens
		profile:        json2.decode[map[string]json2.Any](profile_response.body)!
		id:             profile.id.str()
		email:          selected
		email_verified: true
		name:           if profile.name == '' { profile.login } else { profile.name }
		image:          profile.avatar_url
	}
}
