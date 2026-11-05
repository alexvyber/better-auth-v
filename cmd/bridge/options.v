module main

import better_auth

struct Options {
	sqlite_path                       string = ':memory:'
	postgres                          ?better_auth.PostgresOptions
	mongo                             ?better_auth.MongoOptions
	id_strategy                       string = 'random'
	custom_id_generator               bool
	redis_tcp                         ?better_auth.RedisTCPOptions
	redis_key_prefix                  string = 'better-auth:'
	generic_oauth                     []better_auth.GenericOAuthConfig
	generic_callbacks                 map[string][]string
	account_linking_enabled           bool = true
	update_user_info_on_link          bool
	require_local_email_verified      bool = true
	disable_implicit_linking          bool
	trusted_linking_providers         []string
	disable_email_sign_up             bool
	app_name                          string = 'Better Auth'
	two_factor_callbacks              []string
	two_factor                        ?better_auth.TwoFactorOptions
	anonymous                         ?better_auth.AnonymousOptions
	anonymous_callbacks               []string
	email_otp                         ?better_auth.EmailOTPOptions
	email_otp_callbacks               []string
	verification_options              better_auth.VerificationOptions
	verification_hash_callback        bool
	one_time_token                    ?better_auth.OneTimeTokenOptions
	ott_generate_callback             bool
	ott_hash_callback                 bool
	custom_jwk_store                  bool
	admin_schema                      bool
	admin                             ?better_auth.AdminOptions
	admin_banned_callback             bool
	admin_default_role                string = 'user'
	open_api                          ?better_auth.OpenAPIOptions
	organization_schema               bool
	organization                      ?better_auth.OrganizationOptions
	organization_fields_json          map[string]string
	adapter_model_fields_json         map[string]string
	adapter_model_names               map[string]string
	organization_hooks                []string
	organization_invitation_limit     bool
	organization_invitation_email     bool
	organization_creation_callback    bool
	organization_teams                bool
	logout_providers                  []better_auth.GenericOAuthLogoutProvider
	google_profile_callback           bool
	google_provider                   ?better_auth.GoogleProvider
	store_account_cookie              bool
	account_cookie_bind_user          ?bool
	encrypt_oauth_tokens              bool
	endpoint_plugins                  []RemoteEndpointPlugin
	jwt_plugin                        bool
	jwt_expiration_json               string
	jwt_options                       better_auth.JWTOptions
	defer_migrations                  bool
	storage                           string = 'sqlite'
	stateless_sessions                bool
	cookie_cache                      better_auth.CookieCacheConfig
	base_url                          string = 'http://localhost:3000'
	base_path                         string = '/api/auth'
	secrets_json                      string
	secret                            string = 'better-auth-test-secret-at-least-32-bytes'
	disable_csrf_check                ?bool
	disable_origin_check              bool
	skip_origin_check_paths           []string
	cookie_names                      map[string]string
	default_cookie_attributes_json    string = '{}'
	cookie_attributes_json            string = '{}'
	cookie_prefix                     string = 'better-auth'
	secure_cookies                    ?bool
	cross_subdomain_cookies           bool
	cookie_domain                     string
	trusted_origins                   []string
	verification_delivery_enabled     bool
	auto_sign_in_after_verification   bool
	delete_user_enabled               bool
	delete_token_expires_in           i64 = 86400
	change_email_enabled              bool
	update_email_without_verification bool
	require_email_verification        bool
	send_verification_on_sign_up      ?bool
	send_verification_on_sign_in      bool
	auto_sign_in                      bool = true
	email_and_password                bool = true
	min_password_length               int  = 8
	max_password_length               int  = 128
	session_expires_in                i64  = 604800
	session_update_age                i64  = 86400
	session_fresh_age                 i64  = 86400
	defer_session_refresh             bool
	disable_session_refresh           bool
	verification_expires_in           i64 = 3600
	rate_limit_max                    int
	rate_limit_window                 i64    = 60
	rate_limit_storage                string = 'memory'
	rate_limit_rules                  map[string]better_auth.RateLimitRule
	max_body_bytes                    int
	password_reset_expires_in         i64 = 3600
	revoke_sessions_on_password_reset bool
	real_passwords                    bool
	fail_delivery                     bool
	magic_link                        bool
	trust_proxy_origin_headers        bool
	field_callbacks                   []string
	user_fields_json                  string = '{}'
	session_fields_json               string = '{}'
	callback_methods                  []string
	account_fields_json               string = '{}'
	remote_passwords                  bool
	secondary_storage                 bool
	store_session_in_database         bool
	preserve_session_in_database      bool
}
