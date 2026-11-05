module better_auth

import time
import x.json2

pub struct Config {
pub:
	adapter_models                    map[string]AdapterModel
	app_name                          string              = 'Better Auth'
	id_strategy                       string              = 'random'
	generate_id                       fn (string) !string = no_id_generator
	verification                      VerificationOptions
	cookie_cache                      CookieCacheConfig
	stateless_sessions                bool
	base_url                          string = 'http://localhost:3000'
	base_path                         string = '/api/auth'
	secret                            string
	secrets                           ?[]SecretEntry
	trusted_origins                   []string
	disable_csrf_check                ?bool
	disable_origin_check              bool
	skip_origin_check_paths           []string
	trusted_origins_for               fn (RequestContext) ![]string = no_trusted_origins
	email_and_password                bool = true
	disable_email_sign_up             bool
	generic_oauth                     []GenericOAuthConfig
	trusted_linking_providers         []string
	account_linking_enabled           bool = true
	update_user_info_on_link          bool
	require_local_email_verified      bool = true
	disable_implicit_linking          bool
	require_email_verification        bool
	send_verification_on_sign_up      ?bool
	send_verification_on_sign_in      bool
	auto_sign_in                      bool = true
	min_password_length               int  = 8
	max_password_length               int  = 128
	session_expires_in                i64  = 604800
	session_update_age                i64  = 86400
	session_fresh_age                 i64  = 86400
	defer_session_refresh             bool
	disable_session_refresh           bool
	password_reset_expires_in         i64 = 3600
	revoke_sessions_on_password_reset bool
	on_password_reset                 fn (User) ! = discard_password_reset
	database_transactions             bool        = true
	verification_delivery_enabled     ?bool
	auto_sign_in_after_verification   bool
	before_email_verification         fn (User, RequestContext) ! = discard_verification_callback
	after_email_verification          fn (User, RequestContext) ! = discard_verification_callback
	delete_user_enabled               bool
	delete_token_expires_in           i64                         = 86400
	send_delete_verification          fn (EmailMessage) !         = discard_email
	before_delete                     fn (User, RequestContext) ! = discard_verification_callback
	after_delete                      fn (User, RequestContext) ! = discard_verification_callback
	change_email_enabled              bool
	update_email_without_verification bool
	send_change_email_confirmation    fn (EmailMessage) ! = discard_email
	verification_expires_in           i64                 = 3600
	rate_limit_max                    int                 = 100
	rate_limit_window                 i64                 = 60
	rate_limit_storage                string              = 'memory'
	rate_limit_rules                  map[string]RateLimitRule
	max_body_bytes                    int
	password_hasher                   PasswordHasher      = ScryptHasher{}
	clock                             fn () i64           = time.unix_now
	clock_millis                      fn () i64           = no_millisecond_clock
	send_email                        fn (EmailMessage) ! = discard_email
	cookie_names                      map[string]string
	default_cookie_attributes         map[string]json2.Any
	cookie_attributes                 map[string]map[string]json2.Any
	cookie_prefix                     string = 'better-auth'
	secure_cookies                    ?bool
	cross_subdomain_cookies           bool
	cookie_domain                     string
	trust_proxy_origin_headers        bool
	trust_proxy_ip_headers            bool
	plugins                           []Plugin
	social_providers                  []OAuthProvider
	store_account_cookie              bool
	account_cookie_bind_user          ?bool
	encrypt_oauth_tokens              bool
	logout_providers                  []OAuthLogoutProvider
	user_fields                       map[string]AdditionalField
	session_fields                    map[string]AdditionalField
	model_fields                      map[string]map[string]AdditionalField
	log                               fn (string, string) = discard_log
	validate_user_info                fn (User, UserInfoSource) !ValidationDecision = accept_user_info
	on_existing_user_sign_up          fn (User) !                   = discard_existing_user
	custom_synthetic_user             fn (SyntheticUserInput) !User = default_synthetic_user
	secondary_storage                 SecondaryStorage              = NoSecondaryStorage{}
	store_session_in_database         bool
	preserve_session_in_database      bool
	database_hooks                    []DatabaseHook
	before_commit                     fn (mut EndpointContext) ! = allow_commit
	internal_interceptor              fn (mut EndpointContext, InternalOperation) !Interception = pass_internal_operation
}
