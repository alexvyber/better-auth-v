module better_auth

import time
import x.json2

pub struct User {
pub:
	id                string
	name              string
	email             string
	email_verified    bool @[json: 'emailVerified']
	image             ?string
	created_at        string               @[json: 'createdAt']
	updated_at        string               @[json: 'updatedAt']
	additional_fields map[string]json2.Any @[skip]
}

pub struct Account {
pub:
	id                       string
	user_id                  string  @[json: 'userId']
	provider_id              string  @[json: 'providerId']
	account_id               string  @[json: 'accountId']
	password                 string  @[omitempty]
	id_token                 string  @[json: idToken; omitempty]
	access_token             ?string @[json: accessToken]
	refresh_token            ?string @[json: refreshToken]
	access_token_expires_at  ?string @[json: accessTokenExpiresAt]
	refresh_token_expires_at ?string @[json: refreshTokenExpiresAt]
	scope                    ?string
	created_at               string @[json: 'createdAt']
	updated_at               string @[json: 'updatedAt']
}

pub struct Session {
pub:
	persistent        bool = true   @[skip]
	encrypted_token   string @[skip]
	id                string
	user_id           string @[json: 'userId']
	token             string
	expires_at        string               @[json: 'expiresAt']
	created_at        string               @[json: 'createdAt']
	updated_at        string               @[json: 'updatedAt']
	ip_address        string               @[json: 'ipAddress']
	user_agent        string               @[json: 'userAgent']
	additional_fields map[string]json2.Any @[skip]
}

pub struct SessionResult {
pub:
	session       Session
	user          User
	needs_refresh ?bool @[json: 'needsRefresh']
}

pub struct Verification {
pub:
	created_at        string
	updated_at        string
	id                string
	identifier        string
	value             string
	expires_at        i64
	expires_at_millis ?i64
}

pub struct EmailMessage {
pub:
	kind      string
	user      User
	token     string
	url       string
	new_email string   @[json: newEmail]
	request   ?Request @[skip]
}

pub struct RequestContext {
pub:
	request         ?Request
	trusted_origins []string
	origin          string
	headers         map[string]string
}

pub struct SignUpInput {
pub:
	email             string
	password          string
	name              string
	image             ?string
	additional_fields map[string]json2.Any @[skip]
}

pub struct SignInInput {
pub:
	email       string
	password    string
	remember_me bool = true @[json: 'rememberMe']
}

pub struct AuthResult {
pub:
	session  ?Session @[skip]
	redirect bool
	token    ?string
	url      ?string
	user     User
}

pub struct APIError {
pub:
	status  int
	code    string
	message string
}

pub fn (e APIError) msg() string {
	return e.message
}

pub fn (e APIError) code() int {
	return e.status
}

fn fail(status int, code string, message string) IError {
	return APIError{
		status:  status
		code:    code
		message: message
	}
}

pub interface PasswordHasher {
	hash(string) !string
	verify(string, string) !bool
}

// A transaction spans all storage calls until commit or rollback. Auth serializes
// operations per instance; independent instances need independent connections.
pub interface Storage {
mut:
	jwks() ![]Jwk
	create_jwk(Jwk) !
	begin() !
	begin_read() !
	commit() !
	rollback() !
	close() !
	user(string) !Lookup[User]
	user_by_email(string) !Lookup[User]
	users() ![]User
	create_user(User) !
	update_user(User) !
	delete_user(string) !
	account(string, string) !Lookup[Account]
	account_by_provider(string, string) !Lookup[Account]
	accounts(string) ![]Account
	account_by_id(string) !Lookup[Account]
	delete_account(string) !
	create_account(Account) !
	set_password(string, string) !
	update_account(Account) !
	create_session(Session, string) !
	session(string) !Lookup[Session]
	session_by_id(string) !Lookup[Session]
	sessions(string) ![]Session
	update_session(Session) !
	delete_session(string) !
	delete_sessions(string, string) !
	create_verification(Verification) !
	verification(string) !Lookup[Verification]
	verifications() ![]Verification
	delete_verification(string) !
}

pub struct Jwk {
pub:
	id          string
	public_key  string  @[json: 'publicKey']
	private_key string  @[json: 'privateKey']
	created_at  string  @[json: 'createdAt']
	expires_at  ?string @[json: 'expiresAt']
	alg         string
	crv         string
	encrypted   bool
}

pub struct Config {
pub:
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
	account_linking_enabled           bool
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

pub struct SyntheticUserInput {
pub:
	core_fields       User
	additional_fields map[string]json2.Any
	id                string
}

fn default_synthetic_user(input SyntheticUserInput) !User {
	return User{
		...input.core_fields
		id:                input.id
		additional_fields: input.additional_fields
	}
}

pub struct PluginFields {
pub:
	user    map[string]AdditionalField
	session map[string]AdditionalField
}

pub interface SchemaPlugin {
	schema() PluginFields
}

pub interface UserCreationPlugin {
	prepare_user(User) !User
}

pub struct CookieCacheConfig {
pub:
	refresh_cache ?bool
	update_age    ?f64
	enabled       ?bool
	strategy      string
	max_age       f64
	version       string                     = '1'
	version_for   fn (Session, User) !string = default_cache_version @[skip]
}

fn default_cache_version(_ Session, _ User) !string {
	return '1'
}

pub struct InternalOperation {
pub:
	name           string
	arguments_json string
}

pub struct Interception {
pub:
	handled    bool
	value_json string = 'null'
}

fn pass_internal_operation(mut _ EndpointContext, _ InternalOperation) !Interception {
	return Interception{}
}

fn allow_commit(mut _ EndpointContext) ! {}

pub interface SecondaryStorage {
mut:
	get(string) !Lookup[string]
	get_and_delete(string) !Lookup[string]
	set(string, string, i64) !
	delete(string) !
	increment(string, i64) !i64
}

pub interface DatabaseHook {
	run(mut EndpointContext, DatabaseEvent) !HookResult
}

pub struct DatabaseEvent {
pub:
	model     string
	operation string
	phase     string
	data_json string
}

pub struct HookResult {
pub:
	cancel    bool
	data_json ?string
}

pub struct UserInfoSource {
pub:
	action string = 'create-user'
	method string
	oauth  ?OAuthUserInfoSource
}

pub struct OAuthUserInfoSource {
pub:
	provider_id string               @[json: 'providerId']
	profile     map[string]json2.Any @[skip]
}

pub struct ValidationDecision {
pub:
	error             string
	error_description string @[json: 'errorDescription']
}

fn accept_user_info(_ User, _ UserInfoSource) !ValidationDecision {
	return ValidationDecision{}
}

fn discard_existing_user(_ User) ! {}

fn discard_log(_ string, _ string) {}

pub struct LogEvent {
pub:
	level   string
	message string
}

pub struct AdditionalField {
pub:
	field_type    string @[json: 'type']
	required      bool
	input         bool = true
	returned      bool = true
	default_value ?json2.Any @[json: 'defaultValue']
}

fn discard_email(_ EmailMessage) ! {
	return error('email delivery is not configured')
}

// Plugin endpoints use the same HTTP security checks and serialized dispatch as
// core endpoints. Schema migrations remain explicit, owned by the plugin.
// Request hooks run after trust resolution and before serialized storage work.
pub interface RequestHookPlugin {
	on_request(Request) !RequestHookResult
}

pub struct RequestHookResult {
pub:
	request  ?Request
	response ?Response
}

// Trusted server transport state. Never accept prepared contexts from HTTP clients.
pub struct PreparedRequest {
pub:
	request  Request
	context  RequestContext
	direct   bool
	response ?Response
}

pub interface Plugin {
	id() string
	endpoints() []Endpoint
}

pub struct Endpoint {
pub:
	require_session bool
	fresh_session   bool
	path            string
	method          string = 'POST'
	handler         fn (mut EndpointContext, Request) !Response = empty_endpoint
}

fn empty_endpoint(mut _ EndpointContext, _ Request) !Response {
	return fail(501, 'NOT_IMPLEMENTED', 'Endpoint not implemented')
}

// EndpointContext is valid only during its endpoint invocation. These operations
// use the enclosing transaction and must not acquire the Auth mutex recursively.
pub struct EndpointContext {
pub:
	session ?SessionResult
mut:
	auth &Auth
}

pub fn (mut c EndpointContext) get_session(context RequestContext) !Lookup[SessionResult] {
	return c.auth.current_session(context)
}

pub fn (mut c EndpointContext) require_session(context RequestContext, fresh bool) !SessionResult {
	return c.auth.require_session(context, fresh)
}

pub fn (mut c EndpointContext) user(id string) !Lookup[User] {
	return c.auth.storage.user(id)
}

pub fn (mut c EndpointContext) create_session(user_id string, context RequestContext, remember bool) !Session {
	return c.auth.make_session(user_id, context, remember)
}

pub fn (c &EndpointContext) with_session_cookie(response Response, session Session) Response {
	return c.auth.set_cookie(response, session.token, session.persistent)
}

pub struct Request {
pub:
	method  string = 'GET'
	url     string
	headers map[string]string
	body    string
}

pub struct Header {
pub:
	name  string
	value string
}

pub struct Response {
pub:
	status      int = 200
	status_text string
	headers     []Header
	body        string
}

// Keeps storage failures distinct from an absent record.
pub struct Lookup[T] {
pub:
	value ?T
}

fn no_millisecond_clock() i64 {
	return 0
}

fn discard_password_reset(_ User) ! {}

fn discard_verification_callback(_ User, _ RequestContext) ! {}

pub fn (c &EndpointContext) request_context() RequestContext {
	return c.auth.request_context
}
