module better_auth

import os
import net.urllib
import sync

@[heap]
pub struct Auth {
	models ModelRegistry
pub:
	config Config
mut:
	operation                 &OperationContext = &OperationContext{}
	production_cookie_default bool
	warned_origin_csrf        bool
	initial_trusted_origins   []string
	storage                   Storage
	secret_config             SymmetricSecret
	mutex                     &sync.Mutex = sync.new_mutex()
	limits                    map[string]RateBucket
	closed                    bool
	secondary                 SecondaryStorage
	transactions_enabled      bool
	oauth_nonce_requirements  map[string]bool
	user_defined_fields       []string
}

pub fn new(input_config Config, storage Storage) !&Auth {
	mut config :=
		resolve_cache_defaults(resolve_plugin_fields(resolve_generic_oauth_config(input_config)!))
	if environment := os.getenv_opt('BETTER_AUTH_TRUSTED_ORIGINS') {
		mut origins := config.trusted_origins.clone()
		origins << environment.split(',').filter(it != '')
		config = Config{
			...config
			trusted_origins: origins
		}
	}
	for plugin in config.plugins {
		if plugin is ValidatingPlugin { plugin.validate()! }
	}
	models := compile_model_registry(config)!
	mut configured_storage := storage
	if mut configured_storage is AdapterModelStorage {
		configured_storage.configure_adapter_models(config.adapter_models)!
	} else if config.adapter_models.len > 0 {
		return error('storage does not support adapter models')
	}
	if mut configured_storage is ConfigurableIDStorage {
		configured_storage.configure_ids(config.id_strategy, config.generate_id != no_id_generator)!
	}
	if mut configured_storage is ConfigurableStorage {
		configured_storage.configure_fields(config.user_fields, config.session_fields)!
	}
	if mut configured_storage is ConfigurableModelStorage {
		configured_storage.configure_model_fields(config.model_fields)!
	}
	initial_trusted_origins := config.trusted_origins_for(RequestContext{})!
	mut secret_config := SymmetricSecret(config.secret)
	if entries := config.secrets {
		secret_config = SymmetricSecret(build_secret_config(entries, config.secret)!)
		for warning in secret_config_warnings(entries) {
			config.log('warn', warning)
		}
		config = Config{
			...config
			secret: entries[0].value
		}
	}
	if config.password_reset_expires_in == 0 { config = Config{
			...config
			password_reset_expires_in: 3600
		} }
	validate_cookie_config(config)!
	url := urllib.parse(config.base_url)!
	if config.base_url != ''
		&& (url.scheme !in ['http', 'https'] || url.host == '' || config.base_url.contains('@')
		|| url.raw_query != '' || url.fragment != '' || url.path !in ['', '/']) {
		return error('base_url must be an HTTP(S) origin')
	}
	if config.secret == '' { return error('secret is required') }
	if config.secret.len < 32 && config.secrets == none {
		config.log('warn',
			'[better-auth] Warning: your secret should be at least 32 characters long for adequate security.')
	}
	if config.cookie_cache.strategy !in ['compact', 'jwt', 'jwe'] || config.cookie_cache.max_age <= 0 || (config.cookie_cache.update_age or {
		0
	}) < 0 {
		return error('unsupported cookie cache strategy or invalid max age')
	}
	if !config.base_path.starts_with('/') || config.base_path.ends_with('/')
		|| config.base_path.contains_any('?#\\ \t\r\n\x00') || config.base_path.starts_with('//') {
		return error('base_path must begin with / and must not end with /')
	}
	if config.session_expires_in <= 0 || config.verification_expires_in <= 0
		|| config.session_update_age < 0 || config.session_fresh_age < 0
		|| config.password_reset_expires_in <= 0 || config.rate_limit_window <= 0
		|| config.rate_limit_max < 0 || config.max_body_bytes < 0 || config.min_password_length < 1
		|| config.max_password_length < config.min_password_length {
		return error('invalid auth limits')
	}
	if config.id_strategy !in ['random', 'uuid'] {
		return error('unsupported persisted ID strategy')
	}
	if config.rate_limit_storage !in ['memory', 'database'] {
		return error('unsupported rate limit storage')
	}
	for name, field in config.user_fields {
		if name in core_user_fields
			|| name in ['additional_fields', '__proto__', 'constructor', 'prototype'] {
			return error('additional user field collides with a reserved name')
		}
		if field.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
			'number[]'] {
			return error('unsupported additional field type')
		}
		if value := field.default_value { validate_field(field, value)! }
	}
	for name, field in config.session_fields {
		if name in core_session_fields
			|| name in ['additional_fields', '__proto__', 'constructor', 'prototype'] {
			return error('additional session field collides with a reserved name')
		}
		if field.field_type !in ['string', 'number', 'boolean', 'date', 'json', 'string[]',
			'number[]'] {
			return error('unsupported additional field type')
		}
		if value := field.default_value { validate_field(field, value)! }
	}
	mut ids := map[string]bool{}
	mut provider_ids := map[string]bool{}
	for provider in config.social_providers {
		id := provider.id()
		if id == '' || id.len > 64 || id in provider_ids {
			return error('duplicate or invalid OAuth provider id')
		}
		for c in id.bytes() {
			if !((c >= `a` && c <= `z`) || (c >= `0` && c <= `9`) || c in [`-`, `_`]) {
				return error('invalid OAuth provider id')
			}
		}
		provider_ids[id] = true
	}
	mut routes := map[string]bool{}
	for path, methods in core_routes() {
		for method in methods {
			routes[method + ' ' + path] = true
		}
	}
	for plugin in config.plugins {
		if plugin is JWTPlugin {
			options := normalized_jwt_options(plugin.options)
			if options.custom_signer() && options.remote_url == '' {
				return error('options.jwks.remoteUrl must be set when using options.jwt.sign')
			}
			if options.remote_url != '' && plugin.options.algorithm == '' {
				return error('options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata')
			}
			if options.session_cookie_cache && options.custom_signer() {
				return error('JWT session cookie cache requires locally managed keys and does not support jwt.sign')
			}
			if options.algorithm !in jwt_algorithms
				|| (options.curve != '' && options.curve != jwt_curve(options.algorithm)) {
				return error('unsupported JWT algorithm or curve')
			}
			for extra in options.key_pair_configs {
				if extra.algorithm !in jwt_algorithms
					|| (extra.curve != '' && extra.curve != jwt_curve(extra.algorithm))
					|| extra.modulus_length < 2048 || extra.modulus_length > 8192 {
					return error('unsupported extra JWT key configuration')
				}
			}
			if options.modulus_length < 2048 || options.modulus_length > 8192 {
				return error('invalid RSA modulus length')
			}
			if options.rotation_interval < 0 || options.grace_period < 0 || options.expires_in <= 0 {
				return error('invalid JWT timing options')
			}
			if options.jwks_path == '' || !options.jwks_path.starts_with('/')
				|| options.jwks_path.contains('..') {
				return error('invalid JWKS path')
			}
			if options.session_cookie_cache && config.cookie_cache.strategy != 'jwt' {
				return error('JWT session cookie cache requires the jwt cache strategy')
			}
		}
		if plugin.id() == '' || plugin.id() in ids { return error('duplicate or empty plugin id') }
		ids[plugin.id()] = true
		for endpoint in plugin.endpoints() {
			key := endpoint.method + ' ' + endpoint.path
			if !endpoint.path.starts_with('/') || endpoint.path.starts_with('/callback/')
				|| endpoint.path.starts_with('/reset-password/') || key in routes {
				return error('duplicate or invalid plugin endpoint')
			}
			if endpoint.handler == empty_endpoint {
				return error('plugin endpoint handler is required')
			}
			routes[key] = true
		}
	}
	return &Auth{
		models:                    models
		production_cookie_default: os.getenv('NODE_ENV') == 'production'
		initial_trusted_origins:   initial_trusted_origins
		user_defined_fields:       input_config.user_fields.keys()
		config:                    config
		secret_config:             secret_config
		transactions_enabled:      config.database_transactions
		storage:                   storage
		secondary:                 config.secondary_storage
	}
}

pub fn (mut a Auth) close() ! {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed { return }
	a.storage.close()!
	a.closed = true
}

pub fn (mut a Auth) set_adapter_transactions(enabled bool) ! {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.operation.attempt.transaction.active {
		return error('cannot change adapter transactions during an operation')
	}
	a.transactions_enabled = enabled
}
