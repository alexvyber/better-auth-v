module better_auth

fn (storage &PostgresStorage) sql_type(model string, field string) !string {
	if reference := (storage.additional(model)[field] or { AdditionalField{} }).references {
		if reference.field == 'id' { return storage.sql_type(reference.model, 'id') }
	}
	if model_types := storage.options.column_types[model] {
		if explicit := model_types[field] {
			if explicit !in ['text', 'uuid', 'boolean', 'integer', 'bigint', 'double precision',
				'timestamptz', 'jsonb', 'text[]', 'double precision[]'] {
				return error('unsupported PostgreSQL column type')
			}
			return explicit
		}
	}
	if field == 'id' || (field == 'userId' && model in ['session', 'account', 'twoFactor', 'member']) || (field == 'organizationId' && model in ['member', 'invitation', 'organizationRole']) || (model == 'invitation' && field == 'inviterId') { return if storage.options.uuid_ids {
			'uuid'
		} else {
			'text'
		}
	 }
	if storage.is_date(model, field) { return 'timestamptz' }
	if field in ['emailVerified', 'verified'] { return 'boolean' }
	if model == 'twoFactor' && field == 'failedVerificationCount' { return 'integer' }
	if model == 'rateLimit' && field in ['count', 'lastRequest'] { return 'bigint' }
	if extra := storage.additional(model)[field] {
		return match extra.field_type {
			'boolean' { 'boolean' }
			'number' { 'double precision' }
			'json' { 'jsonb' }
			'string[]' { 'text[]' }
			'number[]' { 'double precision[]' }
			else { 'text' }
		}
	}
	return 'text'
}

fn (storage &PostgresStorage) index_name(model string, suffix string) string {
	return sql_identifier('ba_' + model + '_' + suffix + '_' + digest(storage.table(model))[..12])
}

pub fn (mut storage PostgresStorage) migrate() ! {
	storage.begin()!
	mut committed := false
	defer {
		if !committed { storage.rollback() or {} }
	}
	storage.connection.exec_param('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',

		'better-auth-v:migrate:' + storage.options.schema)!
	storage.connection.exec('CREATE SCHEMA IF NOT EXISTS ${sql_identifier(storage.options.schema)}')!
	mut models := ['user', 'session', 'account', 'verification', 'jwks', 'rateLimit', 'twoFactor',
		'organization', 'member', 'invitation', 'organizationRole']
	models << storage.adapter_models.keys()
	for model in models {
		mut definitions := []string{}
		for field in storage.logical_fields(model) {
			kind := storage.sql_type(model, field)!
			mut constraints := ''
			if model in storage.adapter_models && (storage.additional(model)[field] or {
				AdditionalField{}
			}).required {
				constraints += ' NOT NULL'
			}
			if field == 'id' || (model == 'rateLimit' && field == 'key') {
				constraints = ' PRIMARY KEY'
			}
			if field in ['createdAt', 'updatedAt'] && model !in storage.adapter_models {
				constraints += ' NOT NULL DEFAULT CURRENT_TIMESTAMP'
			}
			if model == 'user' && field in ['name', 'email'] { constraints += ' NOT NULL' }
			if model == 'user' && field == 'emailVerified' {
				constraints += ' NOT NULL DEFAULT false'
			}
			if model == 'session' && field in ['token', 'expiresAt', 'userId'] {
				constraints += ' NOT NULL'
			}
			if model == 'account' && field in ['providerId', 'accountId', 'userId'] {
				constraints += ' NOT NULL'
			}
			if model == 'verification' && field in ['identifier', 'value', 'expiresAt'] {
				constraints += ' NOT NULL'
			}
			if model == 'twoFactor' && field in ['userId', 'secret', 'backupCodes'] {
				constraints += ' NOT NULL'
			}
			if model == 'twoFactor' && field == 'verified' { constraints += ' DEFAULT true' }
			if model == 'twoFactor' && field == 'failedVerificationCount' {
				constraints += ' DEFAULT 0'
			}
			if model == 'jwks' && field in ['publicKey', 'privateKey'] { constraints += ' NOT NULL' }
			if model == 'rateLimit' && field in ['count', 'lastRequest'] {
				constraints += ' NOT NULL'
			}
			if field == 'userId' && model in ['session', 'account', 'twoFactor', 'member'] {
				constraints += ' REFERENCES ${storage.table('user')} (${storage.column_sql('user', 'id')}) ON DELETE CASCADE'
			}
			if model == 'organization' && field in ['name', 'slug'] { constraints += ' NOT NULL' }
			if model == 'member' && field in ['userId', 'role'] { constraints += ' NOT NULL' }
			if model == 'invitation' && field in ['email', 'role', 'status', 'expiresAt'] {
				constraints += ' NOT NULL'
			}
			if model == 'organizationRole' && field in ['role', 'permission'] {
				constraints += ' NOT NULL'
			}
			if field == 'organizationId' && model in ['member', 'invitation', 'organizationRole'] {
				constraints += ' NOT NULL REFERENCES ' + storage.table('organization') +
					' (' + storage.column_sql('organization', 'id') + ') ON DELETE CASCADE'
			}
			if model == 'invitation' && field == 'inviterId' {
				constraints += ' NOT NULL REFERENCES ' + storage.table('user') +
					' (' + storage.column_sql('user', 'id') + ') ON DELETE CASCADE'
			}
			definitions << storage.column_sql(model, field) + ' ' + kind + constraints
		}
		storage.connection.exec('CREATE TABLE IF NOT EXISTS ${storage.table(model)} (${definitions.join(',')})')!
		for field, attribute in storage.additional(model) {
			kind := storage.sql_type(model, field)!
			storage.connection.exec('ALTER TABLE ${storage.table(model)} ADD COLUMN IF NOT EXISTS ${storage.column_sql(model,
				field)} ${kind}')!
			if attribute.unique {
				index := storage.index_name(model, 'unique_' + digest(field)[..12])
				storage.connection.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${index} ON ${storage.table(model)} (${storage.column_sql(model,
					field)})')!
			}
		}
	}
	storage.connection.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${storage.index_name('user', 'email')} ON ${storage.table('user')} (${storage.column_sql('user',
		'email')})')!
	storage.connection.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${storage.index_name('session',
		'token')} ON ${storage.table('session')} (${storage.column_sql('session', 'token')})')!
	storage.connection.exec('CREATE UNIQUE INDEX IF NOT EXISTS ${storage.index_name('account',
		'subject')} ON ${storage.table('account')} (${storage.column_sql('account', 'providerId')},${storage.column_sql('account',
		'accountId')})')!
	for model in ['session', 'account', 'twoFactor', 'member'] {
		storage.connection.exec('CREATE INDEX IF NOT EXISTS ${storage.index_name(model, 'user')} ON ${storage.table(model)} (${storage.column_sql(model,
			'userId')})')!
	}
	storage.connection.exec('CREATE INDEX IF NOT EXISTS ${storage.index_name('verification',
		'identifier')} ON ${storage.table('verification')} (${storage.column_sql('verification',
		'identifier')})')!
	storage.connection.exec('CREATE INDEX IF NOT EXISTS ${storage.index_name('rateLimit',
		'last_request')} ON ${storage.table('rateLimit')} (${storage.column_sql('rateLimit',
		'lastRequest')})')!
	for model, fields in {
		'organization':     ['slug']
		'member':           ['organizationId', 'userId']
		'organizationRole': ['organizationId', 'role']
	} {
		columns := fields.map(storage.column_sql(model, it)).join(',')
		storage.connection.exec('CREATE UNIQUE INDEX IF NOT EXISTS ' +
			storage.index_name(model, 'identity') + ' ON ' + storage.table(model) +
			' (' + columns + ')')!
	}
	for model in ['member', 'invitation', 'organizationRole'] {
		storage.connection.exec('CREATE INDEX IF NOT EXISTS ' +
			storage.index_name(model, 'organization') + ' ON ' + storage.table(model) +
			' (' + storage.column_sql(model, 'organizationId') + ')')!
	}
	for model, definition in storage.adapter_models {
		for field, attribute in definition.fields {
			if reference := attribute.references {
				name := 'ba_ref_' + digest(storage.table(model) + field)[..24]
				if (storage.connection.exec_param2('SELECT 1 FROM pg_constraint WHERE conname=$1 AND conrelid=$2::regclass',
					name, storage.table(model))!).len == 0 {
					storage.connection.exec('ALTER TABLE ${storage.table(model)} ADD CONSTRAINT ${sql_identifier(name)} FOREIGN KEY (${storage.column_sql(model,
						field)}) REFERENCES ${storage.table(reference.model)} (${storage.column_sql(reference.model,
						reference.field)}) ON DELETE CASCADE')!
				}
			}
		}
	}
	storage.commit()!
	committed = true
}

pub fn (mut storage PostgresStorage) consume_rate_limit(input RateLimitInput) !RateLimitDecision {
	table := storage.table('rateLimit')
	key := storage.column_sql('rateLimit', 'key')
	count := storage.column_sql('rateLimit', 'count')
	last := storage.column_sql('rateLimit', 'lastRequest')
	query := 'INSERT INTO ${table} AS existing (${key},${count},${last}) VALUES ($1,1,$2::bigint) ON CONFLICT (${key}) DO UPDATE SET ${count}=CASE WHEN $2::bigint-existing.${last} >= $3::bigint THEN 1 ELSE existing.${count}+1 END, ${last}=$2::bigint WHERE $2::bigint-existing.${last} >= $3::bigint OR existing.${count} < $4::bigint RETURNING ${count},${last}'
	rows := storage.connection.exec_param_many(query, [input.key, input.now.str(),
		(input.window * 1000).str(), input.max.str()])!
	if rows.len > 0 {
		if rows[0].val(0) == '1' {
			storage.connection.exec_param('DELETE FROM ${table} WHERE ${last} < $1::bigint',
				input.prune_before.str())!
		}
		return RateLimitDecision{
			allowed: true
			next:    RateLimitRecord{
				key:          input.key
				count:        rows[0].val(0).i64()
				last_request: rows[0].val(1).i64()
			}
		}
	}
	current := storage.connection.exec_param('SELECT ${count},${last} FROM ${table} WHERE ${key}=$1',
		input.key)!
	if current.len == 0 { return error('PostgreSQL rate limit row disappeared') }
	return decide_rate_limit(RateLimitRecord{
		key:          input.key
		count:        current[0].val(0).i64()
		last_request: current[0].val(1).i64()
	}, input)
}
