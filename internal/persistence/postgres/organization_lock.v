module better_auth

pub fn (mut storage PostgresStorage) lock_organization_mutations() ! {
	if !storage.transaction { return error('organization locking requires a transaction') }
	storage.connection.exec_param('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',

		'better-auth-v:organization:' + storage.table('organization'))!
}
