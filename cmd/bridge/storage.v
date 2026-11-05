module main

import better_auth

fn open_bridge_storage(opts Options, account_fields map[string]string) !better_auth.Storage {
	match opts.storage {
		'memory' {
			return better_auth.Storage(better_auth.open_memory())
		}
		'sqlite' {
			mut storage := better_auth.open_sqlite_with_options(opts.sqlite_path, better_auth.SQLiteOptions{
				account_fields: account_fields
			})!
			if !opts.defer_migrations { storage.migrate()! }
			return better_auth.Storage(storage)
		}
		'postgres' {
			options := opts.postgres or { return error('PostgreSQL options are required') }
			return better_auth.Storage(better_auth.open_postgres(options)!)
		}
		'mongo' {
			options := opts.mongo or { return error('MongoDB options are required') }
			return better_auth.Storage(better_auth.open_mongo(options)!)
		}
		else {
			return error('unsupported storage')
		}
	}
}
