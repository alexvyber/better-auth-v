module better_auth

import os

fn reserve_native_verification(mut auth Auth) !string {
	return auth.with_internal(fn (mut context EndpointContext) !string {
		return context.invoke_internal('reserveVerificationValue',
			'[{"identifier":"cross-connection","value":"guard","expiresAt":"2090-01-01T00:00:00.000Z"}]')
	})
}

fn test_native_verification_reservation_is_shared_between_sqlite_connections() ! {
	path := os.join_path(os.temp_dir(), 'better-auth-reserve-' + random_token()! + '.sqlite')
	defer { os.rm(path) or {} }
	mut first_storage := open_sqlite(path)!
	first_storage.migrate()!
	mut first := new(Config{ secret: 'native-verification-reserve-secret-1234' }, first_storage)!
	defer { first.close() or {} }
	mut second := new(Config{ secret: 'native-verification-reserve-secret-1234' },
		open_sqlite(path)!)!
	defer { second.close() or {} }
	assert reserve_native_verification(mut first)! == 'true'
	assert reserve_native_verification(mut second)! == 'false'
	second.with_internal(fn (mut context EndpointContext) !string {
		context.delete_verification_by_identifier('cross-connection')!
		return 'null'
	})!
	assert reserve_native_verification(mut first)! == 'true'
}
