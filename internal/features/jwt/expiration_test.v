module better_auth

import time

fn test_jwt_expiration_absolute_dates_and_relative_durations() ! {
	assert jwt_expiration(JWTExpiration(f64(0)), 1000)! == 0
	assert jwt_expiration(JWTExpiration(3600.25), 1000)! == 3600.25
	assert jwt_expiration(JWTExpiration(time.unix_milli(1704067200500)), 1000)! == 1704067200
	assert jwt_expiration(JWTExpiration(time.unix_milli(-500)), 1000)! == -1
	for value, expected in {
		'1h':          3600
		'7 days':      604800
		'30 MINUTES':  1800
		'2 months':    5184000
		'1 year':      31557600
		'1h ago':      -3600
		'-1h':         -3600
		'+ 1h':        3600
		'1h from now': 3600
		'0.5s':        1
		'-0.5s':       0
		'-1.5s':       -1
	} {
		assert duration_seconds(value)! == expected, value
		assert jwt_expiration(JWTExpiration(value), 1000)! == 1000 + expected, value
	}
	for invalid in ['', 'invalid', 'abc123', '1', '1ms', '1.5.0s', '.5s', '1.s', '1  hour', '1h ',
		'-1h ago', '+1h from now', '1h\n', '1h\tago', '  1h'] {
		duration_seconds(invalid) or { continue }
		assert false, 'invalid duration accepted: ${invalid}'
	}
}
