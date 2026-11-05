module sqlite

fn test_driver_binding_transaction_rollback_and_disabled_mode() ! {
	$if sqlite ? {
		mut connection := open(':memory:')!
		defer { connection.close() or {} }
		connection.exec('CREATE TABLE records (id TEXT PRIMARY KEY, value TEXT)')!
		connection.exec_param2('INSERT INTO records VALUES (?,?)', 'x', "quoted ' value ✓")!
		row := connection.exec_param('SELECT value FROM records WHERE id=?', 'x')!
		assert row[0].val(0) == "quoted ' value ✓"
		connection.exec('BEGIN')!
		connection.exec_param('DELETE FROM records WHERE id=?', 'x')!
		connection.exec('ROLLBACK')!
		assert connection.q_int('SELECT count(*) FROM records')! == 1
	} $else {
		mut rejected := false
		open(':memory:') or {
			assert err.msg().contains('-d sqlite')
			rejected = true
		}
		assert rejected
	}
}
