module postgres

import db.pg as native

pub const enabled = true

@[heap]
pub struct Connection {
mut:
	native &native.Conn
}

pub fn open(connection_string string) !&Connection {
	mut connection := native.connect_direct_with_conninfo(connection_string)!
	connection.exec("SET TIME ZONE 'UTC'") or {
		connection.close() or {}
		return err
	}
	return &Connection{
		native: connection
	}
}

pub fn (db &Connection) exec(query string) ![]Row {
	return rows(db.native.exec(query)!)
}

pub fn (db &Connection) exec_param(query string, parameter string) ![]Row {
	return rows(db.native.exec_param(query, parameter)!)
}

pub fn (db &Connection) exec_param_many(query string, parameters []string) ![]Row {
	return rows(db.native.exec_param_many(query, parameters)!)
}

pub fn (db &Connection) savepoint(name string) ! {
	db.native.savepoint(name)!
}

pub fn (db &Connection) rollback_to(name string) ! {
	db.native.rollback_to(name)!
}

pub fn (db &Connection) release_savepoint(name string) ! {
	db.native.release_savepoint(name)!
}

pub fn (mut db Connection) close() ! {
	db.native.close()!
}

fn rows(input []native.Row) []Row {
	mut result := []Row{cap: input.len}
	for row in input {
		mut values := []string{cap: row.vals.len}
		for i in 0 .. row.vals.len {
			values << row.val(i)
		}
		result << Row{
			vals: values
		}
	}
	return result
}
