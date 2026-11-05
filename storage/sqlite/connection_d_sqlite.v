module sqlite

import db.sqlite as native

pub const enabled = true

pub struct Connection {
mut:
	native native.DB
}

pub fn open(path string) !Connection {
	mut db := native.connect(path)!
	db.exec('PRAGMA foreign_keys = ON') or {
		db.close() or {}
		return err
	}
	db.busy_timeout(5000)
	return Connection{
		native: db
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

pub fn (db &Connection) q_int(query string) !int {
	return db.native.q_int(query)
}

pub fn (db &Connection) q_string(query string) !string {
	return db.native.q_string(query)
}

pub fn (db &Connection) tables() ![]string {
	return db.native.tables()
}

pub fn (db &Connection) columns(table string) ![]string {
	return db.native.columns(table)
}

pub fn (mut db Connection) close() ! {
	db.native.close()!
}

fn rows(input []native.Row) []Row {
	mut result := []Row{cap: input.len}
	for row in input {
		result << Row{
			vals: row.vals.clone()
		}
	}
	return result
}
