module postgres

// Driver-owned rows keep native database types out of auth interfaces.
pub struct Row {
pub:
	vals []string
}

pub fn (row Row) val(index int) string {
	return row.vals[index]
}

// Two-parameter convenience retains the same prepared-statement path.
pub fn (db &Connection) exec_param2(query string, first string, second string) ![]Row {
	return db.exec_param_many(query, [first, second])
}
