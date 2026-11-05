module sqlite

pub const enabled = false
const disabled_message = 'sqlite support is disabled; compile with -d sqlite'

pub struct Connection {}

pub fn open(_ string) !Connection {
	return error(disabled_message)
}

pub fn (_ &Connection) exec(_ string) ![]Row {
	return error(disabled_message)
}

pub fn (_ &Connection) exec_param(_ string, _ string) ![]Row {
	return error(disabled_message)
}

pub fn (_ &Connection) exec_param_many(_ string, _ []string) ![]Row {
	return error(disabled_message)
}

pub fn (_ &Connection) q_int(_ string) !int {
	return error(disabled_message)
}

pub fn (_ &Connection) q_string(_ string) !string {
	return error(disabled_message)
}

pub fn (_ &Connection) tables() ![]string {
	return error(disabled_message)
}

pub fn (_ &Connection) columns(_ string) ![]string {
	return error(disabled_message)
}

pub fn (mut _ Connection) close() ! {
	return error(disabled_message)
}
