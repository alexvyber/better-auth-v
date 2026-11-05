module postgres

pub const enabled = false
const disabled_message = 'postgres support is disabled; compile with -d postgres'

pub struct Connection {}

pub fn open(_ string) !&Connection {
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

pub fn (_ &Connection) savepoint(_ string) ! {
	return error(disabled_message)
}

pub fn (_ &Connection) rollback_to(_ string) ! {
	return error(disabled_message)
}

pub fn (_ &Connection) release_savepoint(_ string) ! {
	return error(disabled_message)
}

pub fn (mut _ Connection) close() ! {
	return error(disabled_message)
}
