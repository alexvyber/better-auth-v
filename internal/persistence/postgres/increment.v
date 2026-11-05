module better_auth

import x.json2

pub fn (mut s PostgresStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	fields := s.physical_data(model, patch)
	guard := s.physical_data(model, expected)
	mut conditions := ['t.' + s.column_sql(model, 'id') + '=$2']
	for field, _ in guard {
		conditions << 't.' + sql_identifier(field) + ' IS NOT DISTINCT FROM g.' +
			sql_identifier(field)
	}
	assignments := fields.keys().map(sql_identifier(it)).join(',')
	selected := fields.keys().map('r.' + sql_identifier(it)).join(',')
	rows := s.connection.exec_param_many('UPDATE ${s.table(model)} AS t SET (${assignments})=(SELECT ${selected} FROM jsonb_populate_record(NULL::${s.table(model)},$1::jsonb) r) FROM jsonb_populate_record(NULL::${s.table(model)},$3::jsonb) g WHERE ${conditions.join(' AND ')} RETURNING t.${s.column_sql(model, 'id')}', [
		json2.Any(fields).json_str(),
		id,
		json2.Any(guard).json_str(),
	])!
	return rows.len == 1
}
