module schema

fn test_logical_schema_owns_names_without_exposing_mutable_storage() {
	assert is_core_model('user')
	assert !is_core_model('custom')
	assert has_core_field('user', 'email')
	assert !has_core_field('user', 'email_address')
	mut fields := core_fields('user')
	fields << 'local_only'
	assert !has_core_field('user', 'local_only')
	assert core_fields('custom').len == 0
	assert core_fields_or_id('custom') == ['id']
	assert core_references().filter(it.source_model == 'session')[0].target_model == 'user'
}
