module better_auth

import better_auth.adapter
import json
import math
import x.json2

// Native conditional writes, independent of ordinary adapter update semantics.
pub interface AtomicAdapterStorage {
mut:
	compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool
}

fn adapter_number(value json2.Any) bool {
	return value is f64 || value is f32 || value is i64 || value is int || value is i32
		|| value is i16 || value is i8 || value is u64 || value is u32 || value is u16
		|| value is u8
}

fn (c &EndpointContext) adapter_mutation_field(model string, field string) !AdditionalField {
	c.adapter_field(model, field)!
	if field == 'id' { return error('adapter IDs are immutable') }
	fields := if model == 'user' {
		c.auth.config.user_fields
	} else {
		(c.auth.config.adapter_models[model] or { AdapterModel{} }).fields
	}
	if definition := fields[field] { return definition }
	return AdditionalField{
		field_type: if c.adapter_date(model, field) {
			'date'
		} else if field == 'emailVerified' {
			'boolean'
		} else {
			'string'
		}
		required:   field != 'image'
	}
}

fn (mut c EndpointContext) adapter_increment(query adapter.Increment) !string {
	model := query.model
	if model != 'user' && model !in c.auth.config.adapter_models {
		return error('atomic increments support users and configured adapter models')
	}
	where := query.where
	c.adapter_filters(model, where)!
	deltas := query.deltas.clone()
	set := query.set.clone()
	for field, delta in deltas {
		definition := c.adapter_mutation_field(model, field)!
		if definition.field_type != 'number' || !adapter_number(delta) || math.is_nan(delta.f64())
			|| math.is_inf(delta.f64(), 0) {
			return error('increment requires a finite numeric field and delta')
		}
	}
	for field, value in set {
		definition := c.adapter_mutation_field(model, field)!
		if field !in deltas { validate_field(definition, value)! }
	}
	mut storage := c.auth.storage
	if mut storage is AtomicAdapterStorage {
		for _ in 0 .. 16 {
			mut selected := map[string]json2.Any{}
			for candidate in c.adapter_candidates(model, where)! {
				if c.adapter_matches(model, candidate.as_map(), where)! {
					selected = candidate.as_map().clone()
					break
				}
			}
			if selected.len == 0 { return 'null' }
			mut patch := set.clone()
			for field, delta in deltas {
				previous := selected[field] or { json2.Any(json2.Null{}) }
				if previous !is json2.Null && !adapter_number(previous) {
					return error('stored counter is not numeric')
				}
				before := if previous is json2.Null { f64(0) } else { previous.f64() }
				after := before + delta.f64()
				if math.is_nan(after) || math.is_inf(after, 0)
					|| (delta.f64() != 0 && before == after) {
					return error('counter increment cannot be represented safely')
				}
				patch[field] = after
			}
			mut updated := selected.clone()
			mut changed := false
			for field, value in patch {
				validate_field(c.adapter_mutation_field(model, field)!, value)!
				previous := selected[field] or { json2.Any(json2.Null{}) }
				if !c.adapter_equivalent(model, field, previous, value, false)! { changed = true }
				updated[field] = value
			}
			if !changed { return json2.Any(selected).json_str() }
			if model in c.auth.config.adapter_models { c.adapter_validate_model(model, updated)! }
			mut expected := map[string]json2.Any{}
			for clause in where {
				field := clause.field
				expected[field] = selected[field] or { json2.Any(json2.Null{}) }
			}
			for field, _ in patch {
				expected[field] = selected[field] or { json2.Any(json2.Null{}) }
			}
			id := (selected['id'] or { return error('atomic adapter row lacks id') }).str()
			if storage.compare_exchange_adapter(model, id, expected, patch)! {
				return json2.Any(updated).json_str()
			}
		}
		return error('atomic adapter contention exhausted; retry the operation')
	}
	return error('storage does not implement atomic adapter mutations')
}

pub fn (mut s MemoryStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	s.check_write()!
	encoded := if model == 'user' {
		if user := (s.user(id)!).value { encode_user(user) } else { return false }
	} else {
		s.records.organizations[model + '|' + id] or { return false }
	}
	mut row := org_json_fields(encoded)!
	for field, value in expected {
		if !adapter_equal(row[field] or { json2.Any(json2.Null{}) }, value, false) { return false }
	}
	for field, value in patch {
		row[field] = value
	}
	if model == 'user' {
		s.update_user(decode_user(json2.Any(row).json_str())!)!
	} else {
		s.adapter_model_write(model, json2.Any(row).json_str(), false)!
	}
	return true
}

pub fn (mut s SQLiteStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	if model == 'user' { s.require_unique_indexes()! }
	table := if model == 'user' {
		sql_identifier('auth_user')
	} else {
		adapter_model_table(s.adapter_models, model)!
	}
	encoded := json2.Any(patch).json_str()
	mut setters := []string{}
	mut parameters := []string{}
	for field, _ in patch {
		path := '$.' + json.encode(field)
		setters << '?,json_extract(?,?)'
		parameters << [path, encoded, path]
	}
	mut assignment := 'data=json_set(data,' + setters.join(',') + ')'
	if model == 'user' && 'email' in patch {
		assignment += ',email=json_extract(?,?)'
		parameters << [encoded, '$.email']
	}
	parameters << id
	mut guard := ['id=?']
	snapshot := json2.Any(expected).json_str()
	for field, _ in expected {
		path := '$.' + json.encode(field)
		guard << 'json_extract(data,?) IS json_extract(?,?)'
		parameters << [path, snapshot, path]
	}
	rows := s.db.exec_param_many('UPDATE ${table} SET ${assignment} WHERE ${guard.join(' AND ')} RETURNING id',
		parameters)!
	return rows.len == 1
}

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

pub fn (mut s MongoStorage) compare_exchange_adapter(model string, id string, expected map[string]json2.Any, patch map[string]json2.Any) !bool {
	mut guard := map[string]BSONValue{}
	for field, value in s.physical(model, expected)! {
		guard[field] = BSONValue({
			'$eq': value
		})
	}
	guard[s.column(model, 'id')] = s.id_value(id)!
	reply := s.command({
		'findAndModify': BSONValue(s.collection(model))
		'query':         BSONValue(guard)
		'update':        BSONValue({
			'$set': BSONValue(s.physical(model, patch)!)
		})
		'new':           BSONValue(true)
	}, 3)!
	value := reply['value'] or { return false }
	return value !is json2.Null
}
