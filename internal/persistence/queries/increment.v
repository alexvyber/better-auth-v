module better_auth

import better_auth.adapter
import math
import x.json2

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
