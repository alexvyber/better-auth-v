module better_auth

import x.json2
import better_auth.adapter

// Portable trusted adapter operations. The storage interfaces perform physical
// I/O; query evaluation stays native and uses logical schema names. Scan-based
// execution is deliberately explicit until individual adapters push queries down.
fn (c &EndpointContext) adapter_field(model string, field string) ! {
	if model !in ['user', 'session', 'account', 'verification', 'organization', 'member', 'invitation', 'organizationRole']
		&& model !in c.auth.config.adapter_models {
		return error('unsupported adapter model')
	}
	c.auth.models.require_field(model, field)!
}

fn (c &EndpointContext) adapter_date(model string, field string) bool {
	if field in ['createdAt', 'updatedAt', 'expiresAt', 'accessTokenExpiresAt',
		'refreshTokenExpiresAt'] {
		return true
	}
	fields := if model == 'user' {
		c.auth.config.user_fields
	} else if model == 'session' {
		c.auth.config.session_fields
	} else {
		(c.auth.config.adapter_models[model] or { AdapterModel{} }).fields
	}
	return (fields[field] or { AdditionalField{} }).field_type == 'date'
}

fn adapter_equal(a json2.Any, b json2.Any, insensitive bool) bool {
	if adapter_number(a) && adapter_number(b) { return a.f64() == b.f64() }
	if insensitive && a is string && b is string { return a.str().to_lower() == b.str().to_lower() }
	return a.json_str() == b.json_str()
}

fn (c &EndpointContext) adapter_equivalent(model string, field string, a json2.Any, b json2.Any, insensitive bool) !bool {
	if c.adapter_date(model, field) && a is string && b is string {
		return adapter_compare(a, b, true)! == 0
	}
	return adapter_equal(a, b, insensitive)
}

fn adapter_compare(a json2.Any, b json2.Any, date bool) !int {
	if a is json2.Null { return if b is json2.Null { 0 } else { -1 }
	 }
	if b is json2.Null { return 1 }
	if date {
		av := epoch_millis(a.str())!
		bv := epoch_millis(b.str())!
		return if av < bv {
			-1
		} else if av > bv {
			1
		} else {
			0
		}
	}
	if a is string && b is string { return if a.str() < b.str() {
			-1
		} else if a.str() > b.str() {
			1
		} else {
			0
		}
	 }
	av := a.f64()
	bv := b.f64()
	return if av < bv {
		-1
	} else if av > bv {
		1
	} else {
		0
	}
}

fn (c &EndpointContext) adapter_filters(model string, where []adapter.Predicate) ! {
	c.adapter_field(model, 'id')!
	for predicate in where {
		c.adapter_field(model, predicate.field)!
	}
}

fn (c &EndpointContext) adapter_matches(model string, record map[string]json2.Any, where []adapter.Predicate) !bool {
	mut and_match := true
	mut or_match := false
	mut has_or := false
	for filter in where {
		field := filter.field
		a := record[field] or { json2.Any(json2.Null{}) }
		b := filter.value
		op := filter.operator
		insensitive := filter.mode == .insensitive
		mut matches := false
		if op in [.inside, .not_in] {
			for item in b.as_array() {
				if c.adapter_equivalent(model, field, a, item, insensitive)! {
					matches = true
					break
				}
			}
			if op == .not_in { matches = !matches }
		} else if op in [.eq, .ne] {
			matches = c.adapter_equivalent(model, field, a, b, insensitive)!
			if op == .ne { matches = !matches }
		} else if a !is json2.Null && b !is json2.Null {
			if op in [.contains, .starts_with, .ends_with] {
				if a is string {
					av := if insensitive { a.str().to_lower() } else { a.str() }
					bv := if insensitive { b.str().to_lower() } else { b.str() }
					matches = match op {
						.contains { av.contains(bv) }
						.starts_with { av.starts_with(bv) }
						else { av.ends_with(bv) }
					}
				}
			} else {
				comparison := adapter_compare(a, b, c.adapter_date(model, field))!
				matches = match op {
					.gt { comparison > 0 }
					.gte { comparison >= 0 }
					.lt { comparison < 0 }
					else { comparison <= 0 }
				}
			}
		}
		if filter.connector == .or_group {
			has_or = true
			or_match = or_match || matches
		} else {
			and_match = and_match && matches
		}
	}
	return and_match && (!has_or || or_match)
}

fn (mut c EndpointContext) adapter_rows(model string) ![]json2.Any {
	mut rows := []json2.Any{}
	match model {
		'user' {
			for row in c.auth.storage.users()! {
				rows << json2.decode[json2.Any](encode_user(row))!
			}
		}
		'account' {
			for row in c.auth.storage.accounts('')! {
				rows << json2.decode[json2.Any](encode_account(row))!
			}
		}
		'session' {
			for user in c.auth.storage.users()! {
				for row in c.auth.storage.sessions(user.id)! {
					token := if row.token != '' {
						row.token
					} else {
						c.auth.unseal_session_token(row)!
					}
					rows << json2.decode[json2.Any](encode_session(Session{ ...row, token: token }))!
				}
			}
		}
		'verification' {
			for row in c.auth.storage.verifications()! {
				rows << json2.decode[json2.Any](encode_verification(row))!
			}
		}
		else {
			mut storage := c.auth.storage
			if model in organization_models {
				if mut storage is OrganizationStorage {
					for row in storage.organization_rows(model, {})! {
						rows << json2.decode[json2.Any](row)!
					}
					return rows
				}
				return error('unsupported organization adapter storage')
			}
			if mut storage is AdapterModelStorage {
				for row in storage.adapter_model_rows(model)! {
					rows << json2.decode[json2.Any](row)!
				}
			} else {
				return error('unsupported adapter model storage')
			}
		}
	}

	return rows
}

fn (mut c EndpointContext) adapter_user_rows(model string, user_id string) ![]json2.Any {
	mut rows := []json2.Any{}
	if model == 'session' {
		for row in c.auth.storage.sessions(user_id)! {
			token := if row.token != '' { row.token } else { c.auth.unseal_session_token(row)! }
			rows << json2.decode[json2.Any](encode_session(Session{ ...row, token: token }))!
		}
	} else if model == 'account' {
		for row in c.auth.storage.accounts(user_id)! {
			rows << json2.decode[json2.Any](encode_account(row))!
		}
	} else {
		return error('unsupported user relation')
	}
	return rows
}

fn (mut c EndpointContext) adapter_candidates(model string, where []adapter.Predicate) ![]json2.Any {
	// Session authentication is an indexed token lookup. It must not decrypt
	// unrelated sessions (including rows encrypted with retired secrets).
	if model == 'session' && where.len == 1 {
		filter := where[0]
		if filter.field == 'token' && filter.operator == .eq {
			value := filter.value
			if value is string {
				if row := (c.auth.stored_session_for_token(value.str())!).value {
					return [
						json2.decode[json2.Any](encode_session(Session{ ...row, token: value.str() }))!,
					]
				}
				return []json2.Any{}
			}
		}
	}
	return c.adapter_rows(model)
}

fn (mut c EndpointContext) adapter_read(query adapter.Read) ![]json2.Any {
	model := query.model
	where := query.where
	c.adapter_filters(model, where)!
	// Validate the complete plan even when no rows match.
	if sort := query.sort { c.adapter_field(model, sort.field)! }
	for join in query.joins {
		c.adapter_relation(model, join.target)!
	}
	for field in query.selection {
		c.adapter_field(model, field)!
	}
	mut rows := []json2.Any{}
	for row in c.adapter_candidates(model, where)! {
		if c.adapter_matches(model, row.as_map(), where)! { rows << row }
	}
	if sort := query.sort {
		field := sort.field
		direction := sort.direction
		// Stable insertion sort keeps equal-key order deterministic without asking
		// comparator callbacks to swallow date/type errors.
		for i := 1; i < rows.len; i++ {
			mut j := i
			for j > 0 {
				a := rows[j - 1].as_map()[field] or { json2.Any(json2.Null{}) }
				b := rows[j].as_map()[field] or { json2.Any(json2.Null{}) }
				order := adapter_compare(a, b, c.adapter_date(model, field))!
				if (direction == .asc && order <= 0) || (direction == .desc && order >= 0) { break
				 }
				rows[j - 1], rows[j] = rows[j], rows[j - 1]
				j--
			}
		}
	}
	start := query.offset
	limit := query.limit
	end := if start >= rows.len || limit > rows.len - start { rows.len } else { start + limit }
	mut page := if start >= rows.len { []json2.Any{} } else { rows[start..end].clone() }
	selection := query.selection
	for i, item in page {
		base := item.as_map()
		mut projected := map[string]json2.Any{}
		if selection.len > 0 {
			for field in selection {
				if value := base[field] { projected[field] = value }
			}
		} else {
			projected = base.clone()
		}
		for join in query.joins {
			target := join.target
			if !join.enabled { continue
			 }
			relation := c.adapter_relation(model, target)!
			mut related := []json2.Any{}
			candidates := if model == 'user' && target in ['session', 'account'] { c.adapter_user_rows(target, (base['id'] or {
					json2.Any('')}).str())! } else { c.adapter_rows(target)! }
			for row in candidates {
				fields := row.as_map()
				left := base[relation.base_field] or { json2.Any(json2.Null{}) }
				right := fields[relation.target_field] or { json2.Any(json2.Null{}) }
				if left !is json2.Null && right !is json2.Null && adapter_equal(left, right, false) {
					related << row
				}
			}
			cap := join.limit
			if related.len > cap { related = related[..cap].clone() }
			projected[target] = if relation.single {
				if related.len == 0 { json2.Any(json2.Null{}) } else { related[0] }
			} else {
				json2.Any(related)
			}
		}
		page[i] = projected
	}
	return page
}

fn (mut c EndpointContext) adapter_create(model string, input map[string]json2.Any, force bool) !string {
	c.adapter_field(model, 'id')!
	mut data := input.clone()
	if !force { data.delete('id') }
	if 'id' !in data { data['id'] = c.auth.new_id(model)! }
	if model in organization_models {
		for key, _ in data {
			c.adapter_field(model, key)!
		}
		if 'createdAt' !in data { data['createdAt'] = stamp_millis(c.auth.clock_millis()) }
		mut storage := c.auth.storage
		if mut storage is OrganizationStorage {
			storage.organization_create(model, json2.Any(data).json_str())!
		} else {
			return error('unsupported organization adapter storage')
		}
		return json2.Any(data).json_str()
	}
	if definition := c.auth.config.adapter_models[model] {
		for key, _ in data {
			c.adapter_field(model, key)!
		}
		data = fill_field_defaults(definition.fields, data)!
		for key, field in definition.fields {
			if key !in data && !field.required { data[key] = json2.Null{} }
		}
		c.adapter_validate_model(model, data)!
		mut storage := c.auth.storage
		if mut storage is AdapterModelStorage {
			storage.adapter_model_write(model, json2.Any(data).json_str(), true)!
		} else {
			return error('unsupported adapter model storage')
		}
		return json2.Any(data).json_str()
	}
	for field in ['createdAt', 'updatedAt'] {
		if field !in data { data[field] = stamp_millis(c.auth.clock_millis()) }
	}
	for key, _ in data {
		c.adapter_field(model, key)!
	}
	encoded := json2.Any(data).json_str()
	match model {
		'user' {
			decoded := decode_user(encoded)!
			row := User{
				...decoded
				additional_fields: fill_field_defaults(c.auth.config.user_fields,
					decoded.additional_fields)!
			}
			c.auth.storage.create_user(row)!
			return encode_user(row)
		}
		'session' {
			decoded := decode_session(encoded)!
			mut row := Session{
				...decoded
				additional_fields: fill_field_defaults(c.auth.config.session_fields,
					decoded.additional_fields)!
			}
			row = Session{
				...row
				encrypted_token: c.auth.seal_session_token(row)!
			}
			c.auth.storage.create_session(row, digest(row.token))!
			return encode_session(row)
		}
		'account' {
			row := decode_account(encoded)!
			c.auth.storage.create_account(row)!
			return encode_account(row)
		}
		else {
			row := decode_verification_record(encoded)!
			c.auth.storage.create_verification(row)!
			return encode_verification(row)
		}
	}
}

// Compatibility JSON boundary; the executor sees only decoded command types.
fn (mut c EndpointContext) adapter_query(operation string, query map[string]json2.Any) !string {
	command := adapter.decode(operation, query)!
	return match command {
		adapter.Create {
			c.adapter_create(command.model, command.data, command.force_id)!
		}
		adapter.Read {
			rows := c.adapter_read(command)!
			if !command.one {
				json2.Any(rows).json_str()
			} else if rows.len > 0 {
				rows[0].json_str()
			} else {
				'null'
			}
		}
		adapter.Mutation {
			c.adapter_mutate(command)!
		}
		adapter.Increment {
			c.adapter_increment(command)!
		}
	}
}

fn (mut c EndpointContext) adapter_mutate(query adapter.Mutation) !string {
	model := query.model
	where := query.where
	operation := query.kind
	c.adapter_filters(model, where)!
	if operation == .update && where.len == 0 { return 'null' }
	if operation in [.update, .update_many] && model != 'user'
		&& model !in c.auth.config.adapter_models {
		return error('raw update is currently supported for users only')
	}
	patch := query.patch.clone()
	for key, _ in patch {
		c.adapter_field(model, key)!
		if key == 'id' { return error('adapter IDs are immutable') }
	}
	mut count := 0
	mut updated := 'null'
	for item in c.adapter_rows(model)! {
		mut row := item.as_map()
		if !c.adapter_matches(model, row, where)! { continue
		 }
		count++
		id := (row['id'] or { return error('missing stored id') }).str()
		if operation in [.delete, .delete_many] {
			match model {
				'user' {
					c.auth.storage.delete_user(id)!
				}
				'session' {
					c.auth.storage.delete_session(id)!
				}
				'account' {
					c.auth.storage.delete_account(id)!
				}
				'verification' {
					c.auth.storage.delete_verification(id)!
				}
				else {
					mut storage := c.auth.storage
					if mut storage is AdapterModelStorage {
						storage.adapter_model_delete(model, id)!
					}
				}
			}
		} else if operation in [.update, .update_many] {
			for key, value in patch {
				row[key] = value
			}
			if model in c.auth.config.adapter_models {
				c.adapter_validate_model(model, row)!
				mut storage := c.auth.storage
				if mut storage is AdapterModelStorage {
					storage.adapter_model_write(model, json2.Any(row).json_str(), false)!
				}
				updated = json2.Any(row).json_str()
				if operation == .update { break
				 }
				continue
			}
			if 'updatedAt' !in patch { row['updatedAt'] = stamp_millis(c.auth.clock_millis()) }
			c.auth.storage.update_user(decode_user(json2.Any(row).json_str())!)!
			actual := (c.auth.storage.user(id)!).value or {
				return error('adapter update row disappeared')
			}

			updated = encode_user(actual)
		}
		if operation == .update { break
		 }
	}
	return if operation == .update {
		updated
	} else if operation == .delete {
		'null'
	} else {
		count.str()
	}
}
