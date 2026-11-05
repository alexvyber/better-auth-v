module adapter

import x.json2

fn keys(data map[string]json2.Any, allowed []string) ! {
	for key, _ in data {
		if key !in allowed { return error('unsupported adapter query option: ${key}') }
	}
}

fn object(value json2.Any) !map[string]json2.Any {
	if value !is map[string]json2.Any { return error('adapter object required') }
	return value.as_map().clone()
}

fn expect_array(value json2.Any) ![]json2.Any {
	if value !is []json2.Any { return error('adapter array required') }
	return value.as_array()
}

fn page(query map[string]json2.Any, key string, fallback int) !int {
	value := query[key] or { return fallback }
	if value !is int && value !is i64 && value !is f64 {
		return error('adapter pagination must be numeric')
	}
	number := value.f64()
	if number < 0 || number > 2147483647 || number != f64(int(number)) {
		return error('invalid adapter pagination')
	}
	return int(number)
}

fn predicates(value json2.Any) ![]Predicate {
	mut result := []Predicate{}
	for clause in expect_array(value)! {
		if clause !is map[string]json2.Any { return error('adapter predicate must be an object') }
		filter := clause.as_map()
		keys(filter, ['field', 'value', 'operator', 'connector', 'mode'])!
		field := (filter['field'] or { return error('missing predicate field') }).str()
		operand := filter['value'] or { return error('missing predicate value') }
		operator := match (filter['operator'] or { json2.Any('eq') }).str() {
			'eq' { Operator.eq }
			'ne' { Operator.ne }
			'gt' { Operator.gt }
			'gte' { Operator.gte }
			'lt' { Operator.lt }
			'lte' { Operator.lte }
			'in' { Operator.inside }
			'not_in' { Operator.not_in }
			'contains' { Operator.contains }
			'starts_with' { Operator.starts_with }
			'ends_with' { Operator.ends_with }
			else { return error('unsupported adapter operator') }
		}

		if operator in [.inside, .not_in] && operand !is []json2.Any {
			return error('membership predicate requires an array')
		}
		if operator in [.contains, .starts_with, .ends_with] && operand !is string {
			return error('string predicate requires a string')
		}
		connector := match (filter['connector'] or { json2.Any('AND') }).str() {
			'AND' { Connector.and_group }
			'OR' { Connector.or_group }
			else { return error('invalid adapter connector') }
		}

		mode := match (filter['mode'] or { json2.Any('sensitive') }).str() {
			'sensitive' { Mode.sensitive }
			'insensitive' { Mode.insensitive }
			else { return error('invalid adapter comparison mode') }
		}

		result << Predicate{
			field:     field
			value:     operand
			operator:  operator
			connector: connector
			mode:      mode
		}
	}
	return result
}

// Decode only at the trusted JSON boundary. Execution never reparses options.
pub fn decode(operation string, query map[string]json2.Any) !Command {
	model := (query['model'] or { return error('missing adapter model') }).str()
	if operation == 'create' {
		keys(query, ['model', 'data', 'forceAllowId'])!
		if force := query['forceAllowId'] {
			if force !is bool { return error('forceAllowId must be boolean') }
		}
		return Create{
			model:    model
			data:     object(query['data'] or { return error('missing adapter data') })!
			force_id: (query['forceAllowId'] or { json2.Any(false) }).bool()
		}
	}
	if operation in ['findOne', 'findMany'] {
		keys(query, if operation == 'findOne' { ['model', 'where', 'select', 'join'] } else { [
				'model',
				'where',
				'select',
				'join',
				'sortBy',
				'limit',
				'offset',
			] })!
		where := predicates(query['where'] or { json2.Any([]json2.Any{}) })!
		mut sort := ?Sort(none)
		if options := query['sortBy'] {
			fields := object(options)!
			keys(fields, ['field', 'direction'])!
			field := (fields['field'] or { return error('missing sort field') }).str()
			direction := match (fields['direction'] or { json2.Any('asc') }).str() {
				'asc' { Direction.asc }
				'desc' { Direction.desc }
				else { return error('invalid sort direction') }
			}

			sort = Sort{
				field:     field
				direction: direction
			}
		}
		mut joins := []Join{}
		for target, option in object(query['join'] or { json2.Any(map[string]json2.Any{}) })! {
			if option is bool {
				joins << Join{
					target:  target
					enabled: option
				}
				continue
			}
			fields := object(option)!
			keys(fields, ['limit'])!
			joins << Join{
				target: target
				limit:  page(fields, 'limit', 100)!
			}
		}
		mut selection_fields := []string{}
		if selection := query['select'] {
			for field in expect_array(selection)! {
				selection_fields << field.str()
			}
		}
		return Read{
			model:     model
			where:     where
			sort:      sort
			offset:    page(query, 'offset', 0)!
			limit:     if operation == 'findOne' { 1 } else { page(query, 'limit', 100)! }
			selection: selection_fields
			joins:     joins
			one:       operation == 'findOne'
		}
	}
	if operation == 'incrementOne' {
		keys(query, ['model', 'where', 'increment', 'set'])!
		return Increment{
			model:  model
			where:  predicates(query['where'] or { return error('missing increment predicate') })!
			deltas: object(query['increment'] or { return error('missing increment map') })!
			set:    object(query['set'] or { json2.Any(map[string]json2.Any{}) })!
		}
	}
	kind := match operation {
		'update' { MutationKind.update }
		'updateMany' { MutationKind.update_many }
		'delete' { MutationKind.delete }
		'deleteMany' { MutationKind.delete_many }
		'count' { MutationKind.count }
		else { return error('unsupported adapter operation') }
	}

	keys(query, if kind in [.update, .update_many] { ['model', 'where', 'update'] } else { [
			'model',
			'where',
		] })!
	where := predicates(query['where'] or { json2.Any([]json2.Any{}) })!
	// Existing single-update semantics: an empty predicate is a no-op, including
	// an omitted patch. Never reinterpret it as an unguarded table-wide update.
	patch := if kind in [.update, .update_many] && !(kind == .update && where.len == 0) {
		object(query['update'] or { return error('missing adapter update') })!
	} else {
		map[string]json2.Any{}
	}
	return Mutation{
		model: model
		where: where
		kind:  kind
		patch: patch
	}
}
