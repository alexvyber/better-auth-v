module main

import x.json2

fn filter_inspection(encoded string, where string) !string {
	conditions := json2.decode[[]json2.Any](where)!
	records := json2.decode[[]json2.Any](encoded)!
	mut selected := []json2.Any{}
	for record in records {
		mut matches := true
		for condition in conditions {
			filter := condition.as_map()
			for key, _ in filter {
				if key !in ['field', 'value', 'operator'] {
					return error('unsupported inspection predicate')
				}
			}
			if (filter['operator'] or { json2.Any('eq') }).str() != 'eq' {
				return error('only equality inspection predicates are implemented')
			}
			field := (filter['field'] or { return error('missing predicate field') }).str()
			actual := record.as_map()[field] or { json2.Any(json2.Null{}) }
			expected := filter['value'] or { return error('missing predicate value') }
			if actual.json_str() != expected.json_str() {
				matches = false
				break
			}
		}
		if matches { selected << record }
	}
	return json2.Any(selected).json_str()
}
