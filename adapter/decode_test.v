module adapter

import x.json2

fn command(operation string, input string) !Command {
	return decode(operation, (json2.decode[json2.Any](input)!).as_map())
}

fn test_decoded_plans_preserve_predicates_projection_and_join_limits() ! {
	plan := command('findMany',
		'{"model":"user","where":[{"field":"email","operator":"contains","value":"EXAMPLE","mode":"insensitive","connector":"OR"}],"sortBy":{"field":"createdAt","direction":"desc"},"offset":2,"limit":3,"select":["id"],"join":{"session":{"limit":0},"account":false}}')!
	assert plan is Read
	if plan is Read {
		assert plan.where[0].operator == .contains
		assert plan.where[0].connector == .or_group
		assert plan.where[0].mode == .insensitive
		assert plan.selection == ['id']
		assert (plan.sort or { return error('missing sort') }).direction == .desc
		assert plan.offset == 2 && plan.limit == 3
		for join in plan.joins {
			if join.target == 'session' { assert join.enabled && join.limit == 0
			 }
			if join.target == 'account' { assert !join.enabled
			 }
		}
	}
	assert command('create', '{"model":"user","data":{"id":"fixed"},"forceAllowId":true}')! is Create
	assert command('incrementOne', '{"model":"user","where":[],"increment":{"counter":-1}}')! is Increment
	empty := command('update', '{"model":"user","where":[]}')!
	if empty is Mutation {
		assert empty.patch.len == 0
	} else {
		assert false
	}
}

fn test_decoder_rejects_malformed_control_options_before_execution() {
	for input in [
		'{"model":"user","where":[{"field":"id","operator":"in","value":"x"}]}',
		'{"model":"user","where":[{"field":"id","operator":"contains","value":2}]}',
		'{"model":"user","where":[{"field":"id","value":null,"connector":"XOR"}]}',
		'{"model":"user","where":[{"field":"id","value":null,"mode":"unknown"}]}',
		'{"model":"user","limit":-1}',
		'{"model":"user","offset":0.5}',
		'{"model":"user","join":{"account":{"limit":-1}}}',
		'{"model":"user","unexpected":true}',
	] {
		mut rejected := false
		command('findMany', input) or { rejected = true }
		assert rejected, input
	}
}
