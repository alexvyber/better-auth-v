module adapter

import x.json2

// Query control flow is typed; application-defined record values remain JSON.
pub enum Operator {
	eq
	ne
	gt
	gte
	lt
	lte
	inside
	not_in
	contains
	starts_with
	ends_with
}
pub enum Connector {
	and_group
	or_group
}
pub enum Mode {
	sensitive
	insensitive
}
pub enum Direction {
	asc
	desc
}
pub enum MutationKind {
	update
	update_many
	delete
	delete_many
	count
}

pub struct Predicate {
pub:
	field     string
	value     json2.Any
	operator  Operator
	connector Connector
	mode      Mode
}

pub struct Sort {
pub:
	field     string
	direction Direction
}

pub struct Join {
pub:
	target  string
	enabled bool = true
	limit   int  = 100
}

pub struct Create {
pub:
	model    string
	data     map[string]json2.Any
	force_id bool
}

pub struct Read {
pub:
	model     string
	where     []Predicate
	sort      ?Sort
	offset    int
	limit     int = 100
	selection []string
	joins     []Join
	one       bool
}

pub struct Mutation {
pub:
	model string
	where []Predicate
	kind  MutationKind
	patch map[string]json2.Any
}

pub struct Increment {
pub:
	model  string
	where  []Predicate
	deltas map[string]json2.Any
	set    map[string]json2.Any
}

pub type Command = Create | Read | Mutation | Increment
