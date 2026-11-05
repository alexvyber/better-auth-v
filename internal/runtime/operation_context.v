module better_auth

// Auth owns durable configuration and a serialized connection. Request metadata,
// retry state and transactional effects belong to the invocation using it.
@[heap]
struct OperationContext {
mut:
	request      RequestContext
	attempt      &AttemptContext    = &AttemptContext{}
	interception &InterceptionState = &InterceptionState{}
}

@[heap]
struct InterceptionState {
mut:
	active map[string]bool
}

@[heap]
struct AttemptContext {
mut:
	new_session            ?SessionResult
	anonymous_link_session ?SessionResult
	oauth_state_consumed   bool
	transaction            TransactionState
}

struct TransactionState {
mut:
	active            bool
	pending_tasks     []AfterCommitTask
	secondary_created []Session
}

fn (attempt &AttemptContext) fresh() &AttemptContext {
	return &AttemptContext{
		...attempt
		transaction: TransactionState{}
	}
}

// A nested trusted read changes request metadata while sharing the enclosing
// attempt, interception guards and transaction effects.
fn (mut a Auth) with_request_context[T](request RequestContext, operation fn (mut EndpointContext) !T) !T {
	previous := a.operation
	a.operation = &OperationContext{
		request:      request
		attempt:      previous.attempt
		interception: previous.interception
	}
	defer { a.operation = previous }
	mut context := EndpointContext{
		auth: a
	}
	return operation(mut context)
}
