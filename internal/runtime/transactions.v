module better_auth

fn (mut a Auth) begin_transaction(read_only bool) ! {
	if a.operation.attempt.transaction.active { return error('transaction is already active') }
	if a.transactions_enabled {
		if read_only {
			a.storage.begin_read()!
		} else {
			a.storage.begin()!
		}
	}
	a.operation.attempt.transaction.active = true
	a.operation.attempt.transaction.pending_tasks = []AfterCommitTask{}
	a.operation.attempt.transaction.secondary_created = []Session{}
}

fn (mut a Auth) commit_transaction() ! {
	mut context := EndpointContext{
		auth: a
	}
	a.config.before_commit(mut context)!
	if a.transactions_enabled { a.storage.commit()! }
	a.finish_committed_transaction()!
}

fn (mut a Auth) finish_committed_transaction() ! {
	a.operation.attempt.transaction.active = false
	a.operation.attempt.transaction.secondary_created = []Session{}
	tasks := a.operation.attempt.transaction.pending_tasks.clone()
	a.operation.attempt.transaction.pending_tasks = []AfterCommitTask{}
	for task in tasks {
		a.run_task(task)!
	}
}

fn (mut a Auth) rollback_transaction() {
	if !a.operation.attempt.transaction.active { return }
	if a.transactions_enabled { a.storage.rollback() or {
			a.config.log('error', 'Database rollback failed')} }
	a.operation.attempt.transaction.active = false
	a.operation.attempt.transaction.pending_tasks = []AfterCommitTask{}
	for session in a.operation.attempt.transaction.secondary_created {
		a.remove_cached_session(session) or {
			a.config.log('error', 'Failed to remove rolled-back secondary session')
		}
	}
	a.operation.attempt.transaction.secondary_created = []Session{}
}

// Trusted server-side internal operations get the same transaction and hooks as
// HTTP operations. Hooks use their existing EndpointContext to avoid re-locking.
pub fn (mut a Auth) with_internal(operation fn (mut EndpointContext) !string) !string {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed { return error('Auth instance is closed') }
	a.begin_transaction(false)!
	defer { a.rollback_transaction() }
	mut context := EndpointContext{
		auth: a
	}
	result := operation(mut context)!
	a.commit_transaction()!
	return result
}

// EndpointContext already owns Auth's lock. Nested work shares an active
// transaction; after-commit work starts a new one without re-locking Auth.
pub fn (c &EndpointContext) has_active_transaction() bool {
	return c.auth.operation.attempt.transaction.active
}

pub fn (mut c EndpointContext) with_transaction(operation fn (mut EndpointContext) !string) !string {
	if c.auth.operation.attempt.transaction.active { return operation(mut c) }
	return c.auth.with_transaction_unlocked(operation)
}

// Unlike with_internal, this API delegates replayable transaction callbacks to
// a driver's native transaction runner when available. A callback may run again.
pub fn (mut a Auth) with_transaction(operation fn (mut EndpointContext) !string) !string {
	return a.transaction[string](operation)
}

// Typed operations retain their result outside the driver's callback. The C
// driver handles transaction outcomes, never application result serialization.
pub fn (mut a Auth) transaction[T](operation fn (mut EndpointContext) !T) !T {
	a.mutex.@lock()
	defer { a.mutex.unlock() }
	if a.closed { return error('Auth instance is closed') }
	return a.run_transaction[T](operation)
}

pub fn (mut c EndpointContext) transaction[T](operation fn (mut EndpointContext) !T) !T {
	if c.auth.operation.attempt.transaction.active { return operation(mut c) }
	return c.auth.run_transaction[T](operation)
}

fn (mut a Auth) with_transaction_unlocked(operation fn (mut EndpointContext) !string) !string {
	return a.run_transaction[string](operation)
}

// The driver sees one non-generic callback contract. Typed values remain in
// their attempt object, avoiding both JSON conversion and generic C closures.
interface ManagedAttempt {
mut:
	execute() !string
}

@[heap]
struct TypedTransactionAttempt[T] {
mut:
	auth      &Auth
	seed      &AttemptContext
	operation fn (mut EndpointContext) !T @[required]
	value     T
	has_value bool
}

fn (mut attempt TypedTransactionAttempt[T]) execute() !string {
	mut a := attempt.auth
	a.rollback_transaction()
	a.operation.attempt = attempt.seed.fresh()
	attempt.has_value = false
	a.begin_transaction(false)!
	mut context := EndpointContext{
		auth: a
	}
	value := attempt.operation(mut context) or {
		a.rollback_transaction()
		return err
	}
	a.config.before_commit(mut context) or {
		a.rollback_transaction()
		return err
	}
	attempt.value = value
	attempt.has_value = true
	return ''
}

fn (attempt &TypedTransactionAttempt[T]) result() !T {
	if !attempt.has_value { return error('transaction completed without an operation result') }
	return attempt.value
}

fn (mut a Auth) run_transaction[T](operation fn (mut EndpointContext) !T) !T {
	defer { a.rollback_transaction() }
	mut storage := a.storage
	if mut storage is ManagedTransactionStorage {
		if a.transactions_enabled {
			seed := a.operation.attempt.fresh()
			mut typed := &TypedTransactionAttempt[T]{
				auth:      a
				seed:      seed
				operation: operation
			}
			mut attempt := ManagedAttempt(typed)
			storage.run_managed_transaction(fn [mut attempt] [T]() !string {
				return attempt.execute()
			}) or {
				a.rollback_transaction()
				a.operation.attempt = seed
				if err is MongoDriverError && err.cleanup_error != '' {
					a.config.log('error',
						'Failed to abort a MongoDB transaction whose commit did not complete: ' +
						err.cleanup_error)
				}
				return err
			}
			a.finish_committed_transaction()!
			return typed.result()
		}
	}
	a.begin_transaction(false)!
	mut context := EndpointContext{
		auth: a
	}
	value := operation(mut context)!
	a.commit_transaction()!
	return value
}
