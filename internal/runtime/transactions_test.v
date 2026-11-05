module better_auth

@[heap]
struct TransactionProbe {
mut:
	calls   int
	effects int
}

struct TransactionProbeHook {
	probe &TransactionProbe
}

fn (hook TransactionProbeHook) run(mut _ EndpointContext, event DatabaseEvent) !HookResult {
	if event.phase == 'after' {
		mut probe := hook.probe
		probe.effects++
	}
	return HookResult{}
}

// Models a driver-owned physical transaction whose first commit is transient.
// The operation callback must begin a new logical attempt on replay.
struct ReplayMemoryStorage {
	MemoryStorage
}

fn (mut _ ReplayMemoryStorage) begin() ! {}

fn (mut _ ReplayMemoryStorage) rollback() ! {}

fn (mut _ ReplayMemoryStorage) commit() ! {}

fn (mut storage ReplayMemoryStorage) run_managed_transaction(operation fn () !string) !string {
	for attempt in 0 .. 2 {
		storage.MemoryStorage.begin()!
		value := operation() or {
			storage.MemoryStorage.rollback()!
			return err
		}
		if attempt == 0 {
			storage.MemoryStorage.rollback()!
			continue
		}
		storage.MemoryStorage.commit()!
		return value
	}
	return error('missing replay result')
}

fn test_typed_transaction_replay_owns_attempt_state_and_committed_effects() ! {
	mut probe := &TransactionProbe{}
	mut auth := new(Config{
		secret:         'typed-transactions-probe-secret-at-least-32-bytes'
		database_hooks: [DatabaseHook(TransactionProbeHook{
			probe: probe
		})]
	}, ReplayMemoryStorage{})!
	defer { auth.close() or {} }
	response := auth.transaction[Response](fn [mut probe] (mut context EndpointContext) !Response {
		probe.calls++
		assert !context.auth.operation.attempt.oauth_state_consumed
		assert context.auth.operation.attempt.new_session == none
		context.auth.operation.attempt.oauth_state_consumed = true
		context.auth.operation.attempt.new_session = SessionResult{
			user: User{
				name: 'attempt'
			}
		}
		context.create_user(User{ id: 'u', email: 'typed@transaction.example', name: 'Retained' })!
		return Response{
			status:  201
			body:    'attempt ${probe.calls} ✓'
			headers: [Header{'x-attempt', probe.calls.str()}]
		}
	})!
	assert probe.calls == 2
	assert probe.effects == 1
	assert auth.storage.users()!.len == 1
	assert response.status == 201
	assert response.body == 'attempt 2 ✓'
	assert response.headers == [Header{'x-attempt', '2'}]
	assert !auth.operation.attempt.transaction.active
}

fn test_typed_nested_transaction_shares_outer_rollback() ! {
	mut auth :=
		new(Config{ secret: 'typed-transactions-probe-secret-at-least-32-bytes' }, MemoryStorage{})!
	defer { auth.close() or {} }
	mut failed := false
	auth.transaction[int](fn (mut context EndpointContext) !int {
		value := context.transaction[int](fn (mut nested EndpointContext) !int {
			nested.create_user(User{
				id:    'nested'
				email: 'nested@transaction.example'
				name:  'Rollback'
			})!
			return 42
		})!
		assert value == 42
		return error('rollback the enclosing transaction')
	}) or { failed = true }
	assert failed
	assert auth.storage.users()!.len == 0
	assert !auth.operation.attempt.transaction.active
}
