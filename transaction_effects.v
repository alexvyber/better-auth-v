module better_auth

enum AfterCommitKind {
	database_hook
	remove_session
	mirror_session
	password_reset
}

struct AfterCommitTask {
	kind    AfterCommitKind
	event   DatabaseEvent
	session Session
	user    User
}

fn (mut a Auth) queue_task(task AfterCommitTask) ! {
	if a.operation.attempt.transaction.active && a.transactions_enabled {
		a.operation.attempt.transaction.pending_tasks << task
	} else {
		a.run_task(task)!
	}
}

fn (mut a Auth) run_task(task AfterCommitTask) ! {
	if task.kind == .remove_session {
		a.remove_cached_session(task.session)!
		return
	}
	if task.kind == .password_reset {
		a.config.on_password_reset(task.user)!
		return
	}
	if task.kind == .mirror_session {
		a.mirror_session(task.session) or {
			a.config.log('error', 'Failed to mirror committed session to secondary storage')
		}
		return
	}
	mut context := EndpointContext{
		auth: a
	}
	for hook in a.config.database_hooks {
		hook.run(mut context, task.event) or { return as_application_error(err) }
	}
}
