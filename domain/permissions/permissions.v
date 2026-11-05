module permissions

// A request must be granted completely by one role; partial roles do not combine.
pub fn admin_roles() map[string]map[string][]string {
	return {
		'admin': {
			'user':    ['create', 'list', 'set-role', 'ban', 'impersonate', 'delete', 'set-password',
				'set-email', 'get', 'update']
			'session': ['list', 'revoke', 'delete']
		}
		'user':  {
			'user':    []string{}
			'session': []string{}
		}
	}
}

pub fn allows(role_names string, roles map[string]map[string][]string, permissions map[string][]string) bool {
	if permissions.len == 0 { return false }
	for role in role_names.split(',') {
		granted := (roles[role] or { continue }).clone()
		mut allowed := true
		for resource, actions in permissions {
			if actions.len == 0 {
				allowed = false
				break
			}
			scope := granted[resource] or {
				allowed = false
				break
			}
			for action in actions {
				if action !in scope {
					allowed = false
					break
				}
			}
		}
		if allowed { return true }
	}
	return false
}

pub fn organization_roles() map[string]map[string][]string {
	return {
		'owner':  {
			'organization': ['update', 'delete']
			'member':       ['create', 'update', 'delete']
			'invitation':   ['create', 'cancel']
			'team':         ['create', 'update', 'delete']
			'ac':           ['create', 'read', 'update', 'delete']
		}
		'admin':  {
			'organization': ['update']
			'member':       ['create', 'update', 'delete']
			'invitation':   ['create', 'cancel']
			'team':         ['create', 'update', 'delete']
			'ac':           ['create', 'read', 'update', 'delete']
		}
		'member': {
			'organization': []string{}
			'member':       []string{}
			'invitation':   []string{}
			'team':         []string{}
			'ac':           ['read']
		}
	}
}
