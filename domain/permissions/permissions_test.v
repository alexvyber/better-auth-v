module permissions

fn test_roles_fail_closed_and_require_a_complete_grant() {
	roles := {
		'reader': {
			'document': ['read']
		}
		'writer': {
			'document': ['write']
		}
		'editor': {
			'document': ['read', 'write']
		}
	}
	assert !allows('reader,writer', roles, {
		'document': ['read', 'write']
	})
	assert allows('unknown,editor', roles, {
		'document': ['read', 'write']
	})
	assert !allows('editor', roles, {
		'document': []string{}
	})
	assert !allows('editor', roles, {
		'missing': ['read']
	})
	assert !allows('editor', roles, map[string][]string{})
	assert allows('owner', organization_roles(), {
		'organization': ['delete']
	})
	assert !allows('member', organization_roles(), {
		'organization': ['delete']
	})
}
