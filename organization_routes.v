module better_auth

import x.json2

fn organization_string(data map[string]json2.Any, field string) !string {
	value := data[field] or { return fail(400, 'VALIDATION_ERROR', field + ' is required') }
	if value !is string || value.str() == '' {
		return fail(400, 'VALIDATION_ERROR', field + ' must be a non-empty string')
	}
	return value.str()
}

fn organization_metadata(mut data map[string]json2.Any) ! {
	if value := data['logo'] {
		if value !is string && value !is json2.Null {
			return fail(400, 'VALIDATION_ERROR', 'logo must be a string or null')
		}
	}
	if value := data['metadata'] {
		if value !is map[string]json2.Any {
			return fail(400, 'VALIDATION_ERROR', 'metadata must be an object')
		}
		data['metadata'] = value.json_str()
	}
}

fn organization_create(mut context EndpointContext, actor ?SessionResult, fields map[string]json2.Any) !Response {
	options := context.auth.organization_options()!
	user := if current := actor {
		current.user
	} else {
		(context.auth.storage.user((fields['userId'] or { json2.Any('') }).str())!).value or {
			return fail(401, 'UNAUTHORIZED', 'Unauthorized')
		}
	}
	allowed := if options.allow_creation != default_organization_creation {
		options.allow_creation(mut context, user)!
	} else {
		options.allow_user_to_create
	}
	if !allowed && actor != none {
		return fail(403, 'YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION',
			'You are not allowed to create a new organization')
	}
	if maximum := options.organization_limit {
		if (context.organization_rows('member', {
			'userId': user.id
		})!).len >= maximum {
			return fail(403, 'YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS',
				'You have reached the maximum number of organizations')
		}
	}
	name := organization_string(fields, 'name')!
	slug := organization_string(fields, 'slug')!
	if (context.organization_find('organization', {
		'slug': slug
	})!).value != none {
		return fail(400, 'ORGANIZATION_ALREADY_EXISTS', 'Organization already exists')
	}
	mut data := context.auth.organization_client_fields('organization', fields, true)!
	data['name'] = name
	data['slug'] = slug
	for field in ['logo', 'metadata'] {
		if value := fields[field] { data[field] = value }
	}
	if patch := (context.organization_hook('beforeCreateOrganization', {
		'organization': json2.Any(data)
		'user':         json2.decode[json2.Any](encode_user(user))!
	})!).value
	{
		data = organization_merge(data, patch)!
	}
	organization_string(data, 'name')!
	organization_string(data, 'slug')!
	organization_metadata(mut data)!
	if 'id' !in data { data['id'] = context.auth.new_id('organization')! }
	data['createdAt'] = stamp_millis(context.auth.clock_millis())
	data = context.auth.organization_defaults('organization', data)!
	context.organization_create_record('organization', data)!
	member := context.organization_add_member(data, user, options.creator_role,
		map[string]json2.Any{}, true)!
	output := context.auth.organization_output('organization', data)!
	context.organization_hook('afterCreateOrganization', {
		'organization': json2.Any(output)
		'member':       json2.Any(member)
		'user':         json2.decode[json2.Any](encode_user(user))!
	})!
	if current := actor {
		if !(fields['keepCurrentActiveOrganization'] or { json2.Any(false) }).bool() { context.organization_set_active(current.session, (data['id'] or {
				json2.Any('')}).str())! }
	}
	mut response := output.clone()
	response['members'] = json2.Any([json2.Any(member)])
	return admin_json_response(response)
}

fn (mut context EndpointContext) organization_expanded_members(id string, requested_limit int) ![]json2.Any {
	options := context.auth.organization_options()!
	limit := if requested_limit > 0 {
		requested_limit
	} else if options.membership_limit > 0 {
		options.membership_limit
	} else {
		100
	}
	mut rows := context.organization_rows('member', {
		'organizationId': id
	})!
	if rows.len > limit { rows = rows[..limit].clone() }
	mut result := []json2.Any{}
	for row in rows {
		fields := org_json_fields(row)!
		user_id := (fields['userId'] or { json2.Any('') }).str()
		user := (context.auth.storage.user(user_id)!).value or {
			return error('User not found for organization member')
		}

		mut item := context.auth.organization_output('member', fields)!
		mut selected := {
			'id':    json2.Any(user.id)
			'name':  json2.Any(user.name)
			'email': json2.Any(user.email)
			'image': json2.Any(json2.Null{})
		}
		if image := user.image { selected['image'] = image }
		item['user'] = json2.Any(selected)
		result << json2.Any(item)
	}
	return result
}

fn organization_get_or_activate(mut context EndpointContext, current SessionResult, fields map[string]json2.Any, path string) !Response {
	if path == 'set-active' {
		if value := fields['organizationId'] {
			if value is json2.Null {
				updated := context.organization_set_active(current.session, none)!
				return context.auth.set_session_cookies(Response{
					headers: [
						Header{'content-type', 'application/json'},
					]
					body:    'null'
				}, SessionResult{
					session: updated
					user:    current.user
				})
			}
		}
	}
	slug := (fields['organizationSlug'] or { json2.Any('') }).str()
	mut id := organization_id(fields, current.session)
	// Read endpoints give slug precedence; set-active prefers an explicit ID.
	if slug != '' && (path != 'set-active' || !js_truthy(fields['organizationId'] or {
		json2.Any(json2.Null{})
	})) {
		encoded := (context.organization_find('organization', {
			'slug': slug
		})!).value or { return fail(400, 'ORGANIZATION_NOT_FOUND', 'Organization not found') }
		id = (org_json_fields(encoded)!['id'] or { json2.Any('') }).str()
	}
	if id == '' { return Response{
			headers: [Header{'content-type', 'application/json'}]
			body:    'null'
		} }
	org := context.organization_record(id)!
	if (context.organization_find('member', {
		'organizationId': id
		'userId':         current.user.id
	})!).value == none {
		return fail(403, 'USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION',
			'User is not a member of the organization')
	}
	mut output := context.auth.organization_output('organization', org)!
	if path == 'get-full-organization' {
		members := context.organization_expanded_members(id, (fields['membersLimit'] or {
			json2.Any(0)
		}).int())!
		mut invitations := []json2.Any{}
		for encoded in context.organization_rows('invitation', {
			'organizationId': id
		})! {
			invitations << json2.Any(context.auth.organization_output('invitation',
				org_json_fields(encoded)!)!)
		}
		output['members'] = json2.Any(members)
		output['invitations'] = json2.Any(invitations)
	}
	response := admin_json_response(output)
	if path == 'set-active' {
		updated := context.organization_set_active(current.session, id)!
		return context.auth.set_session_cookies(response, SessionResult{
			session: updated
			user:    current.user
		})
	}
	return response
}

fn organization_server_add_member(mut context EndpointContext, fields map[string]json2.Any) !Response {
	current := (context.auth.current_session(context.auth.request_context)!).value
	session := if live := current { live.session } else { Session{} }
	id := organization_id(fields, session)
	if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
	org := context.organization_record(id)!
	user_id := organization_string(fields, 'userId')!
	user := (context.auth.storage.user(user_id)!).value or {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}

	role := admin_role(fields['role'] or { json2.Any('member') }, AdminOptions{})!
	options := context.auth.organization_options()!
	known := options.effective_roles()
	for name in role.split(',') {
		if name !in known { return fail(400, 'ROLE_NOT_FOUND', 'Role not found') }
	}
	additional := context.auth.organization_client_fields('member', fields, true)!
	member := context.organization_add_member(org, user, role, additional, false)!
	return admin_json_response(context.auth.organization_output('member', member)!)
}

fn organization_update(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	id := organization_id(fields, current.session)
	if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
	org := context.organization_record(id)!
	member := context.organization_require(current.user.id, id, 'organization', 'update',
		'YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION',
		'You are not allowed to update this organization')!
	supplied := (fields['data'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	mut patch := context.auth.organization_client_fields('organization', supplied, false)!
	for field in ['name', 'slug', 'logo', 'metadata'] {
		if value := supplied[field] { patch[field] = value }
	}
	for field in ['name', 'slug'] {
		if field in patch { organization_string(patch, field)! }
	}
	if value := patch['slug'] {
		if existing := (context.organization_find('organization', {
			'slug': value.str()
		})!).value
		{
			if (org_json_fields(existing)!['id'] or { json2.Any('') }).str() != id {
				return fail(400, 'ORGANIZATION_SLUG_ALREADY_TAKEN',
					'Organization slug already taken')
			}
		}
	}
	if changed := (context.organization_hook('beforeUpdateOrganization', {
		'organization': json2.Any(patch)
		'user':         json2.decode[json2.Any](encode_user(current.user))!
		'member':       json2.Any(member)
	})!).value
	{
		patch = organization_merge(patch, changed)!
	}
	organization_metadata(mut patch)!
	updated := organization_merge(org, json2.Any(patch).json_str())!
	proposed := context.auth.organization_defaults('organization', updated)!
	if (proposed['id'] or { json2.Any('') }).str() != id {
		return error('organization update hook cannot change identity')
	}
	actual := context.organization_update_record('organization', proposed)!
	output := context.auth.organization_output('organization', actual)!
	context.organization_hook('afterUpdateOrganization', {
		'organization': json2.Any(output)
		'user':         json2.decode[json2.Any](encode_user(current.user))!
		'member':       json2.Any(member)
	})!
	return admin_json_response(output)
}

fn organization_delete(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	options := context.auth.organization_options()!
	if options.disable_deletion {
		return fail(404, 'ORGANIZATION_DELETION_DISABLED', 'Organization deletion is disabled')
	}
	id := (fields['organizationId'] or { json2.Any('') }).str()
	org := context.organization_record(id)!
	member := context.organization_require(current.user.id, id, 'organization', 'delete',
		'YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION',
		'You are not allowed to delete this organization')!
	payload := {
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
		'user':         json2.decode[json2.Any](encode_user(current.user))!
		'member':       json2.Any(member)
	}
	context.organization_hook('beforeDeleteOrganization', payload)!
	mut storage := context.auth.storage
	if mut storage is OrganizationStorage { storage.organization_delete('organization', id)! }
	context.organization_hook('afterDeleteOrganization', payload)!
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    json2.Any(id).json_str()
	}
}
