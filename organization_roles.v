module better_auth

import better_auth.domain.permissions as permission_policy
import json
import x.json2

pub struct OrganizationDynamicAccessControl {
pub:
	enabled       bool
	maximum_roles ?int @[json: maximumRolesPerOrganization]
}

fn (mut context EndpointContext) organization_roles(id string) !map[string]map[string][]string {
	options := context.auth.organization_options()!
	mut roles := options.effective_roles()
	if !options.dynamic_access_control.enabled || options.ac_statements == none { return roles }
	for encoded in context.organization_rows('organizationRole', {
		'organizationId': id
	})! {
		row := org_json_fields(encoded)!
		name := (row['role'] or { json2.Any('') }).str()
		permissions :=
			json2.decode[map[string][]string]((row['permission'] or { json2.Any('{}') }).str())!
		mut merged := (roles[name] or {
			map[string][]string{}
		}).clone()
		for resource, actions in permissions {
			mut combined_actions := (merged[resource] or { []string{} }).clone()
			for action in actions {
				if action !in combined_actions { combined_actions << action }
			}
			merged[resource] = combined_actions
		}
		roles[name] = merged.clone()
	}
	return roles
}

fn (mut context EndpointContext) organization_has_permission(id string, role string, permissions map[string][]string) !bool {
	return permission_policy.allows(role, context.organization_roles(id)!, permissions)
}

fn (mut context EndpointContext) organization_validate_roles(id string, role string) ! {
	options := context.auth.organization_options()!
	mut names := options.effective_roles().keys()
	names << ['owner', 'admin', 'member']
	if options.dynamic_access_control.enabled {
		for encoded in context.organization_rows('organizationRole', {
			'organizationId': id
		})! {
			names << (org_json_fields(encoded)!['role'] or { json2.Any('') }).str()
		}
	}
	for name in role.split(',') {
		if name !in names { return fail(400, 'ROLE_NOT_FOUND', 'ROLE_NOT_FOUND: ' + name) }
	}
}

fn (mut context EndpointContext) organization_member(user_id string, id string) !map[string]json2.Any {
	row := (context.organization_find('member', {
		'organizationId': id
		'userId':         user_id
	})!).value or {
		return fail(403, 'YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION',
			'You are not a member of this organization')
	}

	return org_json_fields(row)
}

fn (auth &Auth) organization_role_output(data map[string]json2.Any) !map[string]json2.Any {
	mut result := auth.organization_output('organizationRole', data)!
	if value := result['permission'] { result['permission'] = json2.decode[json2.Any](value.str())! }
	return result
}

fn (mut context EndpointContext) organization_role_name_available(id string, name string) ! {
	options := context.auth.organization_options()!
	if name in options.effective_roles() {
		return fail(400, 'ROLE_NAME_IS_ALREADY_TAKEN', 'That role name is already taken')
	}
	if (context.organization_find('organizationRole', {
		'organizationId': id
		'role':           name
	})!).value != none {
		return fail(400, 'ROLE_NAME_IS_ALREADY_TAKEN', 'That role name is already taken')
	}
}

fn (mut context EndpointContext) organization_role_grants(id string, role string, value json2.Any, action string) !map[string][]string {
	permissions := json2.decode[map[string][]string](value.json_str()) or {
		return fail(400, 'VALIDATION_ERROR', 'Invalid permission map')
	}
	options := context.auth.organization_options()!
	statements := (options.ac_statements or {
		return fail(501, 'MISSING_AC_INSTANCE',
			'Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information')
	}).clone()
	mut missing := []string{}
	for resource, actions in permissions {
		if resource !in statements {
			return fail(400, 'INVALID_RESOURCE',
				'The provided permission includes an invalid resource')
		}
		for permission in actions {
			if !context.organization_has_permission(id, role, {
				resource: [permission]
			})! {
				missing << resource + ':' + permission
			}
		}
	}
	if missing.len > 0 {
		return APIError{
			status:  403
			code:    'YOU_ARE_NOT_ALLOWED_TO_' + action.to_upper() + '_A_ROLE'
			message: 'You are not allowed to ' + action + ' a role'
			details: {
				'missingPermissions': json2.Any(missing)
			}
		}
	}
	return permissions
}

fn organization_permission_endpoint(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	id := organization_id(fields, current.session)
	if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
	member := context.organization_member(current.user.id, id)!
	permissions := json2.decode[map[string][]string]((fields['permissions'] or {
		json2.Any(json2.Null{})
	}).json_str()) or { return fail(400, 'VALIDATION_ERROR', 'Invalid permission map') }
	permitted := context.organization_has_permission(id,
		(member['role'] or { json2.Any('') }).str(), permissions)!
	return admin_json_response({
		'success': json2.Any(permitted)
		'error':   json2.Any(json2.Null{})
	})
}

fn organization_role_endpoint(mut context EndpointContext, current SessionResult, fields map[string]json2.Any, path string) !Response {
	options := context.auth.organization_options()!
	if !options.dynamic_access_control.enabled { return fail(404, 'NOT_FOUND', 'Not found') }
	id := organization_id(fields, current.session)
	if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
	member := context.organization_member(current.user.id, id)!
	member_role := (member['role'] or { json2.Any('') }).str()
	action := match path {
		'create-role' { 'create' }
		'update-role' { 'update' }
		'delete-role' { 'delete' }
		'list-roles' { 'list' }
		else { 'read' }
	}

	grant := if action == 'list' { 'read' } else { action }
	if !context.organization_has_permission(id, member_role, {
		'ac': [grant]
	})! {
		return fail(403, 'YOU_ARE_NOT_ALLOWED_TO_' + action.to_upper() + '_A_ROLE',

			'You are not allowed to ' + action + ' a role')
	}
	if path == 'list-roles' {
		mut roles := []json2.Any{}
		for encoded in context.organization_rows('organizationRole', {
			'organizationId': id
		})! {
			roles << json2.Any(context.auth.organization_role_output(org_json_fields(encoded)!)!)
		}
		return Response{
			headers: [Header{'content-type', 'application/json'}]
			body:    json2.Any(roles).json_str()
		}
	}
	if path == 'create-role' {
		name := organization_string(fields, 'role')!.to_lower()
		context.organization_role_name_available(id, name)!
		if maximum := options.dynamic_access_control.maximum_roles {
			if (context.organization_rows('organizationRole', {
				'organizationId': id
			})!).len >= maximum {
				return fail(400, 'TOO_MANY_ROLES', 'This organization has too many roles')
			}
		}
		permissions := context.organization_role_grants(id, member_role, fields['permission'] or {
			json2.Any(json2.Null{})
		}, 'create')!
		supplied := (fields['additionalFields'] or { json2.Any(map[string]json2.Any{}) }).as_map()
		mut data := context.auth.organization_client_fields('organizationRole', supplied, true)!
		data['id'] = context.auth.new_id('organizationRole')!
		data['organizationId'] = id
		data['role'] = name
		data['permission'] = json.encode(permissions)
		data['createdAt'] = stamp_millis(context.auth.clock_millis())
		data = context.auth.organization_defaults('organizationRole', data)!
		context.organization_create_record('organizationRole', data)!
		return admin_json_response({
			'success':    json2.Any(true)
			'roleData':   json2.Any(context.auth.organization_role_output(data)!)
			'statements': json2.decode[json2.Any](json.encode(permissions))!
		})
	}
	mut filter := {
		'organizationId': id
	}
	if role_id := fields['roleId'] {
		filter['id'] = role_id.str()
	} else {
		name := organization_string(fields, 'roleName')!
		if path == 'delete-role' && name in options.effective_roles() {
			return fail(400, 'CANNOT_DELETE_A_PRE_DEFINED_ROLE', 'Cannot delete a pre-defined role')
		}
		filter['role'] = name
	}
	encoded := (context.organization_find('organizationRole', filter)!).value or {
		return fail(400, 'ROLE_NOT_FOUND', 'Role not found')
	}

	mut data := org_json_fields(encoded)!
	if path == 'get-role' {
		return admin_json_response(context.auth.organization_role_output(data)!)
	}
	if path == 'delete-role' {
		name := (data['role'] or { json2.Any('') }).str()
		for row in context.organization_rows('member', {
			'organizationId': id
		})! {
			if name in (org_json_fields(row)!['role'] or { json2.Any('') }).str().split(',').map(it.trim_space()) {
				return fail(400, 'ROLE_IS_ASSIGNED_TO_MEMBERS',
					'Cannot delete a role that is assigned to members. Please reassign the members to a different role first')
			}
		}
		mut storage := context.auth.storage
		if mut storage is OrganizationStorage { storage.organization_delete('organizationRole', (data['id'] or {
				json2.Any('')}).str())! }
		return admin_json_response({
			'success': json2.Any(true)
		})
	}
	supplied := (fields['data'] or { json2.Any(map[string]json2.Any{}) }).as_map()
	patch := context.auth.organization_client_fields('organizationRole', supplied, false)!
	for field, value in patch {
		data[field] = value
	}
	if permission := supplied['permission'] {
		grants := context.organization_role_grants(id, member_role, permission, 'update')!
		data['permission'] = json.encode(grants)
	}
	if name := supplied['roleName'] {
		normalized := name.str().to_lower()
		context.organization_role_name_available(id, normalized)!
		data['role'] = normalized
	}
	actual := context.organization_update_record('organizationRole', data)!
	return admin_json_response({
		'success':  json2.Any(true)
		'roleData': json2.Any(context.auth.organization_role_output(actual)!)
	})
}

fn organization_update_member_role(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	id := organization_id(fields, current.session)
	if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
	actor := context.organization_member(current.user.id, id)!
	member_id := organization_string(fields, 'memberId')!
	encoded := (context.organization_find('member', {
		'id': member_id
	})!).value or { return fail(400, 'MEMBER_NOT_FOUND', 'Member not found') }
	mut target := org_json_fields(encoded)!
	if (target['organizationId'] or { json2.Any('') }).str() != id {
		return fail(403, 'YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER',
			'You are not allowed to update this member')
	}
	raw_role := admin_role(fields['role'] or { json2.Any('') }, AdminOptions{})!
	mut normalized := []string{}
	for item in raw_role.split(',') {
		name := item.trim_space()
		if name != '' && name !in normalized { normalized << name }
	}
	if normalized.len == 0 { return fail(400, 'BAD_REQUEST', 'Invalid role') }
	role := normalized.join(',')
	options := context.auth.organization_options()!
	actor_role := (actor['role'] or { json2.Any('') }).str()
	previous_role := (target['role'] or { json2.Any('') }).str()
	owner := options.creator_role in actor_role.split(',')
	if !owner {
		if options.creator_role in previous_role.split(',')
			|| options.creator_role in role.split(',') {
			return fail(403, 'YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER',
				'You are not allowed to update this member')
		}
		if !context.organization_has_permission(id, actor_role, {
			'member': ['update']
		})! {
			return fail(403, 'YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER',
				'You are not allowed to update this member')
		}
	}
	if owner && (actor['id'] or { json2.Any('') }).str() == member_id
		&& options.creator_role !in role.split(',') {
		mut owners := 0
		for encoded_owner in context.organization_rows('member', {
			'organizationId': id
		})! {
			if options.creator_role in (org_json_fields(encoded_owner)!['role'] or { json2.Any('') }).str().split(',') {
				owners++
			}
		}
		if owners <= 1 {
			return fail(400, 'YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER',
				'You cannot leave the organization without an owner')
		}
	}
	context.organization_validate_roles(id, role)!
	org := context.organization_record(id)!
	user := (context.auth.storage.user((target['userId'] or { json2.Any('') }).str())!).value or {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}

	mut payload := {
		'member':       json2.Any(target)
		'newRole':      json2.Any(role)
		'user':         json2.decode[json2.Any](encode_user(user))!
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
	}
	mut assigned := role
	if patch := (context.organization_hook('beforeUpdateMemberRole', payload)!).value {
		changes := org_json_fields(patch)!
		if replacement := changes['role'] {
			if js_truthy(replacement) { assigned = replacement.str() }
		}
	}
	target['role'] = assigned
	actual := context.organization_update_record('member', target)!
	payload['member'] = json2.Any(actual)
	payload['previousRole'] = previous_role
	context.organization_hook('afterUpdateMemberRole', payload)!
	return admin_json_response(context.auth.organization_output('member', actual)!)
}
