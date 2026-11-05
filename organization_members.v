module better_auth

import better_auth.schema as model_schema
import x.json2

fn (mut context EndpointContext) organization_selected_id(fields map[string]json2.Any, session Session) !string {
	slug := (fields['organizationSlug'] or { json2.Any('') }).str()
	if slug != '' {
		encoded := (context.organization_find('organization', {
			'slug': slug
		})!).value or { return fail(400, 'ORGANIZATION_NOT_FOUND', 'Organization not found') }
		return (org_json_fields(encoded)!['id'] or { json2.Any('') }).str()
	}
	id := organization_id(fields, session)
	if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
	return id
}

struct OrganizationMemberRow {
	encoded string
	value   string
}

fn organization_list_members(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	id := context.organization_selected_id(fields, current.session)!
	context.organization_member(current.user.id, id)!
	options := context.auth.organization_options()!
	filter_field := (fields['filterField'] or { json2.Any('') }).str()
	sort_field := (fields['sortBy'] or { json2.Any('') }).str()
	for field in [filter_field, sort_field] {
		if field != '' && field !in model_schema.core_fields('member')
			&& field !in context.auth.config.model_fields['member'] {
			return fail(400, 'VALIDATION_ERROR', 'Unknown member field')
		}
	}
	mut rows := []OrganizationMemberRow{}
	for encoded in context.organization_rows('member', {
		'organizationId': id
	})! {
		row := org_json_fields(encoded)!
		if filter_field != '' {
			value := row[filter_field] or { json2.Any(json2.Null{}) }
			expected := fields['filterValue'] or { json2.Any('') }
			operator := (fields['filterOperator'] or { json2.Any('eq') }).str()
			mut serialized := expected.str()
			if expected is []json2.Any { serialized = expected.map(it.str()).join(',') }
			if !admin_matches(value, serialized, operator) { continue
			 }
		}
		rows << OrganizationMemberRow{
			encoded: encoded
			value:   (row[sort_field] or { json2.Any('') }).str()
		}
	}
	total := rows.len
	if sort_field != '' {
		if (fields['sortDirection'] or { json2.Any('asc') }).str() == 'desc' {
			rows.sort(a.value > b.value)
		} else {
			rows.sort(a.value < b.value)
		}
	}
	offset := (fields['offset'] or { json2.Any(0) }).int()
	requested := (fields['limit'] or { json2.Any(0) }).int()
	if offset < 0 || requested < 0 {
		return fail(400, 'VALIDATION_ERROR', 'Invalid member pagination')
	}
	limit := if requested != 0 {
		requested
	} else if options.membership_limit != 0 {
		options.membership_limit
	} else {
		100
	}
	start := if offset < total { offset } else { total }
	stop := if limit < total - start { start + limit } else { total }
	selected := rows[start..stop].map(it.encoded)
	members := context.organization_expand_members(selected)!
	return admin_json_response({
		'members': json2.Any(members)
		'total':   json2.Any(total)
	})
}

fn organization_active_member_role(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	id := context.organization_selected_id(fields, current.session)!
	actor := context.organization_member(current.user.id, id)!
	user_id := (fields['userId'] or { json2.Any(current.user.id) }).str()
	target := if user_id == current.user.id {
		actor
	} else {
		context.organization_member(user_id, id)!
	}
	return admin_json_response({
		'role': target['role'] or { json2.Any('') }
	})
}

fn (mut context EndpointContext) organization_guard_owner_removal(id string, member map[string]json2.Any, actor map[string]json2.Any) ! {
	creator := (context.auth.organization_options()!).creator_role
	if creator !in (member['role'] or { json2.Any('') }).str().split(',') { return }
	if creator !in (actor['role'] or { json2.Any('') }).str().split(',') {
		return fail(400, 'YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER',
			'You cannot leave the organization as the only owner')
	}
	mut owners := 0
	for row in context.organization_rows('member', {
		'organizationId': id
	})! {
		if creator in (org_json_fields(row)!['role'] or { json2.Any('') }).str().split(',') {
			owners++
		}
	}
	if owners <= 1 {
		return fail(400, 'YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER',
			'You cannot leave the organization as the only owner')
	}
}

fn organization_remove_member(mut context EndpointContext, current SessionResult, fields map[string]json2.Any, leaving bool) !Response {
	id := if leaving {
		organization_string(fields, 'organizationId')!
	} else {
		context.organization_selected_id(fields, current.session)!
	}
	actor := context.organization_member(current.user.id, id)!
	mut target := actor.clone()
	if !leaving {
		key := organization_string(fields, 'memberIdOrEmail')!
		mut filter := {
			'organizationId': id
		}
		if key.contains('@') {
			user := (context.auth.storage.user_by_email(key.to_lower())!).value or {
				return fail(400, 'MEMBER_NOT_FOUND', 'Member not found')
			}

			filter['userId'] = user.id
		} else {
			filter['id'] = key
		}
		encoded := (context.organization_find('member', filter)!).value or {
			return fail(400, 'MEMBER_NOT_FOUND', 'Member not found')
		}

		target = org_json_fields(encoded)!
	}
	context.organization_guard_owner_removal(id, target, actor)!
	if !leaving {
		if !context.organization_has_permission(id, (actor['role'] or { json2.Any('') }).str(), {
			'member': ['delete']
		})! {
			return fail(401, 'YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER',
				'You are not allowed to delete this member')
		}
	}
	org := context.organization_record(id)!
	user := (context.auth.storage.user((target['userId'] or { json2.Any('') }).str())!).value or {
		return fail(400, 'USER_NOT_FOUND', 'User not found')
	}

	payload := {
		'member':       json2.Any(target)
		'user':         json2.decode[json2.Any](encode_user(user))!
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
	}
	if !leaving { context.organization_hook('beforeRemoveMember', payload)! }
	mut storage := context.auth.storage
	if mut storage is OrganizationStorage { storage.organization_delete('member', (target['id'] or {
			json2.Any('')}).str())! }
	mut session := current.session
	if current.user.id == user.id && organization_id(map[string]json2.Any{}, session) == id {
		session = context.organization_set_active(session, none)!
	}
	if !leaving { context.organization_hook('afterRemoveMember', payload)! }
	output := context.auth.organization_output('member', target)!
	response := if leaving { admin_json_response(output) } else { admin_json_response({
			'member': json2.Any(output)
		}) }
	return context.auth.set_session_cookies(response, SessionResult{
		session: session
		user:    current.user
	})
}
