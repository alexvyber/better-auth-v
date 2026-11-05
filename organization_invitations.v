module better_auth

import x.json2

fn (mut context EndpointContext) invitation_claim(id string, status string) ! {
	mut storage := context.auth.storage
	if mut storage is OrganizationStorage {
		if storage.organization_claim_invitation(id, 'pending', status)! { return }
	}
	return fail(400, 'INVITATION_NOT_FOUND', 'Invitation not found')
}

fn (mut context EndpointContext) invitation_send(invitation map[string]json2.Any, org map[string]json2.Any, member map[string]json2.Any, user User) ! {
	mut inviter := member.clone()
	inviter['user'] = json2.decode[json2.Any](encode_user(user))!
	(context.auth.organization_options()!).send_invitation_email(mut context, json2.Any({
		'id':           invitation['id'] or { json2.Any('') }
		'email':        invitation['email'] or { json2.Any('') }
		'role':         invitation['role'] or { json2.Any('') }
		'invitation':   json2.Any(context.auth.organization_output('invitation', invitation)!)
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
		'inviter':      json2.Any(inviter)
	}).json_str())!
}

fn organization_invitation_create(mut context EndpointContext, current SessionResult, fields map[string]json2.Any) !Response {
	options := context.auth.organization_options()!
	id := organization_id(fields, current.session)
	if id == '' { return fail(400, 'ORGANIZATION_NOT_FOUND', 'Organization not found') }
	email := normalize_email(organization_string(fields, 'email')!)!
	member := context.organization_require(current.user.id, id, 'invitation', 'create',
		'YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION',
		'You are not allowed to invite users to this organization')!
	role := admin_role(fields['role'] or { json2.Any('member') }, AdminOptions{})!
	context.organization_validate_roles(id, role)!
	if options.creator_role in role.split(',') && options.creator_role !in (member['role'] or {
		json2.Any('')
	}).str().split(',') {
		return fail(403, 'YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE',
			'You are not allowed to invite user with this role')
	}
	if user := (context.auth.storage.user_by_email(email)!).value {
		if (context.organization_find('member', {
			'organizationId': id
			'userId':         user.id
		})!).value != none {
			return fail(400, 'USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION',
				'User is already a member of this organization')
		}
	}
	org := context.organization_record(id)!
	mut pending := []map[string]json2.Any{}
	mut total := 0
	for encoded in context.organization_rows('invitation', {
		'organizationId': id
		'status':         'pending'
	})! {
		row := org_json_fields(encoded)!
		if epoch_millis((row['expiresAt'] or { json2.Any('') }).str())! > context.auth.clock_millis() {
			total++
			if (row['email'] or { json2.Any('') }).str() == email { pending << row }
		}
	}
	duration := if options.invitation_expires_in == 0 {
		f64(172800)
	} else {
		options.invitation_expires_in
	}
	expires := stamp_millis(context.auth.clock_millis() + i64(duration * 1000))
	if pending.len > 0 {
		if (fields['resend'] or { json2.Any(false) }).bool() {
			mut invitation := pending[0].clone()
			invitation['expiresAt'] = expires
			actual := context.organization_update_record('invitation', invitation)!
			context.invitation_send(actual, org, member, current.user)!
			return admin_json_response(context.auth.organization_output('invitation', actual)!)
		}
		if !options.cancel_pending_invitations {
			return fail(400, 'USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION',
				'User is already invited to this organization')
		}
		context.invitation_claim((pending[0]['id'] or { json2.Any('') }).str(), 'canceled')!
		total--
	}
	limit := if options.invitation_limit_callback != no_invitation_limit {
		options.invitation_limit_callback(mut context, json2.Any({
			'user':         json2.decode[json2.Any](encode_user(current.user))!
			'organization': json2.Any(context.auth.organization_output('organization', org)!)
			'member':       json2.Any(member)
		}).json_str())!
	} else {
		options.invitation_limit
	}
	if total >= limit {
		return fail(403, 'INVITATION_LIMIT_REACHED', 'Invitation limit reached')
	}
	mut invitation := context.auth.organization_client_fields('invitation', fields, true)!
	invitation['email'] = email
	invitation['role'] = role
	invitation['organizationId'] = id
	invitation['inviterId'] = current.user.id
	payload := {
		'invitation':   json2.Any(invitation)
		'inviter':      json2.decode[json2.Any](encode_user(current.user))!
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
	}
	if patch := (context.organization_hook('beforeCreateInvitation', payload)!).value {
		invitation = organization_merge(invitation, patch)!
	}
	// Hooks can add fields and IDs; the checked tenant and inviter remain authoritative.
	invitation['organizationId'] = id
	invitation['inviterId'] = current.user.id
	if 'id' !in invitation { invitation['id'] = context.auth.new_id('invitation')! }
	invitation['status'] = 'pending'
	invitation['expiresAt'] = expires
	invitation['createdAt'] = stamp_millis(context.auth.clock_millis())
	invitation = context.auth.organization_defaults('invitation', invitation)!
	context.organization_create_record('invitation', invitation)!
	context.invitation_send(invitation, org, member, current.user)!
	context.organization_hook('afterCreateInvitation', {
		'invitation':   json2.Any(context.auth.organization_output('invitation', invitation)!)
		'inviter':      json2.decode[json2.Any](encode_user(current.user))!
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
	})!
	return admin_json_response(context.auth.organization_output('invitation', invitation)!)
}

fn organization_invitation_endpoint(mut context EndpointContext, current SessionResult, fields map[string]json2.Any, path string) !Response {
	if path == 'invite-member' {
		return organization_invitation_create(mut context, current, fields)
	}
	if path == 'list-invitations' {
		id := organization_id(fields, current.session)
		if id == '' { return fail(400, 'ORGANIZATION_NOT_FOUND', 'Organization ID is required') }
		if (context.organization_find('member', {
			'organizationId': id
			'userId':         current.user.id
		})!).value == none {
			return fail(403, 'USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION',
				'You are not a member of this organization')
		}
		mut invitations := []json2.Any{}
		for encoded in context.organization_rows('invitation', {
			'organizationId': id
		})! {
			invitations << json2.Any(context.auth.organization_output('invitation',
				org_json_fields(encoded)!)!)
		}
		return Response{
			headers: [Header{'content-type', 'application/json'}]
			body:    json2.Any(invitations).json_str()
		}
	}
	key := if path == 'get-invitation' { 'id' } else { 'invitationId' }
	id := organization_string(fields, key)!
	encoded := (context.organization_find('invitation', {
		'id': id
	})!).value or { return fail(400, 'INVITATION_NOT_FOUND', 'Invitation not found') }
	mut invitation := org_json_fields(encoded)!
	org_id := (invitation['organizationId'] or { json2.Any('') }).str()
	org := context.organization_record(org_id)!
	if path == 'cancel-invitation' {
		context.organization_require(current.user.id, org_id, 'invitation', 'cancel',
			'YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION',
			'You are not allowed to cancel this invitation')!
		payload := {
			'invitation':   json2.Any(invitation)
			'cancelledBy':  json2.decode[json2.Any](encode_user(current.user))!
			'organization': json2.Any(context.auth.organization_output('organization', org)!)
		}
		context.organization_hook('beforeCancelInvitation', payload)!
		invitation['status'] = 'canceled'
		actual := context.organization_update_record('invitation', invitation)!
		mut after := payload.clone()
		after['invitation'] = json2.Any(actual)
		context.organization_hook('afterCancelInvitation', after)!
		return admin_json_response(context.auth.organization_output('invitation', actual)!)
	}
	if (invitation['status'] or { json2.Any('') }).str() != 'pending' {
		return fail(400, 'INVITATION_NOT_FOUND', 'Invitation not found')
	}
	if path != 'reject-invitation' {
		if epoch_millis((invitation['expiresAt'] or { json2.Any('') }).str())! < context.auth.clock_millis() {
			return fail(400, 'INVITATION_NOT_FOUND', 'Invitation not found')
		}
	}
	if (invitation['email'] or { json2.Any('') }).str().to_lower() != current.user.email.to_lower() {
		return fail(403, 'YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION',
			'You are not the recipient of the invitation')
	}
	options := context.auth.organization_options()!
	required := options.require_verified_invitation or {
		context.auth.config.generate_id != no_id_generator
	}

	if required && !current.user.email_verified {
		if path == 'get-invitation' {
			return fail(403, 'EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION',
				'Email verification required for invitation')
		}
		return fail(403, 'EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION',
			'Email verification required before accepting or rejecting invitation')
	}
	if path == 'get-invitation' {
		inviter_id := (invitation['inviterId'] or { json2.Any('') }).str()
		if (context.organization_find('member', {
			'organizationId': org_id
			'userId':         inviter_id
		})!).value == none {
			return fail(400, 'INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION',
				'Inviter is no longer a member of the organization')
		}
		inviter := (context.auth.storage.user(inviter_id)!).value or {
			return fail(400, 'USER_NOT_FOUND', 'User not found')
		}

		mut result := context.auth.organization_output('invitation', invitation)!
		result['organizationName'] = org['name'] or { json2.Any('') }
		result['organizationSlug'] = org['slug'] or { json2.Any('') }
		result['inviterEmail'] = inviter.email
		return admin_json_response(result)
	}
	mut payload := {
		'invitation':   json2.Any(invitation)
		'user':         json2.decode[json2.Any](encode_user(current.user))!
		'organization': json2.Any(context.auth.organization_output('organization', org)!)
	}
	if path == 'reject-invitation' {
		context.organization_hook('beforeRejectInvitation', payload)!
		context.invitation_claim(id, 'rejected')!
		invitation['status'] = 'rejected'
		payload['invitation'] = json2.Any(invitation)
		context.organization_hook('afterRejectInvitation', payload)!
		return admin_json_response({
			'invitation': json2.Any(context.auth.organization_output('invitation', invitation)!)
			'member':     json2.Any(json2.Null{})
		})
	}
	limit := if options.membership_limit == 0 { 100 } else { options.membership_limit }
	if (context.organization_rows('member', {
		'organizationId': org_id
	})!).len >= limit {
		return fail(403, 'ORGANIZATION_MEMBERSHIP_LIMIT_REACHED',
			'Organization membership limit reached')
	}
	context.organization_hook('beforeAcceptInvitation', payload)!
	context.organization_lock_mutations()!
	if (context.organization_rows('member', {
		'organizationId': org_id
	})!).len >= limit {
		return fail(403, 'ORGANIZATION_MEMBERSHIP_LIMIT_REACHED',
			'Organization membership limit reached')
	}
	context.invitation_claim(id, 'accepted')!
	claimed := (context.organization_find('invitation', {
		'id': id
	})!).value or { return error('claimed invitation disappeared') }
	invitation = org_json_fields(claimed)!
	if (invitation['organizationId'] or { json2.Any('') }).str() != org_id || (invitation['email'] or {
		json2.Any('')
	}).str().to_lower() != current.user.email.to_lower() {
		return fail(400, 'INVITATION_NOT_FOUND', 'Invitation changed during acceptance')
	}
	member := context.auth.organization_defaults('member', {
		'id':             json2.Any(context.auth.new_id('member')!)
		'organizationId': json2.Any(org_id)
		'userId':         json2.Any(current.user.id)
		'role':           invitation['role'] or { json2.Any('member') }
		'createdAt':      json2.Any(stamp_millis(context.auth.clock_millis()))
	})!
	context.organization_create_record('member', member)!
	updated := context.organization_set_active(current.session, org_id)!
	payload['invitation'] = json2.Any(invitation)
	payload['member'] = json2.Any(member)
	context.organization_hook('afterAcceptInvitation', payload)!
	return context.auth.set_session_cookies(admin_json_response({
		'invitation': json2.Any(context.auth.organization_output('invitation', invitation)!)
		'member':     json2.Any(context.auth.organization_output('member', member)!)
	}), SessionResult{ session: updated, user: current.user })
}

fn organization_list_user_invitations(mut context EndpointContext, fields map[string]json2.Any) !Response {
	actor := (context.auth.current_session(context.auth.request_context)!).value
	if context.auth.request_context.request != none && 'email' in fields {
		return fail(400, 'BAD_REQUEST', 'User email cannot be passed for client side API calls.')
	}
	mut email := ''
	if current := actor {
		user := (context.auth.storage.user(current.user.id)!).value or {
			return fail(401, 'UNAUTHORIZED', 'Unauthorized')
		}

		if !user.email_verified {
			return fail(403, 'EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION',
				'Email verification required for invitation')
		}
		email = user.email
	} else {
		if !context.trusted_headerless_call() { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
		email = (fields['email'] or { json2.Any('') }).str()
	}
	if email == '' {
		return fail(400, 'BAD_REQUEST', 'Missing session headers, or email query parameter.')
	}
	mut result := []json2.Any{}
	for encoded in context.organization_rows('invitation', {
		'email':  email.to_lower()
		'status': 'pending'
	})! {
		row := org_json_fields(encoded)!
		mut invitation := context.auth.organization_output('invitation', row)!
		if organization := (context.organization_find('organization', {
			'id': (row['organizationId'] or { json2.Any('') }).str()
		})!).value
		{
			invitation['organizationName'] = org_json_fields(organization)!['name'] or {
				json2.Any('')
			}
		}
		result << json2.Any(invitation)
	}
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    json2.Any(result).json_str()
	}
}
