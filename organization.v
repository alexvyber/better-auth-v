module better_auth

import better_auth.schema as model_schema
import net.urllib
import x.json2

pub struct OrganizationOptions {
pub:
	allow_user_to_create        bool = true   @[json: allowUserToCreateOrganization]
	organization_limit          ?int   @[json: organizationLimit]
	membership_limit            int    = 100    @[json: membershipLimit]
	creator_role                string = 'owner' @[json: creatorRole]
	invitation_expires_in       f64    = 172800    @[json: invitationExpiresIn]
	invitation_limit_callback   fn (mut EndpointContext, string) !int = no_invitation_limit @[skip]
	invitation_limit            int = 100   @[json: invitationLimit]
	cancel_pending_invitations  bool  @[json: cancelPendingInvitationsOnReInvite]
	require_verified_invitation ?bool @[json: requireEmailVerificationOnInvitation]
	send_invitation_email       fn (mut EndpointContext, string) ! = no_invitation_email @[skip]
	disable_deletion            bool @[json: disableOrganizationDeletion]
	dynamic_access_control      OrganizationDynamicAccessControl @[json: dynamicAccessControl]
	ac_statements               ?map[string][]string             @[json: acStatements]
	roles                       ?map[string]map[string][]string
	additional_fields           map[string]map[string]AdditionalField                    @[skip]
	hook                        fn (mut EndpointContext, string, string) !Lookup[string] = no_organization_hook @[skip]
	allow_creation              fn (mut EndpointContext, User) !bool                     = default_organization_creation                     @[skip]
}

fn no_invitation_limit(mut _ EndpointContext, _ string) !int {
	return error('invitation limit callback is not configured')
}

fn no_invitation_email(mut _ EndpointContext, _ string) ! {}

fn no_organization_hook(mut _ EndpointContext, _ string, _ string) !Lookup[string] {
	return Lookup[string]{}
}

fn default_organization_creation(mut _ EndpointContext, _ User) !bool {
	return true
}

pub struct OrganizationPlugin {
pub:
	options OrganizationOptions
}

pub fn (_ OrganizationPlugin) id() string {
	return 'organization'
}

pub fn (plugin OrganizationPlugin) schema() PluginFields {
	return PluginFields{
		session: OrganizationSchemaPlugin{}.schema().session
		models:  plugin.options.additional_fields
	}
}

pub fn (plugin OrganizationPlugin) validate() ! {
	validate_organization_fields(plugin.options.additional_fields)!
}

pub fn (plugin OrganizationPlugin) endpoints() []Endpoint {
	mut routes := []Endpoint{}
	for path in ['create', 'update', 'delete', 'check-slug', 'set-active', 'invite-member',
		'accept-invitation', 'reject-invitation', 'cancel-invitation', 'has-permission',
		'update-member-role', 'create-role', 'update-role', 'delete-role', 'remove-member', 'leave'] {
		routes << Endpoint{
			path:           '/organization/' + path
			hide_from_docs: !plugin.options.dynamic_access_control.enabled
				&& path in ['create-role', 'update-role', 'delete-role']
			handler:        organization_endpoint
		}
	}
	for path in ['get-full-organization', 'get-organization', 'list', 'get-active-member',
		'list-members', 'get-invitation', 'list-invitations', 'list-user-invitations', 'list-roles',
		'get-role', 'get-active-member-role'] {
		routes << Endpoint{
			path:           '/organization/' + path
			hide_from_docs: !plugin.options.dynamic_access_control.enabled
				&& path in ['get-role', 'list-roles']
			method:         'GET'
			handler:        organization_endpoint
		}
	}
	routes << Endpoint{
		path:    '/internal/organization/add-member'
		handler: organization_endpoint
	}
	return routes
}

fn (auth &Auth) organization_options() !OrganizationOptions {
	for plugin in auth.config.plugins {
		if plugin is OrganizationPlugin { return plugin.options }
	}
	return error('organization plugin is not configured')
}

fn (mut context EndpointContext) organization_rows(model string, filter map[string]string) ![]string {
	mut storage := context.auth.storage
	if mut storage is OrganizationStorage { return storage.organization_rows(model, filter) }
	return error('organization storage is not supported by this adapter')
}

fn (mut context EndpointContext) organization_create_record(model string, data map[string]json2.Any) !map[string]json2.Any {
	mut storage := context.auth.storage
	if mut storage is OrganizationStorage {
		storage.organization_create(model, json2.Any(data).json_str())!
		return data
	}
	return error('organization storage is not supported by this adapter')
}

fn (mut context EndpointContext) organization_update_record(model string, data map[string]json2.Any) !map[string]json2.Any {
	mut storage := context.auth.storage
	if mut storage is OrganizationStorage {
		storage.organization_update(model, json2.Any(data).json_str())!
		rows := storage.organization_rows(model, {
			'id': (data['id'] or { return error('organization update requires id') }).str()
		})!
		if rows.len == 0 { return error('updated organization record disappeared') }
		return org_json_fields(rows[0])
	}
	return error('organization storage is not supported by this adapter')
}

fn (mut context EndpointContext) organization_find(model string, filter map[string]string) !Lookup[string] {
	rows := context.organization_rows(model, filter)!
	return if rows.len > 0 {
		Lookup[string]{
			value: rows[0]
		}
	} else {
		Lookup[string]{}
	}
}

fn (mut context EndpointContext) organization_record(id string) !map[string]json2.Any {
	encoded := (context.organization_find('organization', {
		'id': id
	})!).value or { return fail(400, 'ORGANIZATION_NOT_FOUND', 'Organization not found') }
	return org_json_fields(encoded)
}

fn (mut context EndpointContext) organization_actor(optional bool) !Lookup[SessionResult] {
	if live := (context.auth.current_session(context.auth.request_context)!).value {
		user := (context.auth.storage.user(live.user.id)!).value or {
			return fail(401, 'UNAUTHORIZED', 'Unauthorized')
		}

		return Lookup[SessionResult]{
			value: SessionResult{
				...live
				user: user
			}
		}
	}
	if optional && context.trusted_headerless_call() { return Lookup[SessionResult]{} }
	return fail(401, 'UNAUTHORIZED', 'Unauthorized')
}

fn (context &EndpointContext) trusted_headerless_call() bool {
	if context.auth.request_context.request != none { return false }
	for name, _ in context.auth.request_context.headers {
		if name != 'content-type' { return false }
	}
	return true
}

fn (mut context EndpointContext) organization_hook(name string, data map[string]json2.Any) !Lookup[string] {
	return (context.auth.organization_options()!).hook(mut context, name,
		json2.Any(data).json_str())
}

fn organization_merge(base map[string]json2.Any, patch string) !map[string]json2.Any {
	mut result := base.clone()
	for key, value in org_json_fields(patch)! {
		result[key] = value
	}
	return result
}

fn (auth &Auth) organization_output(model string, data map[string]json2.Any) !map[string]json2.Any {
	mut result := map[string]json2.Any{}
	schema := (auth.config.model_fields[model] or {
		map[string]AdditionalField{}
	}).clone()
	for key, value in data {
		if key !in model_schema.core_fields(model) {
			definition := schema[key] or { continue }
			if !definition.returned { continue
			 }
		}
		result[key] = value
	}
	if model == 'organization' {
		if metadata := result['metadata'] {
			if metadata is string { result['metadata'] = json2.decode[json2.Any](metadata)! }
		}
	}
	return result
}

fn (auth &Auth) organization_defaults(model string, data map[string]json2.Any) !map[string]json2.Any {
	mut result := map[string]json2.Any{}
	for field in model_schema.core_fields(model) {
		if value := data[field] { result[field] = value }
	}
	for field, definition in auth.config.model_fields[model] or {
		map[string]AdditionalField{}
	} {
		if value := data[field] {
			validate_field(definition, value)!
			result[field] = value
			continue
		}
		if fallback := (definition.resolve_default()!).value {
			validate_field(definition, fallback)!
			result[field] = fallback
			continue
		}
		if definition.required {
			return fail(400, 'MISSING_FIELD', field + ' is required')
		}
	}
	return result
}

fn (auth &Auth) organization_client_fields(model string, data map[string]json2.Any, creating bool) !map[string]json2.Any {
	mut allowed := map[string]json2.Any{}
	mut schema := map[string]AdditionalField{}
	for field, definition in auth.config.model_fields[model] or {
		map[string]AdditionalField{}
	} {
		if definition.input {
			schema[field] = definition
			if value := data[field] { allowed[field] = value }
		}
	}
	return parse_fields(schema, allowed, map[string]json2.Any{}, creating)
}

fn (options OrganizationOptions) effective_roles() map[string]map[string][]string {
	if roles := options.roles { return roles.clone() }
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

fn (mut context EndpointContext) organization_require(user_id string, organization_id string, resource string, action string, code string, message string) !map[string]json2.Any {
	encoded := (context.organization_find('member', {
		'organizationId': organization_id
		'userId':         user_id
	})!).value or {
		return fail(403, 'USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION',
			'User is not a member of the organization')
	}

	member := org_json_fields(encoded)!
	role := (member['role'] or { json2.Any('member') }).str()
	if !context.organization_has_permission(organization_id, role, {
		resource: [action]
	})! {
		return fail(403, code, message)
	}
	return member
}

fn (mut context EndpointContext) organization_set_active(session Session, id ?string) !Session {
	mut fields := session.additional_fields.clone()
	fields['activeOrganizationId'] = json2.Null{}
	if value := id { fields['activeOrganizationId'] = value }
	return context.auth.update_session_record(Session{ ...session, additional_fields: fields })
}

fn organization_id(fields map[string]json2.Any, session Session) string {
	if value := fields['organizationId'] {
		if js_truthy(value) { return value.str() }
	}
	value := session.additional_fields['activeOrganizationId'] or { json2.Any(json2.Null{}) }
	return if js_truthy(value) { value.str() } else { '' }
}

fn (mut context EndpointContext) organization_add_member(org map[string]json2.Any, user User, role string, additional map[string]json2.Any, creator bool) !map[string]json2.Any {
	id := (org['id'] or { return error('organization requires id') }).str()
	if (context.organization_find('member', {
		'organizationId': id
		'userId':         user.id
	})!).value != none {
		return fail(400, 'USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION',
			'User is already a member of this organization')
	}
	options := context.auth.organization_options()!
	limit := if options.membership_limit == 0 { 100 } else { options.membership_limit }
	if !creator && (context.organization_rows('member', {
		'organizationId': id
	})!).len >= limit {
		return fail(403, 'ORGANIZATION_MEMBERSHIP_LIMIT_REACHED',
			'Organization membership limit reached')
	}
	mut data := additional.clone()
	data['organizationId'] = id
	data['userId'] = user.id
	data['role'] = role
	org_output := context.auth.organization_output('organization', org)!
	payload := {
		'member':       json2.Any(data)
		'user':         json2.decode[json2.Any](encode_user(user))!
		'organization': json2.Any(org_output)
	}
	if patch := (context.organization_hook('beforeAddMember', payload)!).value {
		data = organization_merge(data, patch)!
	}
	if 'id' !in data { data['id'] = context.auth.new_id('member')! }
	data['createdAt'] = stamp_millis(context.auth.clock_millis())
	data = context.auth.organization_defaults('member', data)!
	context.organization_create_record('member', data)!
	context.organization_hook('afterAddMember', {
		'member':       json2.Any(data)
		'user':         json2.decode[json2.Any](encode_user(user))!
		'organization': json2.Any(org_output)
	})!
	return data
}

fn organization_endpoint(mut context EndpointContext, request Request) !Response {
	parsed := urllib.parse(request.url)!
	path := parsed.path.all_after_last('/')
	if path == 'add-member' && context.auth.request_context.request != none {
		return fail(404, 'NOT_FOUND', 'Not found')
	}
	mut fields := map[string]json2.Any{}
	if request.method == 'GET' {
		for item in parsed.query().data {
			if item.key == 'filterValue' {
				if previous := fields[item.key] {
					mut values := if previous is []json2.Any { previous.clone() } else { [
							previous,
						] }
					values << json2.Any(item.value)
					fields[item.key] = json2.Any(values)
					continue
				}
			}
			fields[item.key] = item.value
		}
	} else {
		fields = org_json_fields(request.body) or {
			return fail(400, 'VALIDATION_ERROR', 'Invalid request body')
		}
	}
	if path == 'add-member' {
		context.organization_lock_mutations()!
		return organization_server_add_member(mut context, fields)
	}
	if path == 'list-user-invitations' {
		return organization_list_user_invitations(mut context, fields)
	}
	actor := (context.organization_actor(path == 'create')!).value
	if path == 'create' {
		context.organization_lock_mutations()!
		return organization_create(mut context, actor, fields)
	}
	current := actor or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	// Acceptance invokes its before hook before claiming the invitation. Keep
	// that ordering; the acceptance handler acquires the aggregate barrier and
	// checks capacity again immediately before its atomic claim.
	if request.method == 'POST' && path !in ['has-permission', 'check-slug', 'accept-invitation'] {
		context.organization_lock_mutations()!
	}
	if path in ['invite-member', 'accept-invitation', 'reject-invitation', 'cancel-invitation',
		'get-invitation', 'list-invitations'] {
		return organization_invitation_endpoint(mut context, current, fields, path)
	}
	if path == 'has-permission' {
		return organization_permission_endpoint(mut context, current, fields)
	}
	if path == 'update-member-role' {
		return organization_update_member_role(mut context, current, fields)
	}
	if path in ['create-role', 'update-role', 'delete-role', 'list-roles', 'get-role'] {
		return organization_role_endpoint(mut context, current, fields, path)
	}
	match path {
		'list' {
			mut result := []json2.Any{}
			for encoded in context.organization_rows('member', {
				'userId': current.user.id
			})! {
				row := org_json_fields(encoded)!
				id := (row['organizationId'] or { json2.Any('') }).str()
				if org := (context.organization_find('organization', {
					'id': id
				})!).value
				{
					result << json2.Any(context.auth.organization_output('organization',
						org_json_fields(org)!)!)
				}
			}
			return Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    json2.Any(result).json_str()
			}
		}
		'check-slug' {
			if (context.organization_find('organization', {
				'slug': (fields['slug'] or { json2.Any('') }).str()
			})!).value != none {
				return fail(400, 'ORGANIZATION_SLUG_ALREADY_TAKEN',
					'Organization slug already taken')
			}
			return admin_json_response({
				'status': json2.Any(true)
			})
		}
		'get-organization', 'get-full-organization', 'set-active' {
			return organization_get_or_activate(mut context, current, fields, path)
		}
		'update' {
			return organization_update(mut context, current, fields)
		}
		'delete' {
			return organization_delete(mut context, current, fields)
		}
		'get-active-member' {
			id := organization_id(fields, current.session)
			if id == '' { return fail(400, 'NO_ACTIVE_ORGANIZATION', 'No active organization') }
			encoded := (context.organization_find('member', {
				'organizationId': id
				'userId':         current.user.id
			})!).value or { return fail(400, 'MEMBER_NOT_FOUND', 'Member not found') }
			return admin_json_response(context.auth.organization_output('member',
				org_json_fields(encoded)!)!)
		}
		'list-members' {
			return organization_list_members(mut context, current, fields)
		}
		'get-active-member-role' {
			return organization_active_member_role(mut context, current, fields)
		}
		'remove-member', 'leave' {
			return organization_remove_member(mut context, current, fields, path == 'leave')
		}
		else {
			return fail(404, 'NOT_FOUND', 'Not found')
		}
	}
}
