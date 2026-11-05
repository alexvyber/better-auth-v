module better_auth

import net.urllib
import x.json2

pub struct AdminOptions {
pub:
	allow_impersonating_admins     bool              @[json: allowImpersonatingAdmins]
	impersonation_session_duration f64    = 3600               @[json: impersonationSessionDuration]
	default_role                   string = 'user'            @[json: defaultRole]
	admin_roles                    ?[]string         @[json: adminRoles]
	admin_user_ids                 []string          @[json: adminUserIds]
	user_field_names               map[string]string @[json: userFieldNames]
	session_field_names            map[string]string @[json: sessionFieldNames]
	roles                          ?map[string]map[string][]string
	default_ban_reason             string = 'No reason' @[json: defaultBanReason]
	default_ban_expires_in         f64    @[json: defaultBanExpiresIn]
	banned_user_message            string = 'You have been banned from this application. Please contact support if you believe this is an error.' @[json: bannedUserMessage]
	banned_message                 fn (mut EndpointContext, User) !string = default_banned_message @[skip]
}

fn default_banned_message(mut _ EndpointContext, _ User) !string {
	return ''
}

pub struct AdminPlugin {
pub:
	options AdminOptions
}

pub fn (_ AdminPlugin) id() string {
	return 'admin'
}

pub fn (plugin AdminPlugin) schema() PluginFields {
	base := AdminSchemaPlugin{}.schema()
	mut users := base.user.clone()
	mut sessions := base.session.clone()
	for field, name in plugin.options.user_field_names {
		if current := users[field] { users[field] = AdditionalField{
				...current
				field_name: name
			} }
	}
	for field, name in plugin.options.session_field_names {
		if current := sessions[field] { sessions[field] = AdditionalField{
				...current
				field_name: name
			} }
	}
	return PluginFields{
		user:    users
		session: sessions
	}
}

pub fn (plugin AdminPlugin) prepare_user(user User) !User {
	return AdminSchemaPlugin{
		default_role: plugin.options.default_role
	}.prepare_user(user)
}

pub fn (plugin AdminPlugin) validate() ! {
	roles := plugin.options.effective_roles()
	for role in plugin.options.admin_roles or { []string{} } {
		if role.to_lower() !in roles.keys().map(it.to_lower()) {
			return error('Invalid admin roles: ${role}. Admin roles must be defined in the roles configuration.')
		}
	}
}

pub interface ValidatingPlugin {
	validate() !
}

pub interface SessionCreationPlugin {
	before_session(mut context EndpointContext, session Session) !
}

pub fn (plugin AdminPlugin) before_session(mut context EndpointContext, session Session) ! {
	user := (context.auth.storage.user(session.user_id)!).value or {
		return fail(404, 'USER_NOT_FOUND', 'User not found')
	}

	context.auth.check_admin_ban(user, plugin.options)!
}

fn (mut auth Auth) check_admin_ban(user User, options AdminOptions) ! {
	if !(user.additional_fields['banned'] or { json2.Any(false) }).bool() { return }
	if expires := user.additional_fields['banExpires'] {
		if expires is string {
			if epoch_millis(expires)! < auth.clock_millis() {
				mut fields := user.additional_fields.clone()
				fields['banned'] = false
				fields['banReason'] = json2.Null{}
				fields['banExpires'] = json2.Null{}
				auth.update_user_record(User{
					...user
					updated_at:        stamp_millis(auth.clock_millis())
					additional_fields: fields
				})!
				return
			}
		}
	}
	mut context := EndpointContext{
		auth: auth
	}
	mut message := options.banned_user_message
	if options.banned_message != default_banned_message {
		message = options.banned_message(mut context, user)!
	}
	return fail(403, 'BANNED_USER', message)
}

fn (options AdminOptions) effective_roles() map[string]map[string][]string {
	if roles := options.roles { return roles.clone() }
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

pub fn (options AdminOptions) has_permission(user User, permissions map[string][]string) bool {
	if user.id in options.admin_user_ids { return true }
	if permissions.len == 0 { return false }
	roles := options.effective_roles()
	for role in (user.additional_fields['role'] or { json2.Any(options.default_role) }).str().split(',') {
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

fn (a &Auth) admin_options() !AdminOptions {
	for plugin in a.config.plugins {
		if plugin is AdminPlugin { return plugin.options }
	}
	return error('admin plugin is not configured')
}

pub fn (_ AdminPlugin) endpoints() []Endpoint {
	mut result := []Endpoint{}
	for path in ['create-user', 'set-role', 'ban-user', 'unban-user', 'update-user',
		'set-user-password', 'remove-user', 'list-user-sessions', 'revoke-user-session',
		'revoke-user-sessions', 'has-permission', 'impersonate-user', 'stop-impersonating'] {
		result << Endpoint{
			path:    '/admin/' + path
			handler: admin_endpoint
		}
	}
	for path in ['get-user', 'list-users'] {
		result << Endpoint{
			path:    '/admin/' + path
			method:  'GET'
			handler: admin_endpoint
		}
	}
	return result
}

// Cookie cache is a presentation optimization, never an authorization source.
fn (mut context EndpointContext) admin_actor(optional bool) !Lookup[SessionResult] {
	request := context.auth.operation.request
	current := (context.auth.current_session(request)!).value or {
		mut has_headers := false
		for name, _ in request.headers {
			if name != 'content-type' { has_headers = true }
		}
		if optional && request.request == none && !has_headers { return Lookup[SessionResult]{} }
		return fail(401, 'UNAUTHORIZED', 'Unauthorized')
	}

	mut authoritative := Lookup[Session]{}
	if context.auth.database_sessions() {
		authoritative = context.auth.stored_session_for_token(current.session.token)!
	} else {
		live := (context.auth.find_session_record(current.session.token)!).value or {
			return fail(401, 'UNAUTHORIZED', 'Unauthorized')
		}

		authoritative = Lookup[Session]{
			value: live.session
		}
	}
	{
		stored := authoritative.value or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }

		if stored.user_id != current.user.id
			|| epoch_millis(stored.expires_at)! <= context.auth.clock_millis() {
			return fail(401, 'UNAUTHORIZED', 'Unauthorized')
		}
	}
	user := (context.auth.storage.user(current.user.id)!).value or {
		return fail(401, 'UNAUTHORIZED', 'Unauthorized')
	}

	context.auth.check_admin_ban(user, context.auth.admin_options()!)!
	return Lookup[SessionResult]{
		value: SessionResult{
			...current
			user: user
		}
	}
}

fn (mut context EndpointContext) admin_require(user User, resource string, action string, code string, message string) ! {
	if !(context.auth.admin_options()!).has_permission(user, {
		resource: [action]
	}) {
		return fail(403, code, message)
	}
}

fn admin_role(value json2.Any, options AdminOptions) !string {
	values := if value is []json2.Any { value } else { [value] }
	mut roles := []string{}
	for item in values {
		if item !is string { return fail(400, 'INVALID_ROLE_TYPE', 'Invalid role type') }
		if configured := options.roles {
			if item.str() !in configured {
				return fail(400, 'YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE',
					'You are not allowed to set a non-existent role value')
			}
		}
		roles << item.str()
	}
	return roles.join(',')
}

fn (mut context EndpointContext) admin_user(id string) !User {
	return (context.auth.storage.user(id)!).value or {
		return fail(404, 'USER_NOT_FOUND', 'User not found')
	}
}

fn (mut context EndpointContext) admin_patch(user User, patch map[string]json2.Any) !User {
	mut data := patch.clone()
	data['updatedAt'] = stamp_millis(context.auth.clock_millis())
	return context.auth.update_user_record(decode_user(merge_record_json(encode_user(user),
		json2.Any(data).json_str())!)!)
}

fn admin_endpoint(mut context EndpointContext, request Request) !Response {
	url := urllib.parse(request.url)!
	path := url.path.all_after_last('/')
	options := context.auth.admin_options()!
	actor := (context.admin_actor(path in ['create-user', 'has-permission'])!).value
	mut fields := map[string]json2.Any{}
	if request.method == 'GET' {
		for item in url.query().data {
			fields[item.key] = item.value
		}
	} else {
		fields = json2.decode[map[string]json2.Any](request.body) or {
			return fail(400, 'VALIDATION_ERROR', 'Invalid request body')
		}
	}
	if path == 'stop-impersonating' { return admin_stop_impersonating(mut context) }
	if path == 'impersonate-user' { return admin_impersonate(mut context, actor or {
			return fail(401, 'UNAUTHORIZED', 'Unauthorized')}, fields, options) }
	if path == 'create-user' { return admin_create_user(mut context, actor, fields, options) }
	if path == 'has-permission' {
		permission := fields['permissions'] or {
			return fail(400, 'BAD_REQUEST',
				'invalid permission check. no permission(s) were passed.')
		}
		permissions := json2.decode[map[string][]string](permission.json_str())!
		mut subject := User{}
		if live := actor {
			subject = live.user
		} else if role := fields['role'] {
			subject = User{
				id:                (fields['userId'] or { json2.Any('') }).str()
				additional_fields: {
					'role': role
				}
			}
		} else if id := fields['userId'] {
			subject = (context.auth.storage.user(id.str())!).value or {
				return fail(400, 'BAD_REQUEST', 'user not found')
			}
		} else {
			return fail(400, 'BAD_REQUEST', 'user id or role is required')
		}
		return admin_json_response({
			'error':   json2.Any(json2.Null{})
			'success': json2.Any(options.has_permission(subject, permissions))
		})
	}
	live := actor or { return fail(401, 'UNAUTHORIZED', 'Unauthorized') }
	if path == 'get-user' {
		context.admin_require(live.user, 'user', 'get', 'YOU_ARE_NOT_ALLOWED_TO_GET_USER',
			'You are not allowed to get user')!
		user := context.admin_user((fields['id'] or { json2.Any('') }).str())!
		return Response{
			headers: [Header{'content-type', 'application/json'}]
			body:    context.auth.user_json(user)
		}
	}
	if path == 'list-users' { return admin_list_users(mut context, live.user, fields) }
	if path == 'revoke-user-session' {
		context.admin_require(live.user, 'session', 'revoke',
			'YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS',
			'You are not allowed to revoke users sessions')!
		token := (fields['sessionToken'] or { json2.Any('') }).str()
		context.auth.remove_session(token)!
		return admin_json_response({
			'success': json2.Any(true)
		})
	}
	id := (fields['userId'] or { json2.Any('') }).str()
	if path == 'set-user-password' && id == '' {
		return fail(400, 'VALIDATION_ERROR', 'userId is required')
	}
	resource, action, code, message := match path {
		'set-role' { 'user', 'set-role', 'YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE', 'You are not allowed to change users role' }
		'ban-user', 'unban-user' { 'user', 'ban', 'YOU_ARE_NOT_ALLOWED_TO_BAN_USERS', 'You are not allowed to ban users' }
		'update-user' { 'user', 'update', 'YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS', 'You are not allowed to update users' }
		'set-user-password' { 'user', 'set-password', 'YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD', 'You are not allowed to set users password' }
		'remove-user' { 'user', 'delete', 'YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS', 'You are not allowed to delete users' }
		'list-user-sessions' { 'session', 'list', 'YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS', 'You are not allowed to list users sessions' }
		'revoke-user-sessions' { 'session', 'revoke', 'YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS', 'You are not allowed to revoke users sessions' }
		else { return fail(404, 'NOT_FOUND', 'Not found') }
	}

	context.admin_require(live.user, resource, action, code, message)!
	if path == 'set-user-password' { context.auth.check_password((fields['newPassword'] or {
			json2.Any('')}).str())! }
	user := context.admin_user(id)!
	mut patch := map[string]json2.Any{}
	match path {
		'set-role' {
			patch['role'] = admin_role(fields['role'] or { json2.Any(json2.Null{}) }, options)!
		}
		'ban-user' {
			if id == live.user.id {
				return fail(400, 'YOU_CANNOT_BAN_YOURSELF', 'You cannot ban yourself')
			}
			patch['banned'] = true
			mut reason := (fields['banReason'] or { json2.Any('') }).str()
			if reason == '' { reason = options.default_ban_reason }
			if reason == '' { reason = 'No reason' }
			patch['banReason'] = reason
			mut seconds := (fields['banExpiresIn'] or { json2.Any(0) }).f64()
			if seconds == 0 { seconds = options.default_ban_expires_in }
			if seconds < -8640000000000 || seconds > 8640000000000 {
				return fail(400, 'VALIDATION_ERROR', 'Invalid ban duration')
			}
			patch['banExpires'] = json2.Null{}
			if seconds != 0 {
				patch['banExpires'] = stamp_millis(i64(f64(context.auth.clock_millis()) +
					seconds * 1000))
			}
		}
		'unban-user' {
			patch['banned'] = false
			patch['banReason'] = json2.Null{}
			patch['banExpires'] = json2.Null{}
		}
		'update-user' {
			patch = (fields['data'] or { json2.Any(map[string]json2.Any{}) }).as_map()
			admin_validate_patch(mut context, live.user, user, mut patch, options)!
		}
		'set-user-password' {
			password := (fields['newPassword'] or { json2.Any('') }).str()
			hashed := context.auth.config.password_hasher.hash(password)!
			if (context.auth.storage.account(id, 'credential')!).value != none {
				context.auth.update_password(id, hashed)!
			} else {
				context.auth.persist_account(Account{
					id:          context.auth.new_id('account')!
					user_id:     id
					account_id:  id
					provider_id: 'credential'
					password:    hashed
				})!
			}
			return admin_json_response({
				'status': json2.Any(true)
			})
		}
		'remove-user' {
			if id == live.user.id {
				return fail(400, 'YOU_CANNOT_REMOVE_YOURSELF', 'You cannot remove yourself')
			}
			context.auth.remove_user(id)!
			return admin_json_response({
				'success': json2.Any(true)
			})
		}
		'list-user-sessions' {
			sessions := context.auth.user_sessions(id)!
			return Response{
				headers: [Header{'content-type', 'application/json'}]
				body:    '{"sessions":[' + sessions.map(context.auth.session_json(it)).join(',') +
					']}'
			}
		}
		'revoke-user-sessions' {
			context.auth.remove_user_sessions(id, '')!
			return admin_json_response({
				'success': json2.Any(true)
			})
		}
		else {}
	}

	updated := context.admin_patch(user, patch)!
	if (patch['banned'] or { json2.Any(false) }).bool() {
		context.auth.remove_user_sessions(id, '')!
	}
	body := if path == 'update-user' {
		context.auth.user_json(updated)
	} else {
		'{"user":' + context.auth.user_json(updated) + '}'
	}
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    body
	}
}

fn admin_create_user(mut context EndpointContext, actor ?SessionResult, fields map[string]json2.Any, options AdminOptions) !Response {
	if live := actor {
		context.admin_require(live.user, 'user', 'create', 'YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS',
			'You are not allowed to create users')!
	}
	mut data := (fields['data'] or { json2.Any(map[string]json2.Any{}) }).as_map().clone()
	mut role := options.default_role
	requested := fields['role'] or { data['role'] or { json2.Any(json2.Null{}) } }
	if 'role' in fields || 'role' in data {
		if live := actor {
			context.admin_require(live.user, 'user', 'set-role',
				'YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE',
				'You are not allowed to change users role')!
		}
		role = admin_role(requested, options)!
	}
	if ['banned', 'banReason', 'banExpires'].any(it in data) {
		if live := actor {
			context.admin_require(live.user, 'user', 'ban', 'YOU_ARE_NOT_ALLOWED_TO_BAN_USERS',
				'You are not allowed to ban users')!
		}
	}
	email := normalize_email((fields['email'] or { json2.Any('') }).str())!
	name := fields['name'] or { return fail(400, 'VALIDATION_ERROR', 'name is required') }
	if name !is string { return fail(400, 'VALIDATION_ERROR', 'name must be a string') }
	if value := fields['password'] {
		if value !is string { return fail(400, 'VALIDATION_ERROR', 'password must be a string') }
	}
	password := (fields['password'] or { json2.Any('') }).str()
	if utf16_length(password) > context.auth.config.max_password_length {
		return fail(400, 'PASSWORD_TOO_LONG', 'Password too long')
	}
	if (context.auth.find_user_by_email(email)!).value != none {
		return fail(400, 'USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL',
			'User already exists. Use another email.')
	}
	now := stamp_millis(context.auth.clock_millis())
	data['id'] = context.auth.new_id('user')!
	data['email'] = email
	data['name'] = name
	data['role'] = role
	data['createdAt'] = now
	data['updatedAt'] = now
	mut user := decode_user(json2.Any(data).json_str())!
	decision := context.auth.config.validate_user_info(user, UserInfoSource{ method: 'admin' })!
	if decision.error != '' { return fail(403, decision.error, if decision.error_description != '' {
			decision.error_description
		} else {
			decision.error
		})
	 }
	mut additional := user.additional_fields.clone()
	for field, definition in context.auth.config.user_fields {
		if value := additional[field] {
			validate_field(definition, value)!
		} else if fallback := (definition.resolve_default()!).value {
			validate_field(definition, fallback)!
			additional[field] = fallback
		} else if definition.required {
			return fail(400, 'MISSING_FIELD', field + ' is required')
		}
	}
	user = User{
		...user
		additional_fields: additional
	}
	user = context.auth.persist_user(user)!
	if password != '' { context.auth.persist_account(Account{
			id:          context.auth.new_id('account')!
			user_id:     user.id
			provider_id: 'credential'
			account_id:  user.id
			password:    context.auth.config.password_hasher.hash(password)!
		})! }
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    '{"user":' + context.auth.user_json(user) + '}'
	}
}

fn admin_validate_patch(mut context EndpointContext, actor User, user User, mut patch map[string]json2.Any, options AdminOptions) ! {
	if patch.len == 0 { return fail(400, 'NO_DATA_TO_UPDATE', 'No data to update') }
	if 'password' in patch {
		return fail(400, 'PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER',
			'Password cannot be updated through update-user. Use the set-user-password endpoint instead')
	}
	if 'id' in patch { return fail(400, 'USER_ID_CANNOT_BE_UPDATED', 'User id cannot be updated') }
	if role := patch['role'] {
		context.admin_require(actor, 'user', 'set-role',
			'YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE', 'You are not allowed to change users role')!
		patch['role'] = admin_role(role, options)!
	}
	if ['banned', 'banReason', 'banExpires'].any(it in patch) {
		context.admin_require(actor, 'user', 'ban', 'YOU_ARE_NOT_ALLOWED_TO_BAN_USERS',
			'You are not allowed to ban users')!
		if (patch['banned'] or { json2.Any(false) }).bool() && user.id == actor.id {
			return fail(400, 'YOU_CANNOT_BAN_YOURSELF', 'You cannot ban yourself')
		}
	}
	if 'email' in patch || 'emailVerified' in patch {
		context.admin_require(actor, 'user', 'set-email', 'YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL',
			'You are not allowed to update users email')!
		if value := patch['email'] {
			email := normalize_email(value.str())!
			if existing := (context.auth.find_user_by_email(email)!).value {
				if existing.id != user.id {
					return fail(400, 'USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL',
						'User already exists. Use another email.')
				}
			}
			patch['email'] = email
		}
	}
}

fn admin_filter_value(user User, field string) !json2.Any {
	values := json2.decode[map[string]json2.Any](encode_user(user))!
	return values[if field == '_id' {
		'id'
	} else {
		field
	}] or { json2.Any(json2.Null{}) }
}

fn admin_matches(value json2.Any, expected string, operator string) bool {
	actual := value.str()
	return match operator {
		'eq' { actual == expected }
		'ne' { actual != expected }
		'contains' { actual.contains(expected) }
		'starts_with' { actual.starts_with(expected) }
		'ends_with' { actual.ends_with(expected) }
		'lt' { actual < expected }
		'lte' { actual <= expected }
		'gt' { actual > expected }
		'gte' { actual >= expected }
		'in' { actual in expected.split(',') }
		'not_in' { actual !in expected.split(',') }
		else { false }
	}
}

struct AdminUserRow {
	user  User
	value string
}

fn admin_list_users(mut context EndpointContext, actor User, fields map[string]json2.Any) !Response {
	context.admin_require(actor, 'user', 'list', 'YOU_ARE_NOT_ALLOWED_TO_LIST_USERS',
		'You are not allowed to list users')!
	mut rows := []AdminUserRow{}
	for user in context.auth.storage.users()! {
		if search := fields['searchValue'] {
			if search.str() != '' {
				field := (fields['searchField'] or { json2.Any('email') }).str()
				if !admin_matches(admin_filter_value(user, field)!, search.str(), (fields['searchOperator'] or {
					json2.Any('contains')
				}).str()) {
					continue
				}
			}
		}
		if filter := fields['filterValue'] {
			if !admin_matches(admin_filter_value(user, (fields['filterField'] or {
				json2.Any('email')
			}).str())!, filter.str(), (fields['filterOperator'] or { json2.Any('eq') }).str()) {
				continue
			}
		}
		rows << AdminUserRow{
			user:  user
			value: (admin_filter_value(user, (fields['sortBy'] or { json2.Any('id') }).str())!).str()
		}
	}
	if 'sortBy' in fields {
		if (fields['sortDirection'] or { json2.Any('asc') }).str() == 'desc' {
			rows.sort(a.value > b.value)
		} else {
			rows.sort(a.value < b.value)
		}
	}
	total := rows.len
	mut offset := (fields['offset'] or { json2.Any(0) }).int()
	mut limit := (fields['limit'] or { json2.Any(0) }).int()
	if offset < 0 || limit < 0 { return admin_json_response({
			'users': json2.Any([]json2.Any{})
			'total': json2.Any(0)
		}) }
	if offset > total { offset = total }
	if limit == 0 || limit > total - offset { limit = total - offset }
	mut output := map[string]json2.Any{}
	mut users := []json2.Any{}
	for row in rows[offset..offset + limit] {
		users << json2.decode[json2.Any](context.auth.user_json(row.user))!
	}
	output['users'] = json2.Any(users)
	output['total'] = total
	if value := fields['limit'] {
		if value.int() != 0 { output['limit'] = value.int() }
	}
	if value := fields['offset'] {
		if value.int() != 0 { output['offset'] = value.int() }
	}
	return admin_json_response(output)
}

fn admin_json_response(value map[string]json2.Any) Response {
	return Response{
		headers: [Header{'content-type', 'application/json'}]
		body:    json2.Any(value).json_str()
	}
}
