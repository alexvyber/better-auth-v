module better_auth

import x.json2

fn org_doc_type(kind string) json2.Any {
	return json2.Any({
		'type': json2.Any(kind)
	})
}

fn org_doc_array(item json2.Any) json2.Any {
	return json2.Any({
		'type':  json2.Any('array')
		'items': item
	})
}

fn org_doc_object(properties map[string]json2.Any, required []string) json2.Any {
	mut schema := {
		'type':       json2.Any('object')
		'properties': json2.Any(properties)
	}
	if required.len > 0 { schema['required'] = json2.Any(required.map(json2.Any(it))) }
	return json2.Any(schema)
}

fn org_doc_nullable(schema json2.Any) json2.Any {
	return json2.Any({
		'anyOf': json2.Any([schema, org_doc_type('null')])
	})
}

fn org_doc_permissions() json2.Any {
	return json2.Any({
		'type':                 json2.Any('object')
		'additionalProperties': org_doc_array(org_doc_type('string'))
	})
}

fn org_doc_role() json2.Any {
	return json2.Any({
		'anyOf': json2.Any([org_doc_type('string'), org_doc_array(org_doc_type('string'))])
	})
}

fn org_doc_extend(base json2.Any, properties map[string]json2.Any, required []string) json2.Any {
	return json2.Any({
		'allOf': json2.Any([base, org_doc_object(properties, required)])
	})
}

fn (auth &Auth) org_doc_extra_fields(model string, creating bool, mut properties map[string]json2.Any, mut required []string) {
	for name, field in auth.config.model_fields[model] or {
		map[string]AdditionalField{}
	} {
		if !field.input { continue
		 }
		properties[name] = json2.Any(openapi_type(field, false))
		if creating && field.required && !field.has_default() { required << name }
	}
}

fn org_doc_joined_member() json2.Any {
	return org_doc_extend(openapi_ref('Member'), {
		'user': org_doc_object({
			'id':    org_doc_type('string')
			'name':  org_doc_type('string')
			'email': org_doc_type('string')
			'image': org_doc_nullable(org_doc_type('string'))
		}, ['id', 'name', 'email', 'image'])
	}, ['user'])
}

fn (auth &Auth) openapi_organization_operation(mut operation map[string]json2.Any, path string, method string) ! {
	if !path.starts_with('/organization/') { return }
	_ := auth.organization_options() or { return }
	name := path.all_after_last('/')
	mut properties := map[string]json2.Any{}
	mut required := []string{}
	mut response := json2.Any(map[string]json2.Any{})
	mut operation_id := ''
	if method == 'POST' {
		match name {
			'create' {
				operation_id = 'createOrganization'
				for field in ['name', 'slug', 'userId'] {
					properties[field] = org_doc_type('string')
				}
				properties['logo'] = org_doc_nullable(org_doc_type('string'))
				properties['metadata'] = org_doc_type('object')
				properties['keepCurrentActiveOrganization'] = org_doc_type('boolean')
				properties['userId'] = json2.Any({
					'type':        json2.Any('string')
					'description': json2.Any('Trusted server API only; HTTP creation uses the authenticated user')
				})
				required = ['name', 'slug']
				auth.org_doc_extra_fields('organization', true, mut properties, mut required)
				response = org_doc_extend(openapi_ref('Organization'), {
					'members': org_doc_array(openapi_ref('Member'))
				}, ['members'])
			}
			'update' {
				operation_id = 'updateOrganization'
				mut data := {
					'name':     org_doc_type('string')
					'slug':     org_doc_type('string')
					'logo':     org_doc_nullable(org_doc_type('string'))
					'metadata': org_doc_type('object')
				}
				mut data_required := []string{}
				auth.org_doc_extra_fields('organization', false, mut data, mut data_required)
				properties = {
					'organizationId': org_doc_type('string')
					'data':           org_doc_object(data, data_required)
				}
				required = ['data']
				response = openapi_ref('Organization')
			}
			'delete', 'leave' {
				operation_id = if name == 'delete' {
					'deleteOrganization'
				} else {
					'leaveOrganization'
				}
				properties['organizationId'] = org_doc_type('string')
				required = ['organizationId']
				response = openapi_ref(if name == 'delete' { 'Organization' } else { 'Member' })
			}
			'check-slug' {
				operation_id = 'checkOrganizationSlug'
				properties['slug'] = org_doc_type('string')
				required = ['slug']
				response = org_doc_object({
					'status': org_doc_type('boolean')
				}, ['status'])
			}
			'set-active' {
				operation_id = 'setActiveOrganization'
				properties = {
					'organizationId':   org_doc_nullable(org_doc_type('string'))
					'organizationSlug': org_doc_type('string')
				}
				response = org_doc_nullable(openapi_ref('Organization'))
			}
			'invite-member' {
				operation_id = 'createInvitation'
				properties = {
					'email':          org_doc_type('string')
					'role':           org_doc_role()
					'organizationId': org_doc_type('string')
					'resend':         org_doc_type('boolean')
				}
				required = ['email']
				auth.org_doc_extra_fields('invitation', true, mut properties, mut required)
				response = openapi_ref('Invitation')
			}
			'accept-invitation', 'reject-invitation', 'cancel-invitation' {
				operation_id = if name == 'accept-invitation' {
					'acceptInvitation'
				} else if name == 'reject-invitation' {
					'rejectInvitation'
				} else {
					'cancelInvitation'
				}
				properties['invitationId'] = org_doc_type('string')
				required = ['invitationId']
				response = if name == 'cancel-invitation' {
					openapi_ref('Invitation')
				} else {
					org_doc_object({
						'invitation': openapi_ref('Invitation')
						'member':     if name == 'reject-invitation' {
							org_doc_type('null')
						} else {
							openapi_ref('Member')
						}
					}, ['invitation', 'member'])
				}
			}
			'has-permission' {
				operation_id = 'hasOrganizationPermission'
				properties = {
					'organizationId': org_doc_type('string')
					'permissions':    org_doc_permissions()
				}
				required = ['permissions']
				response = org_doc_object({
					'success': org_doc_type('boolean')
					'error':   org_doc_type('null')
				}, ['success', 'error'])
			}
			'update-member-role' {
				operation_id = 'updateMemberRole'
				properties = {
					'organizationId': org_doc_type('string')
					'memberId':       org_doc_type('string')
					'role':           org_doc_role()
				}
				required = ['memberId', 'role']
				response = openapi_ref('Member')
			}
			'remove-member' {
				operation_id = 'removeMember'
				properties = {
					'organizationId':   org_doc_type('string')
					'organizationSlug': org_doc_type('string')
					'memberIdOrEmail':  org_doc_type('string')
				}
				required = ['memberIdOrEmail']
				response = org_doc_object({
					'member': openapi_ref('Member')
				}, ['member'])
			}
			'create-role', 'update-role', 'delete-role' {
				operation_id = if name == 'create-role' {
					'createOrgRole'
				} else if name == 'update-role' {
					'updateOrgRole'
				} else {
					'deleteOrgRole'
				}
				properties['organizationId'] = org_doc_type('string')
				if name == 'create-role' {
					properties['role'] = org_doc_type('string')
					properties['permission'] = org_doc_permissions()
					required = ['role', 'permission']
					mut extra := map[string]json2.Any{}
					mut extra_required := []string{}
					auth.org_doc_extra_fields('organizationRole', true, mut extra, mut
						extra_required)
					properties['additionalFields'] = org_doc_object(extra, extra_required)
					if extra_required.len > 0 { required << 'additionalFields' }
					response = org_doc_object({
						'success':    org_doc_type('boolean')
						'roleData':   openapi_ref('OrganizationRole')
						'statements': org_doc_permissions()
					}, ['success', 'roleData', 'statements'])
				} else {
					properties['roleId'] = org_doc_type('string')
					properties['roleName'] = org_doc_type('string')
					if name == 'update-role' {
						mut data := {
							'roleName':   org_doc_type('string')
							'permission': org_doc_permissions()
						}
						mut data_required := []string{}
						auth.org_doc_extra_fields('organizationRole', false, mut data, mut
							data_required)
						properties['data'] = org_doc_object(data, data_required)
						required = ['data']
						response = org_doc_object({
							'success':  org_doc_type('boolean')
							'roleData': openapi_ref('OrganizationRole')
						}, ['success', 'roleData'])
					} else {
						response = org_doc_object({
							'success': org_doc_type('boolean')
						}, ['success'])
					}
				}
			}
			else {
				return
			}
		}

		mut body := openapi_body(properties, required.map(json2.Any(it))).as_map().clone()
		if name in ['update-role', 'delete-role'] {
			mut content := body['content']!.as_map().clone()
			mut media := content['application/json']!.as_map().clone()
			mut schema := media['schema']!.as_map().clone()
			schema['anyOf'] = json2.Any([
				json2.Any({
					'required': json2.Any([json2.Any('roleId')])
				}),
				json2.Any({
					'required': json2.Any([json2.Any('roleName')])
				}),
			])
			media['schema'] = json2.Any(schema)
			content['application/json'] = json2.Any(media)
			body['content'] = json2.Any(content)
		}
		operation['requestBody'] = json2.Any(body)
	} else if method == 'GET' {
		match name {
			'list' {
				operation_id = 'listOrganizations'
				response = org_doc_array(openapi_ref('Organization'))
			}
			'get-organization', 'get-full-organization' {
				operation_id = if name == 'get-organization' {
					'getOrganization'
				} else {
					'getFullOrganization'
				}
				properties = {
					'organizationId':   org_doc_type('string')
					'organizationSlug': org_doc_type('string')
				}
				response = openapi_ref('Organization')
				if name == 'get-full-organization' {
					properties['membersLimit'] = org_doc_type('integer')
					response = org_doc_extend(response, {
						'members':     org_doc_array(org_doc_joined_member())
						'invitations': org_doc_array(openapi_ref('Invitation'))
					}, ['members', 'invitations'])
				}
				response = org_doc_nullable(response)
			}
			'get-active-member' {
				operation_id = 'getActiveMember'
				response = openapi_ref('Member')
			}
			'get-active-member-role' {
				operation_id = 'getActiveMemberRole'
				properties = {
					'organizationId':   org_doc_type('string')
					'organizationSlug': org_doc_type('string')
					'userId':           org_doc_type('string')
				}
				response = org_doc_object({
					'role': org_doc_type('string')
				}, ['role'])
			}
			'list-members' {
				operation_id = 'listMembers'
				for field in ['organizationId', 'organizationSlug', 'sortBy', 'sortDirection',
					'filterField', 'filterOperator'] {
					properties[field] = org_doc_type('string')
				}
				for field in ['limit', 'offset'] {
					properties[field] = json2.Any({
						'type':    json2.Any('integer')
						'minimum': json2.Any(0)
					})
				}
				properties['filterValue'] = org_doc_role()
				properties['sortDirection'] = json2.Any({
					'type': json2.Any('string')
					'enum': json2.Any([json2.Any('asc'), json2.Any('desc')])
				})
				response = org_doc_object({
					'members': org_doc_array(org_doc_joined_member())
					'total':   org_doc_type('integer')
				}, ['members', 'total'])
			}
			'get-invitation' {
				operation_id = 'getInvitation'
				properties['id'] = org_doc_type('string')
				required = ['id']
				response = org_doc_extend(openapi_ref('Invitation'), {
					'organizationName': org_doc_type('string')
					'organizationSlug': org_doc_type('string')
					'inviterEmail':     org_doc_type('string')
				}, ['organizationName', 'organizationSlug', 'inviterEmail'])
			}
			'list-invitations' {
				operation_id = 'listInvitations'
				properties['organizationId'] = org_doc_type('string')
				response = org_doc_array(openapi_ref('Invitation'))
			}
			'list-user-invitations' {
				operation_id = 'listUserInvitations'
				// Explicit email selection is a trusted server API, not an HTTP query.
				response = org_doc_array(org_doc_extend(openapi_ref('Invitation'), {
					'organizationName': org_doc_type('string')
				}, []))
			}
			'list-roles', 'get-role' {
				operation_id = if name == 'list-roles' { 'listOrgRoles' } else { 'getOrgRole' }
				properties['organizationId'] = org_doc_type('string')
				if name == 'get-role' {
					properties['roleId'] = org_doc_type('string')
					properties['roleName'] = org_doc_type('string')
				}
				response = if name == 'list-roles' {
					org_doc_array(openapi_ref('OrganizationRole'))
				} else {
					openapi_ref('OrganizationRole')
				}
			}
			else {
				return
			}
		}

		mut parameters := []json2.Any{}
		for field, schema in properties {
			parameters << json2.Any({
				'name':     json2.Any(field)
				'in':       json2.Any('query')
				'required': json2.Any(field in required)
				'schema':   schema
			})
		}
		if parameters.len > 0 { operation['parameters'] = json2.Any(parameters) }
	} else {
		return
	}
	operation['operationId'] = operation_id
	operation['tags'] = json2.Any([json2.Any('Organization')])
	operation['responses'] = json2.Any({
		'200': json2.Any({
			'description': json2.Any('Success')
			'content':     json2.Any({
				'application/json': json2.Any({
					'schema': response
				})
			})
		})
	})
}
