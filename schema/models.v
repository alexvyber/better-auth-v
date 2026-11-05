module schema

// Logical names belong to the schema, independently of SQL/BSON mappings.
const core_fields_by_model = {
	'organization':     ['id', 'name', 'slug', 'logo', 'metadata', 'createdAt']
	'member':           ['id', 'organizationId', 'userId', 'role', 'createdAt']
	'invitation':       ['id', 'organizationId', 'email', 'role', 'status', 'inviterId', 'expiresAt',
		'createdAt']
	'organizationRole': ['id', 'organizationId', 'role', 'permission', 'createdAt', 'updatedAt']
	'user':             ['id', 'name', 'email', 'emailVerified', 'image', 'createdAt', 'updatedAt']
	'session':          ['id', 'userId', 'token', 'expiresAt', 'createdAt', 'updatedAt', 'ipAddress',
		'userAgent']
	'account':          ['id', 'userId', 'accountId', 'providerId', 'password', 'accessToken',
		'refreshToken', 'idToken', 'accessTokenExpiresAt', 'refreshTokenExpiresAt', 'scope',
		'createdAt', 'updatedAt']
	'verification':     ['id', 'identifier', 'value', 'expiresAt', 'createdAt', 'updatedAt']
	'jwks':             ['id', 'publicKey', 'privateKey', 'alg', 'crv', 'createdAt', 'expiresAt']
	'rateLimit':        ['key', 'count', 'lastRequest']
	'twoFactor':        ['id', 'userId', 'secret', 'backupCodes', 'verified',
		'failedVerificationCount', 'lockedUntil']
}

pub fn core_models() []string {
	return core_fields_by_model.keys()
}

pub fn is_core_model(model string) bool {
	return model in core_fields_by_model
}

pub fn core_fields(model string) []string {
	return (core_fields_by_model[model] or { []string{} }).clone()
}

pub fn core_fields_or_id(model string) []string {
	return (core_fields_by_model[model] or { ['id'] }).clone()
}

pub fn has_core_field(model string, field string) bool {
	return field in (core_fields_by_model[model] or { []string{} })
}

pub struct Reference {
pub:
	source_model string
	source_field string
	target_model string
	target_field string = 'id'
	unique       bool
}

pub fn core_references() []Reference {
	return [
		Reference{
			source_model: 'session'
			source_field: 'userId'
			target_model: 'user'
		},
		Reference{
			source_model: 'account'
			source_field: 'userId'
			target_model: 'user'
		},
		Reference{
			source_model: 'member'
			source_field: 'userId'
			target_model: 'user'
		},
		Reference{
			source_model: 'member'
			source_field: 'organizationId'
			target_model: 'organization'
		},
		Reference{
			source_model: 'invitation'
			source_field: 'inviterId'
			target_model: 'user'
		},
		Reference{
			source_model: 'invitation'
			source_field: 'organizationId'
			target_model: 'organization'
		},
		Reference{
			source_model: 'organizationRole'
			source_field: 'organizationId'
			target_model: 'organization'
		},
	]
}
