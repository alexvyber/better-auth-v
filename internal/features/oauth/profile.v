module better_auth

import json
import x.json2

fn oauth_extra_fields(mapped map[string]json2.Any) map[string]json2.Any {
	mut extra := map[string]json2.Any{}
	for key, value in mapped {
		if key !in ['id', 'name', 'email', 'emailVerified', 'image', 'createdAt', 'updatedAt',
			'sub'] {
			extra[key] = value
		}
	}
	return extra
}

fn (a &Auth) provider_user_fields(input map[string]json2.Any, creating bool) !map[string]json2.Any {
	mut allowed := map[string]json2.Any{}
	for key, value in input {
		if field := a.config.user_fields[key] {
			if field.input { allowed[key] = value }
		}
	}
	return parse_fields(a.config.user_fields, allowed, map[string]json2.Any{}, creating)
}

fn (mut a Auth) sync_oauth_profile(user User, identity OAuthIdentity) !User {
	mut patch := a.provider_user_fields(identity.additional_fields, false)!
	if identity.name != '' || 'name' in identity.profile { patch['name'] = identity.name }
	if image := identity.image {
		patch['image'] = image
	} else if 'picture' in identity.profile || 'image' in identity.profile {
		patch['image'] = json2.Null{}
	}
	encoded := json2.Any(patch).json_str()
	if intercepted := (a.intercept_internal('updateUser', '[' + json.encode(user.id) + ',' +
		encoded + ']')!).value
	{
		if intercepted == 'null' { return user }
		return decode_user(intercepted)
	}
	return a.update_user_record(decode_user(merge_record_json(encode_user(user), encoded)!)!)
}

fn (provider GoogleProvider) mapped_identity(profile map[string]json2.Any, tokens OAuthTokens) !OAuthIdentity {
	base := google_profile_identity(profile, tokens)
	mapped :=
		json2.decode[map[string]json2.Any](provider.map_profile(json2.Any(profile).json_str())!)!
	image := mapped['image'] or {
		if original := base.image { json2.Any(original) } else { json2.Any(json2.Null{}) }
	}
	return OAuthIdentity{
		...base
		email:             (mapped['email'] or { json2.Any(base.email) }).str()
		email_verified:    (mapped['emailVerified'] or { json2.Any(base.email_verified) }).bool()
		name:              (mapped['name'] or { json2.Any(base.name) }).str()
		image:             if image is string { ?string(image.str()) } else { none }
		additional_fields: oauth_extra_fields(mapped)
	}
}
