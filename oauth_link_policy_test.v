module better_auth

struct LinkPolicyCase {
	local_verified    bool
	provider_verified bool
	trusted           bool
	require_local     bool = true
	disabled          bool
	allowed           bool
	promoted          bool
}

fn test_native_implicit_link_policy_and_local_verification_promotion() ! {
	cases := [LinkPolicyCase{ provider_verified: true, trusted: true },
		LinkPolicyCase{ local_verified: true, provider_verified: true, allowed: true },
		LinkPolicyCase{ local_verified: true, trusted: true, allowed: true },
		LinkPolicyCase{ local_verified: true }, LinkPolicyCase{
			provider_verified: true
			trusted:           true
			require_local:     false
			allowed:           true
			promoted:          true
		}, LinkPolicyCase{
			local_verified:    true
			provider_verified: true
			trusted:           true
			disabled:          true
		}]
	for item in cases {
		mut storage := open_memory()
		mut auth := new(Config{
			secret:                       'native-link-policy-secret-32-bytes-minimum'
			account_linking_enabled:      true
			require_local_email_verified: item.require_local
			disable_implicit_linking:     item.disabled
			trusted_linking_providers:    if item.trusted { ['provider'] } else { []string{} }
		}, storage)!
		storage.create_user(User{
			id:             'local'
			email:          'local@example.com'
			name:           'Local'
			email_verified: item.local_verified
		})!
		result := auth.oauth_identity_account(OAuthIdentity{
			id:             'provider-subject'
			email:          'local@example.com'
			email_verified: item.provider_verified
			name:           'Provider'
		}, 'provider', false) or {
			assert !item.allowed
			assert err is APIError
			if err is APIError { assert err.code == 'ACCOUNT_NOT_LINKED'
			 }
			assert storage.accounts('local')!.len == 0
			auth.close()!
			continue
		}
		assert item.allowed
		assert result.user.id == 'local'
		assert storage.accounts('local')!.len == 1
		assert result.user.email_verified == (item.local_verified || item.promoted)
		auth.close()!
	}
}
