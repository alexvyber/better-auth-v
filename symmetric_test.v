module better_auth

import encoding.hex

fn test_hchacha20_matches_published_subkey_vector() ! {
	key := hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')!
	nonce := hex.decode('000000090000004a0000000031415927')!
	assert hex.encode(hchacha20(key, nonce)!) == '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc'
}

fn test_versioned_symmetric_keys_reject_retired_versions() ! {
	old := SecretConfig{
		keys:            {
			i64(1): 'old-secret'
		}
		current_version: 1
	}
	rotated := SecretConfig{
		keys:            {
			i64(2): 'new-secret'
			i64(1): 'old-secret'
		}
		current_version: 2
	}
	ciphertext := symmetric_encrypt(SymmetricSecret(old), 'rotation')!
	assert ciphertext.starts_with('\$ba\$1\$')
	assert symmetric_decrypt(SymmetricSecret(rotated), ciphertext)! == 'rotation'
	retired := SecretConfig{
		keys:            {
			i64(2): 'new-secret'
		}
		current_version: 2
	}
	symmetric_decrypt(SymmetricSecret(retired), ciphertext) or {
		assert err.msg().contains('Secret version 1 not found')
		return
	}
	assert false, 'a retired encryption key must not fall back to another version'
}
