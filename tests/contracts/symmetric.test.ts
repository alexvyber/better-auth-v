import { describe, expect, it } from 'vitest';
import { hkdfSync } from 'node:crypto';
import { symmetricEncrypt as referenceEncrypt, symmetricDecrypt as referenceDecrypt, symmetricEncodeJWT as referenceEncodeJWT, symmetricDecodeJWT as referenceDecodeJWT } from 'better-auth/crypto';
import { exportJWK, generateKeyPair, createLocalJWKSet, jwtVerify } from 'jose';
import { symmetricEncrypt, symmetricDecrypt, symmetricEncodeJWT, symmetricDecodeJWT, derivePurposeKey } from '../harness/crypto.js';
import { getTestInstance } from '../harness/test-instance.js';
import { jwt } from '../harness/plugins.js';
import type { SecretConfig } from '@better-auth/core';
import type { Jwk } from 'better-auth/plugins/jwt';

const secret = 'better-auth-secret-that-is-long-enough-for-validation-test';

describe('native symmetric crypto interoperability', () => {
  it.each(['', 'plain text', 'Unicode: café 🧪 مرحبا', 'x'.repeat(65)])('exchanges XChaCha20-Poly1305 ciphertext with upstream for %j', async data => {
    const native = await symmetricEncrypt({key: secret, data});
    expect(await referenceDecrypt({key: secret, data: native})).toBe(data);
    const reference = await referenceEncrypt({key: secret, data});
    expect(await symmetricDecrypt({key: secret, data: reference})).toBe(data);
    const changed = Buffer.from(native, 'hex'); changed[changed.length - 1] ^= 1;
    await expect(symmetricDecrypt({key: secret, data: changed.toString('hex')})).rejects.toThrow();
    await expect(symmetricDecrypt({key: secret + 'wrong', data: native})).rejects.toThrow();
  });

  it('exchanges versioned ciphertext and JWE using retired and legacy keys', async () => {
    const old: SecretConfig = {keys: new Map([[1, secret]]), currentVersion: 1};
    const rotated: SecretConfig = {keys: new Map([[3, secret + '-new'], [1, secret]]), currentVersion: 3, legacySecret: secret};
    const native = await symmetricEncrypt({key: old, data: 'retired key'});
    expect(await referenceDecrypt({key: rotated, data: native})).toBe('retired key');
    expect(await symmetricDecrypt({key: rotated, data: await referenceEncrypt({key: old, data: 'upstream retired key'})})).toBe('upstream retired key');
    const fromV = await symmetricEncodeJWT({scope: 'native'}, old, 'interop');
    expect((await referenceDecodeJWT<{scope: string}>(fromV, rotated, 'interop'))?.scope).toBe('native');
    const fromTS = await referenceEncodeJWT({scope: 'upstream'}, old, 'interop');
    expect((await symmetricDecodeJWT<{scope: string}>(fromTS, rotated, 'interop'))?.scope).toBe('upstream');
  });

  it('derives isolated OAuth keys with the exact upstream HKDF context', () => {
    const expected = Buffer.from(hkdfSync('sha256', secret, 'better-auth:oauth-encryption:v1', 'better-auth:oauth-proxy-profile:v1', 32)).toString('hex');
    expect(derivePurposeKey(secret, 'oauth-proxy-profile')).toBe(expected);
  });

  it('imports an upstream-encrypted private JWK and publishes keys that upstream can decrypt', async () => {
    const pair = await generateKeyPair('ES256', {extractable: true});
    const publicJWK = await exportJWK(pair.publicKey);
    const privateJWK = await exportJWK(pair.privateKey);
    const stored: Jwk[] = [{id: 'upstream-key', alg: 'ES256', crv: 'P-256', createdAt: new Date(),
      publicKey: JSON.stringify(publicJWK), privateKey: JSON.stringify(await referenceEncrypt({key: secret, data: JSON.stringify(privateJWK)}))}];
    const {auth} = await getTestInstance({plugins: [jwt({jwks: {keyPairConfig: {alg: 'ES256'}}, adapter: {
      getJwks: async () => stored,
      createJwk: async () => {throw new Error('Unexpected native mint');},
    }})]});
    const {token} = await auth.api.signJWT({body: {payload: {sub: 'interop-user'}}});
    expect((await jwtVerify(token, pair.publicKey)).payload.sub).toBe('interop-user');
    const generated: Jwk[] = [];
    const instance = await getTestInstance({plugins: [jwt({adapter: {
      getJwks: async () => generated,
      createJwk: async data => {const row = {...data, id: 'native-key'}; generated.push(row); return row;},
    }})]});
    const signed = await instance.auth.api.signJWT({body: {payload: {sub: 'native-user'}}});
    const unsealed = JSON.parse(await referenceDecrypt({key: secret, data: JSON.parse(generated[0].privateKey)}));
    expect(unsealed.kty).toBe('OKP');
    expect(unsealed.d).toBeTypeOf('string');
    expect((await jwtVerify(signed.token, createLocalJWKSet(await instance.auth.api.getJwks()))).payload.sub).toBe('native-user');
  });
});

it('preserves secret versions wider than 32 bits without aliasing version zero', async () => {
  const version = 4294967296;
  const config: SecretConfig = {keys: new Map([[version, secret]]), currentVersion: version};
  const encrypted = await symmetricEncrypt({key: config, data: 'wide version'});
  expect(encrypted.startsWith(`$ba$${version}$`)).toBe(true);
  expect(await referenceDecrypt({key: config, data: encrypted})).toBe('wide version');
  const zero: SecretConfig = {keys: new Map([[0, secret]]), currentVersion: 0};
  await expect(symmetricDecrypt({key: zero, data: encrypted})).rejects.toThrow();
});
