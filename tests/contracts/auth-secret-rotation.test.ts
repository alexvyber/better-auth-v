import { describe, expect, it } from 'vitest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import type { Jwk } from 'better-auth/plugins/jwt';
import { getTestInstance } from '../harness/test-instance.js';
import { jwt } from '../harness/plugins.js';

const oldSecret = 'old-secret-that-is-long-enough-for-rotation-tests';
const newSecret = 'new-secret-that-is-long-enough-for-rotation-tests';
function keyring() {
  const keys: Jwk[] = [];
  return {keys, adapter: {
    getJwks: async () => keys,
    createJwk: async (data: Omit<Jwk, 'id'>) => {const key = {...data, id: crypto.randomUUID()}; keys.push(key); return key;},
  }};
}

describe('native auth versioned secrets', () => {
  it('reuses a versioned persisted signing key while rotating the current secret', async () => {
    const store = keyring();
    const first = await getTestInstance({secrets: [{version: 1, value: oldSecret}], plugins: [jwt({adapter: store.adapter})]}, {disableTestUser: true});
    const old = await first.auth.api.signJWT({body: {payload: {sub: 'before-rotation'}}});
    expect(JSON.parse(store.keys[0].privateKey)).toMatch(/^\$ba\$1\$/);
    const rotated = await getTestInstance({secrets: [{version: 2, value: newSecret}, {version: 1, value: oldSecret}], plugins: [jwt({adapter: store.adapter})]}, {disableTestUser: true});
    const current = await rotated.auth.api.signJWT({body: {payload: {sub: 'after-rotation'}}});
    expect(store.keys).toHaveLength(1);
    const jwks = createLocalJWKSet(await rotated.auth.api.getJwks());
    expect((await jwtVerify(old.token, jwks)).payload.sub).toBe('before-rotation');
    expect((await jwtVerify(current.token, jwks)).payload.sub).toBe('after-rotation');
    const retired = await getTestInstance({secret: oldSecret, secrets: [{version: 2, value: newSecret}], plugins: [jwt({adapter: store.adapter})]}, {disableTestUser: true});
    await expect(retired.auth.api.signJWT({body: {payload: {sub: 'retired'}}})).rejects.toThrow('Secret version 1 not found');
    expect(store.keys).toHaveLength(1);
  });

  it('requires an explicit legacy secret for previously unversioned private keys', async () => {
    const store = keyring();
    const original = await getTestInstance({secret: oldSecret, plugins: [jwt({adapter: store.adapter})]}, {disableTestUser: true});
    await original.auth.api.signJWT({body: {payload: {sub: 'unversioned'}}});
    expect(JSON.parse(store.keys[0].privateKey)).not.toContain('$ba$');
    const absent = await getTestInstance({secrets: [{version: 2, value: newSecret}], plugins: [jwt({adapter: store.adapter})]}, {disableTestUser: true});
    await expect(absent.auth.api.signJWT({body: {payload: {sub: 'no-legacy'}}})).rejects.toThrow('no legacy secret');
    const compatible = await getTestInstance({secret: oldSecret, secrets: [{version: 2, value: newSecret}], plugins: [jwt({adapter: store.adapter})]}, {disableTestUser: true});
    const {token} = await compatible.auth.api.signJWT({body: {payload: {sub: 'with-legacy'}}});
    expect((await jwtVerify(token, createLocalJWKSet(await compatible.auth.api.getJwks()))).payload.sub).toBe('with-legacy');
    expect(store.keys).toHaveLength(1);
  });

  it.for([[], [{version: 1, value: oldSecret}, {version: 1, value: newSecret}], [{version: -1, value: oldSecret}], [{version: 1, value: ''}]])('rejects invalid main auth secrets configuration %j', async secrets => {
    await expect(getTestInstance({secrets}, {disableTestUser: true})).rejects.toThrow();
  });
});
