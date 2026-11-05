import type {GenericEndpointContext} from '@better-auth/core';
import {runWithEndpointContext} from '@better-auth/core/context';
import type {JwtOptions} from 'better-auth/plugins/jwt';
import {createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify} from 'jose';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';
import {jwt} from '../harness/plugins.js';
import {generateExportedKeyPair, getJwksAdapter, signJWT, toExpJWT, verifyJWT} from '../harness/jwt.js';

const baseURL = 'http://localhost:3000';
const baseOptions = {jwks: {keyPairConfig: {alg: 'ES256'}}, jwt: {issuer: 'https://configured.issuer', audience: 'configured-audience', expirationTime: '2h'}} satisfies JwtOptions;
afterEach(() => vi.useRealTimers());

describe('native JWT per-call options', () => {
  it('shallowly replaces jwt options and leaves the configured plugin unchanged', async () => {
    const {auth} = await getTestInstance({plugins: [jwt(baseOptions)]});
    const payload = {sub: 'user', iat: Math.floor(Date.now() / 1000)};
    const configured = await auth.api.signJWT({body: {payload}});
    const overridden = await auth.api.signJWT({body: {payload, overrideOptions: {jwt: {issuer: 'https://call.issuer'}}}});
    const keys = createLocalJWKSet(await auth.api.getJwks());
    const claims = (await jwtVerify(overridden.token, keys, {issuer: 'https://call.issuer', audience: baseURL})).payload;
    expect(claims.exp).toBe(payload.iat + 900);
    expect(decodeProtectedHeader(overridden.token).alg).toBe('ES256');
    expect(decodeJwt(configured.token).exp).toBe(payload.iat + 7200);
    const later = decodeJwt((await auth.api.signJWT({body: {payload}})).token);
    expect(later.iss).toBe(baseOptions.jwt.issuer);
    expect(later.aud).toBe(baseOptions.jwt.audience);
    expect(later.exp).toBe(payload.iat + 7200);
  });

  it('uses per-call algorithms and encryption settings without changing the configured primary', async () => {
    const {auth} = await getTestInstance({plugins: [jwt(baseOptions)]});
    await auth.api.signJWT({body: {payload: {sub: 'configured'}}});
    const context = await auth.$context;
    const options = {...baseOptions, jwks: {keyPairConfig: {alg: 'EdDSA'}, disablePrivateKeyEncryption: true}} satisfies JwtOptions;
    const token = await signJWT({context} as unknown as GenericEndpointContext, {options, payload: {sub: 'call'}, signingAlgorithm: 'EdDSA', header: {typ: 'logout+jwt'}});
    const keys = createLocalJWKSet(await auth.api.getJwks());
    expect((await jwtVerify(token, keys, {issuer: baseOptions.jwt.issuer, audience: baseOptions.jwt.audience})).protectedHeader).toMatchObject({alg: 'EdDSA', typ: 'logout+jwt'});
    const records = await context.adapter.findMany<any>({model: 'jwks'});
    expect(records).toHaveLength(2);
    expect(JSON.parse(records.find(record => record.alg === 'EdDSA').privateKey).kty).toBe('OKP');
    expect(typeof JSON.parse(records.find(record => record.alg === 'ES256').privateKey)).toBe('string');
    const later = (await auth.api.signJWT({body: {payload: {sub: 'configured-again'}}})).token;
    expect(decodeProtectedHeader(later).alg).toBe('ES256');
    await expect(signJWT({context} as unknown as GenericEndpointContext, {options: {...baseOptions, jwks: {disablePrivateKeyEncryption: true, keyPairConfig: {alg: 'ES256'}}}, payload: {sub: 'mismatched-encryption'}, signingAlgorithm: 'ES256'})).rejects.toThrow();
  });

  it('treats omitted helper options as defaults rather than inheriting plugin options', async () => {
    const {auth} = await getTestInstance({plugins: [jwt(baseOptions)]});
    await auth.api.signJWT({body: {payload: {sub: 'configured'}}});
    const context = await auth.$context;
    const token = await signJWT({context} as unknown as GenericEndpointContext, {payload: {sub: 'defaults'}, signingAlgorithm: 'EdDSA'});
    expect(decodeProtectedHeader(token).alg).toBe('EdDSA');
    const claims = (await jwtVerify(token, createLocalJWKSet(await auth.api.getJwks()), {issuer: baseURL, audience: baseURL})).payload;
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000) + 890);
    const record = await getJwksAdapter(context.adapter).getLatestKeyByAlg({context} as unknown as GenericEndpointContext, 'EdDSA');
    expect(record.id).toBe(decodeProtectedHeader(token).kid);
    expect(decodeProtectedHeader((await auth.api.signJWT({body: {payload: {sub: 'still-configured'}}})).token).alg).toBe('ES256');
  });

  it('uses per-call custom key stores for signing, verification and lookup', async () => {
    const {auth} = await getTestInstance({plugins: [jwt()]});
    const context = await auth.$context;
    const records: any[] = [];
    const createJwk = vi.fn(async (data: any) => {
      expect(data.createdAt).toBeInstanceOf(Date);
      const key = {...data, id: 'per-call-key'};
      records.push(key);
      return key;
    });
    const options = {jwks: {keyPairConfig: {alg: 'ES256'}, disablePrivateKeyEncryption: true}, jwt: {issuer: 'https://isolated.issuer', audience: 'isolated-audience'}, adapter: {getJwks: async () => records, createJwk}} satisfies JwtOptions;
    const endpoint = {context} as unknown as GenericEndpointContext;
    const token = await signJWT(endpoint, {options, payload: {sub: 'isolated'}});
    expect(createJwk).toHaveBeenCalledOnce();
    const publicKeys = {keys: records.map(record => ({...JSON.parse(record.publicKey), kid: record.id, alg: record.alg}))};
    expect((await jwtVerify(token, createLocalJWKSet(publicKeys), {issuer: options.jwt.issuer, audience: options.jwt.audience})).payload.sub).toBe('isolated');
    expect(await getJwksAdapter(context.adapter, options).getAllKeys(endpoint)).toHaveLength(1);
    expect((await runWithEndpointContext(endpoint, () => verifyJWT(token, options)))?.sub).toBe('isolated');
    expect(await context.adapter.findMany({model: 'jwks'})).toHaveLength(0);
    expect((await auth.api.verifyJWT({body: {token}})).payload).toBeNull();
  });

  it('allows a per-call custom signer without changing routes or minting local keys', async () => {
    const {auth} = await getTestInstance({plugins: [jwt()]});
    const context = await auth.$context;
    const sign = vi.fn(async () => 'remote-signed-value');
    expect(await auth.api.signJWT({body: {payload: {sub: 'remote'}, overrideOptions: {jwt: {issuer: 'https://remote.issuer', sign}}}})).toEqual({token: 'remote-signed-value'});
    expect(sign).toHaveBeenCalledWith(expect.objectContaining({sub: 'remote', iss: 'https://remote.issuer', aud: baseURL, exp: expect.any(Number)}), undefined, {signingKeyId: undefined, signingAlgorithm: undefined});
    expect(await context.adapter.findMany({model: 'jwks'})).toHaveLength(0);
    expect((await auth.api.getJwks()).keys).toHaveLength(1);
    expect(decodeProtectedHeader((await auth.api.signJWT({body: {payload: {sub: 'local'}}})).token).alg).toBe('EdDSA');
    expect(sign).toHaveBeenCalledOnce();
  });

  it('preserves explicit empty issuer, fractional issue/expiry claims and Date expirations', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.900Z'));
    const {auth} = await getTestInstance({plugins: [jwt({jwt: {issuer: '', audience: 'audience'}})]});
    const now = Math.floor(Date.now() / 1000);
    const token = (await auth.api.signJWT({body: {payload: {sub: 'fractional', iat: now + 0.25, exp: now + 0.5}}})).token;
    const keys = createLocalJWKSet(await auth.api.getJwks());
    expect((await jwtVerify(token, keys, {issuer: '', audience: 'audience', currentDate: new Date()})).payload.iat).toBe(now + 0.25);
    expect((await auth.api.verifyJWT({body: {token}})).payload.sub).toBe('fractional');
    const relative = decodeJwt((await auth.api.signJWT({body: {payload: {sub: 'relative', iat: now + 0.25}, overrideOptions: {jwt: {expirationTime: '1s'}}}})).token);
    expect(relative.exp).toBe(now + 1.25);
    const dated = decodeJwt((await auth.api.signJWT({body: {payload: {sub: 'dated'}, overrideOptions: {jwt: {expirationTime: new Date((now + 5) * 1000 + 999)}}}})).token);
    expect(dated.exp).toBe(now + 5);
    expect(toExpJWT('1s', now + 0.25)).toBe(now + 1.25);
    vi.advanceTimersByTime(100);
    expect((await auth.api.verifyJWT({body: {token}})).payload).toBeNull();
  });

  it('preserves an empty audience array and validates default expiration even when exp is supplied', async () => {
    const {auth} = await getTestInstance({plugins: [jwt({jwt: {audience: []}})]});
    const token = (await auth.api.signJWT({body: {payload: {sub: 'empty-array'}}})).token;
    expect(decodeJwt(token).aud).toEqual([]);
    expect((await auth.api.verifyJWT({body: {token}})).payload).toBeNull();
    await expect(auth.api.signJWT({body: {payload: {sub: 'invalid-config', exp: Math.floor(Date.now() / 1000) + 100}, overrideOptions: {jwt: {expirationTime: 'invalid duration'}}}})).rejects.toThrow(/Invalid time string/);
  });

  it('defaults nullable claims and rejects claim types that JOSE setters reject', async () => {
    const {auth} = await getTestInstance({plugins: [jwt()]});
    const now = Math.floor(Date.now() / 1000);
    const token = (await auth.api.signJWT({body: {payload: {sub: 'nullable', iat: now, exp: null, iss: null, aud: null}}})).token;
    const claims = (await jwtVerify(token, createLocalJWKSet(await auth.api.getJwks()), {issuer: baseURL, audience: baseURL})).payload;
    expect(claims.exp).toBe(now + 900);
    for (const payload of [{sub: 42}, {sub: 'user', iss: 42}, {sub: 'user', aud: ['audience', 42]}, {sub: 'user', jti: 42}]) {
      await expect(auth.api.signJWT({body: {payload}})).rejects.toThrow(/claim must be/);
    }
  });

  it('matches upstream pinning at the exact millisecond key-expiry boundary', async () => {
    const pair = await generateExportedKeyPair();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.123Z'));
    const record = {id: 'boundary-key', alg: 'EdDSA' as const, publicKey: JSON.stringify(pair.publicWebKey), privateKey: JSON.stringify(pair.privateWebKey), createdAt: new Date(Date.now() - 1000), expiresAt: new Date()};
    const createJwk = vi.fn(async () => {throw new Error('must not mint a replacement');});
    const options = {jwks: {disablePrivateKeyEncryption: true}, adapter: {getJwks: async () => [record], createJwk}} satisfies JwtOptions;
    const {auth} = await getTestInstance({plugins: [jwt(options)]});
    const context = await auth.$context;
    const endpoint = {context} as unknown as GenericEndpointContext;
    expect(await getJwksAdapter(context.adapter, options).getLatestKeyByAlg(endpoint, 'EdDSA')).toBeUndefined();
    const token = await signJWT(endpoint, {options, payload: {sub: 'boundary'}, signingKeyId: record.id});
    expect((await jwtVerify(token, createLocalJWKSet({keys: [{...pair.publicWebKey, kid: record.id, alg: 'EdDSA'}]}), {issuer: baseURL, audience: baseURL, currentDate: new Date()})).payload.sub).toBe('boundary');
    vi.advanceTimersByTime(1);
    await expect(signJWT(endpoint, {options, payload: {sub: 'expired'}, signingKeyId: record.id})).rejects.toThrow(/expired/);
    expect(createJwk).not.toHaveBeenCalled();
  });
});
