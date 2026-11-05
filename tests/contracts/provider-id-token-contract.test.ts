import {afterAll, beforeAll, beforeEach, describe, expect, it, vi} from 'vitest';
import {createLocalJWKSet, exportJWK, generateKeyPair, generateSecret, importJWK, jwtVerify, SignJWT, type JWK} from 'jose';
import {createPrivateKey, generateKeyPairSync, sign as rawSign} from 'node:crypto';
import {http, HttpResponse} from 'msw';
import {setupServer} from 'msw/node';
import type {OAuthIdTokenConfig} from '@better-auth/core/oauth2';
import {apple, cognito, facebook, google, microsoft, supportsIdTokenSignIn, verifyProviderIdToken} from '../harness/id-token.js';

let privateKey: CryptoKey;
let jwk: JWK;
let keys: JWK[];
let requests: string[] = [];
const server = setupServer(http.get('*', ({request}) => {
  requests.push(request.url);
  return HttpResponse.json({keys});
}));
beforeAll(async () => {
  const pair = await generateKeyPair('RS256', {extractable: true});
  privateKey = pair.privateKey;
  jwk = {...await exportJWK(pair.publicKey), kid: 'key', alg: 'RS256'};
  server.listen({onUnhandledRequest: 'error'});
});
beforeEach(() => { keys = [jwk]; requests = []; });
afterAll(() => server.close());
function sign(issuer: string, claims: Record<string, unknown> = {}) {
  return new SignJWT({sub: 'subject', ...claims}).setProtectedHeader({alg: 'RS256', kid: 'key'})
    .setIssuer(issuer).setAudience('client').setIssuedAt().setExpirationTime('1h').sign(privateKey);
}
function rawToken(header: Record<string, unknown>, claims: Record<string, unknown>) {
  const input = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + Buffer.from(JSON.stringify(claims)).toString('base64url');
  return input + '.' + rawSign('RSA-SHA256', Buffer.from(input), createPrivateKey({key: jwkPrivate!, format: 'jwk'})).toString('base64url');
}
let jwkPrivate: JWK;
beforeAll(async () => { jwkPrivate = await exportJWK(privateKey); });

describe('native shared ID-token policy and verification profiles', () => {
  it('preserves override/custom callback precedence, context identity and optional nonce', async () => {
    const ctx: any = {marker: {}};
    const custom = vi.fn(async () => { throw new Error('must not run'); });
    const override = vi.fn(async (token, nonce, context) => token === 'opaque' && nonce === undefined && context === ctx);
    const provider = {id: 'custom', options: {verifyIdToken: override}, idToken: {verify: custom}};
    expect(await verifyProviderIdToken(provider, 'opaque', undefined, ctx)).toBe(true);
    expect(override).toHaveBeenCalledWith('opaque', undefined, ctx);
    expect(custom).not.toHaveBeenCalled();
    expect(await verifyProviderIdToken({...provider, options: {verifyIdToken: override, disableIdTokenSignIn: true}}, 'opaque')).toBe(false);
    expect(override).toHaveBeenCalledTimes(1);
    expect(supportsIdTokenSignIn({...provider, options: {disableIdTokenSignIn: true}})).toBe(false);
  });

  it('checks audience and algorithm before calling a supplied resolver', async () => {
    const resolver = vi.fn(async () => importJWK(jwk, 'RS256'));
    const token = await sign('issuer');
    expect(await verifyProviderIdToken({id: 'test', idToken: {jwks: resolver, audience: ''}}, token)).toBe(false);
    expect(await verifyProviderIdToken({id: 'test', idToken: {jwks: resolver, audience: 'client', algorithms: ['ES256']}}, token)).toBe(false);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('checks extra claims only after signature and standard claims, failing closed on callback exceptions', async () => {
    const claims = vi.fn(() => false);
    const config = {jwks: createLocalJWKSet({keys: [jwk]}), issuer: 'issuer', audience: 'client', verifyClaims: claims};
    expect(await verifyProviderIdToken({id: 'test', idToken: config}, await sign('other'))).toBe(false);
    expect(claims).not.toHaveBeenCalled();
    expect(await verifyProviderIdToken({id: 'test', idToken: config}, await sign('issuer'))).toBe(false);
    expect(claims).toHaveBeenCalledWith(expect.objectContaining({sub: 'subject'}));
    claims.mockImplementation(() => { throw new Error('policy failed'); });
    expect(await verifyProviderIdToken({id: 'test', idToken: config}, await sign('issuer'))).toBe(false);
  });

  it.each([
    ['apple', apple, 'https://appleid.apple.com', 'https://appleid.apple.com/auth/keys', {}],
    ['cognito', cognito, 'https://cognito-idp.us-east-1.amazonaws.com/pool', 'https://cognito-idp.us-east-1.amazonaws.com/pool/.well-known/jwks.json', {region: 'us-east-1', userPoolId: 'pool'}],
    ['facebook', facebook, 'https://www.facebook.com', 'https://limited.facebook.com/.well-known/oauth/openid/jwks/', {}],
    ['google', google, 'accounts.google.com', 'https://www.googleapis.com/oauth2/v3/certs', {}],
    ['microsoft', microsoft, 'https://login.microsoftonline.com/work/v2.0', 'https://login.microsoftonline.com/common/discovery/v2.0/keys', {}],
  ] as const)('verifies a signed %s profile with native trust and key selection', async (_id, create, issuer, url, options) => {
    const provider = create({clientId: 'client', ...options});
    expect(await verifyProviderIdToken(provider, await sign(issuer, {tid: 'work'}))).toBe(true);
    expect(requests).toEqual([url]);
    expect(await verifyProviderIdToken(provider, await sign('https://untrusted.example', {tid: 'work'}))).toBe(false);
  });

  it('binds Microsoft multi-tenant tokens to tenant/account class and accepts absent/null key algorithms', async () => {
    keys = [{...jwk, alg: undefined}];
    const provider = microsoft({clientId: 'client', tenantId: 'organizations', authority: 'https://authority.example///'});
    expect(await verifyProviderIdToken(provider, await sign('https://authority.example/work/v2.0', {tid: 'work'}))).toBe(true);
    expect(await verifyProviderIdToken(provider, await sign('https://authority.example/other/v2.0', {tid: 'work'}))).toBe(false);
    const consumer = '9188040d-6c67-4c5b-b112-36a304b66dad';
    expect(await verifyProviderIdToken(provider, await sign(`https://authority.example/${consumer}/v2.0`, {tid: consumer}))).toBe(false);
    keys = [{...jwk, alg: null as any}];
    expect(await verifyProviderIdToken(provider, await sign('https://authority.example/work/v2.0', {tid: 'work'}))).toBe(true);
  });

  it('rejects unsupported and critical headers before profile HTTP transport', async () => {
    const provider = google({clientId: 'client'});
    const claims = {iss: 'accounts.google.com', aud: 'client', sub: 'subject', exp: Math.floor(Date.now() / 1000) + 1000, iat: Math.floor(Date.now() / 1000)};
    const token = rawToken({alg: 'RS256', kid: 'key', crit: ['unknown'], unknown: true}, claims);
    expect(await verifyProviderIdToken(provider, token)).toBe(false);
    expect(requests).toEqual([]);
  });

  it('retains CryptoKey hash/type/usage restrictions across key serialization', async () => {
    const imported = await importJWK(jwk, 'RS384') as CryptoKey;
    const token = await sign('issuer');
    await expect(jwtVerify(token, imported, {audience: 'client'})).rejects.toThrow();
    expect(await verifyProviderIdToken({id: 'test', idToken: {jwks: async () => imported, audience: 'client'}}, token)).toBe(false);
    const wrongType = {...{jwks: async () => privateKey, audience: 'client'}};
    expect(await verifyProviderIdToken({id: 'test', idToken: wrongType}, token)).toBe(false);
  });

  it.each(['HS256', 'HS384', 'HS512', 'EdDSA', 'ES256', 'ES384', 'ES512', 'RS384', 'PS256'])('verifies %s with native signature checks and serialized platform keys', async (alg) => {
    const pair = alg.startsWith('HS') ? null : await generateKeyPair(alg, {extractable: true});
    const signingKey = pair?.privateKey ?? await generateSecret(alg, {extractable: true});
    const verifyingKey = pair?.publicKey ?? signingKey;
    const token = await new SignJWT({sub: 'subject'}).setProtectedHeader({alg}).setIssuer('issuer').setAudience('client').setIssuedAt().setExpirationTime('1h').sign(signingKey);
    expect(await jwtVerify(token, verifyingKey, {issuer: 'issuer', audience: 'client'})).toBeTruthy();
    expect(await verifyProviderIdToken({id: 'test', idToken: {issuer: 'issuer', audience: 'client', jwks: async () => verifyingKey}}, token)).toBe(true);
  });

  it('rejects a correctly signed RSA token whose modulus is below 2048 bits', async () => {
    const pair = generateKeyPairSync('rsa', {modulusLength: 1024});
    const publicJwk = pair.publicKey.export({format: 'jwk'});
    const now = Math.floor(Date.now() / 1000);
    const input = Buffer.from(JSON.stringify({alg: 'RS256'})).toString('base64url') + '.' + Buffer.from(JSON.stringify({iss: 'issuer', aud: 'client', sub: 'subject', iat: now, exp: now + 3600})).toString('base64url');
    const token = input + '.' + rawSign('RSA-SHA256', Buffer.from(input), pair.privateKey).toString('base64url');
    const key = await importJWK(publicJwk, 'RS256');
    await expect(jwtVerify(token, key)).rejects.toThrow();
    expect(await verifyProviderIdToken({id: 'test', idToken: {audience: 'client', jwks: async () => key}}, token)).toBe(false);
  });

  it.each(['-0.5s', '0.5s ago', '+0.5s', '1 month', '1month', '1000000000000000000000000s'])('matches JOSE max-token-age parsing for %s', async (maxTokenAge) => {
    const now = 2000000000;
    const token = await new SignJWT({sub: 'subject'}).setProtectedHeader({alg: 'RS256', kid: 'key'}).setIssuer('issuer').setAudience('client').setIssuedAt(now - 30).setExpirationTime(now + 3600).sign(privateKey);
    const resolver = createLocalJWKSet({keys: [jwk]});
    let expected = false;
    try { await jwtVerify(token, resolver, {issuer: 'issuer', audience: 'client', maxTokenAge, clockTolerance: 30, currentDate: new Date(now * 1000)}); expected = true; } catch {}
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
    try { expect(await verifyProviderIdToken({id: 'test', idToken: {jwks: resolver, issuer: 'issuer', audience: 'client', maxTokenAge}}, token)).toBe(expected); }
    finally { clock.mockRestore(); }
  });

  it('rejects an explicitly empty issuer allowlist', async () => {
    const resolver = createLocalJWKSet({keys: [jwk]});
    const token = await sign('issuer');
    await expect(jwtVerify(token, resolver, {issuer: [], audience: 'client'})).rejects.toThrow();
    expect(await verifyProviderIdToken({id: 'test', idToken: {jwks: resolver, issuer: [], audience: 'client'}}, token)).toBe(false);
  });

  it('resolves keys before parsing max-token-age strings, matching callback order', async () => {
    const key = await importJWK(jwk, 'RS256');
    const resolver = vi.fn(async () => key);
    expect(await verifyProviderIdToken({id: 'test', idToken: {jwks: resolver, audience: 'client', maxTokenAge: 'invalid'}}, await sign('issuer'))).toBe(false);
    expect(resolver).toHaveBeenCalledOnce();
  });

  it('keeps opaque opt-in independent of unused verifier configuration', async () => {
    const config: OAuthIdTokenConfig = {audience: '', jwks: async () => { throw new Error('unused'); }, allowOpaqueToken: true, maxTokenAge: 'invalid'};
    expect(await verifyProviderIdToken({id: 'test', idToken: config}, 'opaque', 'ignored')).toBe(true);
    expect(await verifyProviderIdToken({id: 'test', options: {verifyIdToken: async () => true}, idToken: config}, 'a.b.c')).toBe(true);
  });
});
