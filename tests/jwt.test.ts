import { describe, expect, it } from 'vitest';
import { createLocalJWKSet, jwtVerify, generateKeyPair, exportJWK, SignJWT } from 'jose';
import { jwt } from './harness/plugins.js';
import type { Jwk } from 'better-auth/plugins/jwt';
import { getTestInstance } from './harness/test-instance.js';

describe('native JWT plugin boundaries', () => {
  it('keeps encrypted keys usable when a custom store assigns IDs and retains only upstream fields', async () => {
    const stored: Jwk[] = [];
    const {auth} = await getTestInstance({plugins: [jwt({adapter: {
      getJwks: async () => stored,
      createJwk: async data => {
        const key = {id: 'store-assigned-key', publicKey: data.publicKey, privateKey: data.privateKey, createdAt: data.createdAt, expiresAt: data.expiresAt, alg: data.alg, crv: data.crv};
        stored.push(key);
        return key;
      },
    }})]});
    const first = await auth.api.signJWT({body: {payload: {sub: 'first'}}});
    const second = await auth.api.signJWT({body: {payload: {sub: 'second'}}});
    expect((await auth.api.verifyJWT({body: {token: first.token}})).payload?.sub).toBe('first');
    expect((await auth.api.verifyJWT({body: {token: second.token}})).payload?.sub).toBe('second');
    expect(stored).toHaveLength(1);
    expect(stored[0].privateKey).not.toContain('"d":');
  });

  it('fails publication when a custom store acknowledges creation without retaining the key', async () => {
    const {auth} = await getTestInstance({plugins: [jwt({adapter: {
      getJwks: async () => [],
      createJwk: async data => ({...data, id: 'not-retained'}),
    }})]});
    await expect(auth.api.getJwks()).rejects.toMatchObject({statusCode: 500});
  });
  it.each(['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as const)('imports Node %s keys and verifies tokens in both directions', async alg => {
    const {publicKey, privateKey} = await generateKeyPair(alg, {extractable: true});
    const pub = await exportJWK(publicKey);
    const priv = await exportJWK(privateKey);
    const record = {id: 'node-generated-key', publicKey: JSON.stringify(pub), privateKey: JSON.stringify(priv), createdAt: new Date(), alg, crv: pub.crv};
    const {auth} = await getTestInstance({plugins: [jwt({
      jwks: {keyPairConfig: {alg} as any, disablePrivateKeyEncryption: true},
      adapter: {getJwks: async () => [record] as any, createJwk: async () => {throw new Error('Unexpected native key generation');}},
    })]});
    const native = await auth.api.signJWT({body: {payload: {sub: 'native-subject'}}});
    expect((await jwtVerify(native.token, publicKey)).payload.sub).toBe('native-subject');
    const nodeToken = await new SignJWT({sub: 'node-subject'}).setProtectedHeader({alg, kid: record.id})
      .setIssuer('http://localhost:3000').setAudience('http://localhost:3000').setExpirationTime('5m').sign(privateKey);
    expect((await auth.api.verifyJWT({body: {token: nodeToken}})).payload?.sub).toBe('node-subject');
    const pieces = nodeToken.split('.');
    const signature = Buffer.from(pieces[2], 'base64url'); signature[0] ^= 1;
    pieces[2] = signature.toString('base64url');
    expect((await auth.api.verifyJWT({body: {token: pieces.join('.')}})).payload).toBeNull();
  });
  it('publishes only public keys and issues independently verifiable session JWTs', async () => {
    const {auth, signInWithTestUser} = await getTestInstance({plugins: [jwt()]});
    const {headers} = await signInWithTestUser();
    const response = await auth.api.getSession({headers, asResponse: true});
    const token = response.headers.get('set-auth-jwt');
    expect(token).toBeTruthy();
    expect(response.headers.get('access-control-expose-headers')).toContain('set-auth-jwt');
    const jwks = await auth.api.getJwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe('OKP');
    expect(jwks.keys[0].crv).toBe('Ed25519');
    expect(jwks.keys[0]).not.toHaveProperty('d');
    const verified = await jwtVerify(token!, createLocalJWKSet(jwks), {issuer: 'http://localhost:3000', audience: 'http://localhost:3000'});
    expect(verified.payload.sub).toBeTruthy();
    expect(verified.payload.exp! - verified.payload.iat!).toBe(900);
    const dedicated = await auth.api.getToken({headers});
    expect((await jwtVerify(dedicated.token, createLocalJWKSet(jwks))).payload.sub).toBe(verified.payload.sub);
  });

  it('keeps signing/verification server-only and authenticates the token endpoint', async () => {
    const {auth} = await getTestInstance({plugins: [jwt()]});
    for (const path of ['/sign-jwt', '/verify-jwt']) {
      const response = await auth.handler(new Request('http://localhost:3000/api/auth' + path, {
        method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({payload: {sub: 'attacker'}}),
      }));
      expect(response.status).toBe(404);
    }
    expect((await auth.handler(new Request('http://localhost:3000/api/auth/token'))).status).toBe(401);
  });

  it('validates issuer, audience, signature, and expiry on the native verification path', async () => {
    const {auth} = await getTestInstance({plugins: [jwt({jwt: {issuer: 'issuer', audience: 'audience'}})]});
    const {token} = await auth.api.signJWT({body: {payload: {sub: 'subject', custom: 'claim'}}});
    expect((await auth.api.verifyJWT({body: {token}})).payload).toMatchObject({sub: 'subject', custom: 'claim'});
    const pieces = token.split('.');
    pieces[1] = Buffer.from(JSON.stringify({sub: 'forged', iss: 'issuer', aud: 'audience'})).toString('base64url');
    expect((await auth.api.verifyJWT({body: {token: pieces.join('.')}})).payload).toBeNull();
    for (const fields of [{iss: 'wrong'}, {aud: 'wrong'}, {exp: 1}, {nbf: Math.floor(Date.now()/1000) + 3600}]) {
      const invalid = await auth.api.signJWT({body: {payload: {sub: 'subject', ...fields}}});
      expect((await auth.api.verifyJWT({body: {token: invalid.token}})).payload).toBeNull();
    }
  });

  it('honors custom JWKS paths and can disable the automatic JWT response header', async () => {
    const {auth, signInWithTestUser} = await getTestInstance({plugins: [jwt({jwks: {jwksPath: '/public-keys'}, disableSettingJwtHeader: true})]});
    const {headers} = await signInWithTestUser();
    const response = await auth.api.getSession({headers, asResponse: true});
    expect(response.headers.get('set-auth-jwt')).toBeNull();
    expect((await auth.api.getJwks()).keys).toHaveLength(1);
    expect((await auth.handler(new Request('http://localhost:3000/api/auth/jwks'))).status).toBe(404);
  });
});

describe('native JWT expiration options', () => {
  it.each(['2 hours', 2000000000, new Date(2000000000500)] as const)('applies expirationTime %s and preserves explicit exp', async expirationTime => {
    const {auth} = await getTestInstance({plugins: [jwt({jwt: {expirationTime}})]});
    const signed = await auth.api.signJWT({body: {payload: {sub: 'expiration-user', iat: 1000}}});
    const claims = JSON.parse(Buffer.from(signed.token.split('.')[1], 'base64url').toString());
    expect(claims.exp).toBe(typeof expirationTime === 'string' ? 8200 : 2000000000);
    const overridden = await auth.api.signJWT({body: {payload: {sub: 'expiration-user', exp: 12345}}});
    const overrideClaims = JSON.parse(Buffer.from(overridden.token.split('.')[1], 'base64url').toString());
    expect(overrideClaims.exp).toBe(12345);
  });
});
