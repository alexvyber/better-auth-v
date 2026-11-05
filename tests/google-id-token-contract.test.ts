import {afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi} from 'vitest';
import {exportJWK, generateKeyPair, jwtVerify, SignJWT, type JWK} from 'jose';
import {createPrivateKey, sign as rawSign} from 'node:crypto';
import {http, HttpResponse} from 'msw';
import {setupServer} from 'msw/node';
import {getTestInstance} from './harness/test-instance.js';
import {verifyGoogleIdToken} from './harness/google.js';
import {parseCookies, parseSetCookieHeader} from './harness/cookies.js';

const NOW = Date.UTC(2030, 0, 1) + 123;
const seconds = Math.floor(NOW / 1000);
let privateKey: CryptoKey;
let publicJwk: JWK;
let otherPrivate: CryptoKey;
let otherJwk: JWK;
let keys: JWK[];
let keyRequests = 0;
let codeRequests = 0;
const server = setupServer(http.get('https://www.googleapis.com/oauth2/v3/certs', () => { keyRequests++; return HttpResponse.json({keys}); }), http.post('https://oauth2.googleapis.com/token', () => { codeRequests++; return HttpResponse.json({}); }));
beforeAll(async () => {
  const keypair = await generateKeyPair('RS256', {extractable: true});
  privateKey = keypair.privateKey;
  publicJwk = {...await exportJWK(keypair.publicKey), kid: 'google-key', alg: 'RS256', use: 'sig'};
  const other = await generateKeyPair('RS256', {extractable: true});
  otherPrivate = other.privateKey;
  otherJwk = {...await exportJWK(other.publicKey), kid: 'other-key', alg: 'RS256'};
  server.listen({onUnhandledRequest: 'error'});
});
afterAll(() => server.close());
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); keys = [publicJwk]; keyRequests = 0; codeRequests = 0; });
afterEach(() => { vi.useRealTimers(); server.resetHandlers(); });

function claims(changes: Record<string, unknown> = {}) {
  return {iss: 'https://accounts.google.com', aud: 'client', sub: 'google-subject', exp: seconds + 3600, iat: seconds, nonce: 'nonce', email: 'signed@example.com', email_verified: true, name: 'Signed User', hd: 'example.com', ...changes};
}
async function sign(payload: Record<string, unknown> = claims(), header: Record<string, unknown> = {alg: 'RS256', kid: 'google-key'}, key: CryptoKey | Uint8Array = privateKey) {
  return new SignJWT(payload).setProtectedHeader(header as any).sign(key);
}
async function instance(google: Record<string, unknown> = {}) {
  return getTestInstance({socialProviders: {google: {clientId: 'client', clientSecret: 'secret', ...google}}, account: {storeAccountCookie: true}, session: {cookieCache: {enabled: true}}});
}
async function request(auth: any, idToken: unknown) {
  return auth.handler(new Request('http://localhost:3000/api/auth/sign-in/social', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({provider: 'google', idToken})})) as Promise<Response>;
}

describe('native Google ID-token credentials', () => {
  it('creates a session directly after native verification and persists the pinned branch token fields', async () => {
    const {auth, db, cookieSetter} = await instance();
    const token = await sign();
    const response = await request(auth, {token, nonce: 'nonce', accessToken: 'access', refreshToken: 'input-refresh', expiresAt: seconds + 120, user: {email: 'spoofed@example.com'}});
    expect(response.status).toBe(200);
    const result = await response.clone().json();
    expect(result).toMatchObject({redirect: false, token: expect.any(String), user: {email: 'signed@example.com', emailVerified: true}});
    expect(result).not.toHaveProperty('url');
    expect(codeRequests).toBe(0);
    expect(keyRequests).toBe(1);
    const headers = new Headers(); cookieSetter(headers)({response});
    const cookies = parseCookies(headers.get('cookie')!);
    expect(cookies.has('better-auth.session_token')).toBe(true);
    expect(cookies.has('better-auth.session_data')).toBe(true);
    expect(cookies.has('better-auth.account_data')).toBe(true);
    expect(cookies.has('better-auth.oauth_state')).toBe(false);
    expect(cookies.has('better-auth.state')).toBe(false);
    expect((await auth.api.getSession({headers}))?.user.id).toBe(result.user.id);
    const account = (await db.findMany<any>({model: 'account', where: [{field: 'providerId', value: 'google'}]}))[0];
    expect(account.accessToken).toBe('access');
    expect(account.idToken).toBe(token);
    expect(account.refreshToken).toBeUndefined();
    expect(account.accessTokenExpiresAt).toBeUndefined();
    expect(await db.findMany({model: 'verification'})).toEqual([]);
  });

  it('rejects missing required claims, wrong issuer/audience and nonce before any account write', async () => {
    const {auth, db} = await instance();
    const variants: Record<string, unknown>[] = ['iss', 'sub', 'aud', 'exp', 'iat'].map(name => { const value: any = claims(); delete value[name]; return value; });
    variants.push(claims({iss: 'https://attacker.example'}), claims({aud: 'other-client'}), claims({nonce: 'wrong'}), claims({exp: 'tomorrow'}), claims({iat: 'now'}));
    for (const payload of variants) {
      const response = await request(auth, {token: await sign(payload), nonce: 'nonce'});
      expect(response.status).toBe(401);
      expect((await response.json()).code).toBe('INVALID_TOKEN');
    }
    expect(await db.findMany({model: 'account', where: [{field: 'providerId', value: 'google'}]})).toEqual([]);
  });

  it('rejects forgery and symmetric/none algorithms without using the token algorithm as trusted policy', async () => {
    const {auth} = await instance();
    expect((await request(auth, {token: await sign(claims(), {alg: 'RS256', kid: 'google-key'}, otherPrivate)})).status).toBe(401);
    const count = keyRequests;
    const hmac = await sign(claims(), {alg: 'HS256', kid: 'google-key'}, new TextEncoder().encode('untrusted-key-material-at-least-32-bytes'));
    const none = Buffer.from(JSON.stringify({alg: 'none'})).toString('base64url') + '.' + Buffer.from(JSON.stringify(claims())).toString('base64url') + '.';
    expect((await request(auth, {token: hmac})).status).toBe(401);
    expect((await request(auth, {token: none})).status).toBe(401);
    expect(keyRequests).toBe(count);
    expect(codeRequests).toBe(0);
  });

  it('matches independent JOSE at exact 30-second clock and maximum-age boundaries', async () => {
    const {auth} = await instance();
    const variants = [{exp: seconds - 30}, {exp: seconds - 29.5}, {nbf: seconds + 30}, {nbf: seconds + 30.5}, {iat: seconds - 3630}, {iat: seconds - 3630.5}, {iat: seconds + 30}, {iat: seconds + 30.5}];
    const {importJWK} = await import('jose');
    const key = await importJWK(publicJwk, 'RS256');
    for (const value of variants) {
      const token = await sign(claims(value));
      let valid = false;
      try { await jwtVerify(token, key, {issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: 'client', algorithms: ['RS256'], requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'], maxTokenAge: '1h', clockTolerance: 30}); valid = true; } catch {}
      const response = await request(auth, {token});
      expect(response.status === 200, JSON.stringify(value)).toBe(valid);
    }
  });

  it('honors audience arrays, hosted-domain checks and the disabled direct-token option', async () => {
    const {auth} = await instance({clientId: ['primary', 'client'], hd: 'example.com', clientSecret: undefined});
    expect((await request(auth, {token: await sign()})).status).toBe(200);
    expect((await request(auth, {token: await sign(claims({hd: 'other.example'}))})).status).toBe(401);
    const disabled = await instance({disableIdTokenSignIn: true});
    const before = keyRequests;
    const response = await request(disabled.auth, {token: await sign()});
    expect(response.status).toBe(404);
    expect((await response.json()).code).toBe('ID_TOKEN_NOT_SUPPORTED');
    expect(keyRequests).toBe(before);
  });

  it('distinguishes standalone candidate iteration from the provider resolver first-key policy', async () => {
    keys = [otherJwk, {...publicJwk, alg: 'RS512', use: 'enc'}];
    const token = await sign(claims(), {alg: 'RS256'});
    expect((await verifyGoogleIdToken({token, audience: 'client'}))?.sub).toBe('google-subject');
    const {auth} = await instance();
    expect((await request(auth, {token})).status).toBe(401);
    // A kid selects the trusted key; importJWK's explicit RS256 argument
    // overrides optional alg/use metadata before jwtVerify checks the token.
    expect((await request(auth, {token: await sign()})).status).toBe(200);
  });

  it('rejects malformed direct-token bodies instead of starting a code flow', async () => {
    const {auth} = await instance();
    for (const idToken of [null, '', [], {}, {token: 1}, {token: 'x', nonce: null}, {token: 'x', expiresAt: 'tomorrow'}, {token: 'x', user: {name: []}}]) expect((await request(auth, idToken)).status).toBe(400);
    expect(keyRequests).toBe(0);
    expect(codeRequests).toBe(0);
  });

  it('keeps an unverified Google email unverified under the default provider policy', async () => {
    const {auth, db} = await instance();
    const response = await request(auth, {token: await sign(claims({email_verified: false}))});
    expect(response.status).toBe(200);
    expect((await response.json()).user.emailVerified).toBe(false);
    const users = await db.findMany<any>({model: 'user', where: [{field: 'email', value: 'signed@example.com'}]});
    expect(users[0].emailVerified).toBe(false);
  });

  it('fails closed on key redirects and malformed matching keys', async () => {
    const {auth} = await instance();
    const token = await sign();
    keys = [{...publicJwk, key_ops: ['sign']}];
    expect((await request(auth, {token})).status).toBe(401);
    keys = [{...publicJwk, e: ''}];
    expect((await request(auth, {token})).status).toBe(401);
    server.use(http.get('https://www.googleapis.com/oauth2/v3/certs', () => new HttpResponse(null, {status: 302, headers: {location: 'https://other.example/keys'}})));
    expect((await request(auth, {token})).status).toBe(401);
  });

  it('accepts understood b64 critical headers and rejects unknown critical extensions', async () => {
    const {auth} = await instance();
    const token = await sign(claims(), {alg: 'RS256', kid: 'google-key', crit: ['b64'], b64: true});
    expect((await request(auth, {token})).status).toBe(200);
    const header = Buffer.from(JSON.stringify({alg: 'RS256', kid: 'google-key', crit: ['unknown'], unknown: true})).toString('base64url');
    const input = header + '.' + token.split('.')[1];
    const signingKey = createPrivateKey({key: await exportJWK(privateKey), format: 'jwk'});
    const unknown = input + '.' + rawSign('RSA-SHA256', Buffer.from(input), signingKey).toString('base64url');
    const {importJWK} = await import('jose');
    expect((await jwtVerify(unknown, await importJWK(publicJwk, 'RS256'), {crit: {unknown: true}})).payload.sub).toBe('google-subject');
    const body = {provider: 'google', idToken: {token: unknown}};
    const response = await auth.handler(new Request('http://localhost:3000/api/auth/sign-in/social', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body)}));
    expect(response.status).toBe(401);
    expect(parseSetCookieHeader(response.headers.get('set-cookie') ?? '').size).toBe(0);
  });
});
