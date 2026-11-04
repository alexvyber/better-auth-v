import {createHmac, hkdfSync} from 'node:crypto';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {EncryptJWT, exportJWK, generateKeyPair, SignJWT} from 'jose';
import {getCookieCache as reference} from 'better-auth/cookies';
import {symmetricEncodeJWT} from 'better-auth/crypto';
import {getCookieCache} from './harness/cookies.js';

const NOW = Date.UTC(2030, 0, 1) + 123;
const SECRET = 'cookie-reader-independent-secret-at-least-32-bytes';
function payload() {
  return {session: {id: 'session', token: 'opaque', userId: 'user', expiresAt: new Date(NOW + 60000), createdAt: new Date(NOW - 1000), updatedAt: new Date(NOW)},
    user: {id: 'user', name: 'Name', email: 'CACHE@EXAMPLE.COM', emailVerified: true, createdAt: new Date(NOW - 1000), updatedAt: new Date(NOW)},
    updatedAt: NOW, version: '1', custom: {date: new Date(NOW)}};
}
function compact(data: any, expiresAt = NOW + 30000) {
  const signature = createHmac('sha256', SECRET).update(JSON.stringify({...data, expiresAt})).digest('base64url');
  return Buffer.from(JSON.stringify({session: data, expiresAt, signature})).toString('base64url');
}
function headers(value: string, name = 'better-auth.session_data') { return new Headers({cookie: `${name}=${value}`}); }

describe('standalone native cookie-cache reader', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); vi.stubEnv('BETTER_AUTH_SECRET', ''); });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

  it('matches compact schema defaults and retains unknown data without imposing auth-session binding', async () => {
    const data: any = payload();
    delete data.user.emailVerified;
    delete data.user.createdAt;
    delete data.session.updatedAt;
    data.session.userId = 42;
    data.session.id = '';
    data.user.image = null;
    data.expiresAt = 'overwritten for signing';
    const request = headers(compact(data));
    const actual = await getCookieCache(request, {secret: SECRET});
    expect(actual).toEqual(await reference(request, {secret: SECRET}));
    expect(actual?.session.userId).toBe('42');
    expect(actual?.user.email).toBe('cache@example.com');
    expect(actual?.user.emailVerified).toBe(false);
    expect(actual?.user.createdAt).toEqual(new Date(NOW));
    expect((actual as any).custom.date).toEqual(new Date(NOW));
  });

  it.each(['HS256', 'HS384', 'HS512'])('accepts independently signed %s snapshots', async alg => {
    const data = JSON.parse(JSON.stringify(payload()));
    const token = await new SignJWT(data).setProtectedHeader({alg}).setExpirationTime(NOW / 1000 + 60).sign(new TextEncoder().encode(SECRET));
    const request = headers(token);
    expect(await getCookieCache(request, {secret: SECRET, strategy: 'jwt'})).toEqual(await reference(request, {secret: SECRET, strategy: 'jwt'}));
    expect((await getCookieCache(request, {secret: SECRET, strategy: 'jwt'}))?.session.token).toBe('opaque');
    expect(await getCookieCache(request, {secret: 'wrong', strategy: 'jwt'})).toBeNull();
  });

  it('decrypts upstream JWE snapshots and enforces the embedded millisecond deadline', async () => {
    const token = await symmetricEncodeJWT(payload(), SECRET, 'better-auth-session', 60);
    const request = headers(token);
    expect(await getCookieCache(request, {secret: SECRET, strategy: 'jwe'})).toEqual(await reference(request, {secret: SECRET, strategy: 'jwe'}));
    vi.setSystemTime(NOW + 60001);
    expect(await getCookieCache(request, {secret: SECRET, strategy: 'jwe'})).toBeNull();
    expect(await reference(request, {secret: SECRET, strategy: 'jwe'})).toBeNull();
  });

  it('preserves fractional JWE claims at the JOSE tolerance boundary', async () => {
    const key = new Uint8Array(hkdfSync('sha256', SECRET, 'better-auth-session', 'BetterAuth.js Generated Encryption Key', 64));
    const data = JSON.parse(JSON.stringify(payload()));
    const seconds = Math.floor(NOW / 1000);
    for (const [claims, valid] of [[{exp: seconds - 14.5}, true], [{nbf: seconds + 15.5}, false]] as const) {
      const token = await new EncryptJWT({...data, ...claims}).setProtectedHeader({alg: 'dir', enc: 'A256CBC-HS512'}).encrypt(key);
      const request = headers(token);
      const actual = await getCookieCache(request, {secret: SECRET, strategy: 'jwe'});
      expect(actual).toEqual(await reference(request, {secret: SECRET, strategy: 'jwe'}));
      expect(actual !== null).toBe(valid);
    }
  });

  it('uses standalone permissive chunk ordering and custom secure names', async () => {
    const value = compact(payload());
    const cut = Math.floor(value.length / 2);
    const request = new Headers({cookie: `__Secure-custom.cache.nested.01=${value.slice(cut)}; __Secure-custom.cache.0junk=${value.slice(0, cut)}`});
    const options = {secret: SECRET, cookiePrefix: 'custom', cookieName: 'cache', isSecure: true};
    expect(await getCookieCache(request, options)).toEqual(await reference(request, options));
    expect((await getCookieCache(request, options))?.session.token).toBe('opaque');
  });

  it('runs version callbacks after authentication and before final expiry checks', async () => {
    const request = headers(compact(payload(), NOW));
    const callback = vi.fn(async (session, user) => {
      expect(session.expiresAt).toBeInstanceOf(Date);
      expect(user.email).toBe('cache@example.com');
      vi.setSystemTime(NOW + 1);
      return '1';
    });
    expect(await getCookieCache(request, {secret: SECRET, version: callback})).toBeNull();
    expect(callback).toHaveBeenCalledTimes(1);
    vi.setSystemTime(NOW);
    const expected = vi.fn(callback.getMockImplementation());
    expect(await reference(request, {secret: SECRET, version: expected})).toBeNull();
    expect(expected).toHaveBeenCalledTimes(1);
    const never = vi.fn(() => '1');
    expect(await getCookieCache(headers('invalid'), {secret: SECRET, version: never})).toBeNull();
    expect(never).not.toHaveBeenCalled();
  });

  it('distinguishes missing credentials from a missing snapshot and honors environment secrets', async () => {
    expect(await getCookieCache(new Headers())).toBeNull();
    await expect(getCookieCache(headers('invalid'))).rejects.toThrow('getCookieCache requires a secret');
    vi.stubEnv('BETTER_AUTH_SECRET', SECRET);
    const request = headers(compact(payload()));
    expect(await getCookieCache(request)).toEqual(await reference(request));
    expect(await getCookieCache(request, {version: '2'})).toBeNull();
    expect(await getCookieCache(request, {version: () => ''})).toBeNull();
  });

  it('rejects signed payloads with invalid schema, dates and expired outer windows', async () => {
    for (const mutate of [
      (data: any) => { data.session.expiresAt = NOW + 60000; },
      (data: any) => { data.user.emailVerified = 'true'; },
      (data: any) => { data.updatedAt = '123'; },
      (data: any) => { data.version = 1; },
      (data: any) => { data.user.name = null; },
      (data: any) => { data.session.createdAt = '2030-01-01T00:00:00+00:00'; },
      (data: any) => { data.session.token = new Date(NOW); },
      (data: any) => { data.user.image = new Date(NOW); },
      (data: any) => { data.version = new Date(NOW); },
    ]) {
      const data: any = payload(); mutate(data);
      const request = headers(compact(data));
      expect(await getCookieCache(request, {secret: SECRET})).toBeNull();
      expect(await reference(request, {secret: SECRET})).toBeNull();
    }
    const request = headers(compact(payload(), NOW - 1));
    expect(await getCookieCache(request, {secret: SECRET})).toBeNull();
    expect(await getCookieCache(headers(compact(payload(), NOW)), {secret: SECRET})).not.toBeNull();
  });

  it.each(['EdDSA', 'ES256', 'RS256'])('verifies public JWKS %s profiles with issuer and identity binding', async alg => {
    const {publicKey, privateKey} = await generateKeyPair(alg, {extractable: true});
    const key = {...await exportJWK(publicKey), kid: 'key', alg};
    const options = {strategy: 'jwt' as const, jwt: {jwks: {keys: [key]}}};
    const sign = (changes: Record<string, unknown> = {}) => new SignJWT({...JSON.parse(JSON.stringify(payload())), iss: 'issuer', sub: 'user', sid: 'opaque', aud: 'better-auth:session-cache', ...changes})
      .setProtectedHeader({alg, kid: 'key', typ: 'better-auth.session-cache+jwt'}).setExpirationTime(Math.floor(NOW / 1000) + 60).sign(privateKey);
    const request = headers(await sign());
    expect(await getCookieCache(request, options)).toEqual(await reference(request, options));
    expect((await getCookieCache(request, options))?.session.token).toBe('opaque');
    for (const changes of [{sid: 'wrong'}, {sub: 'wrong'}, {iss: ''}, {aud: 'wrong'}]) {
      const invalid = headers(await sign(changes));
      expect(await getCookieCache(invalid, options)).toBeNull();
      expect(await reference(invalid, options)).toBeNull();
    }
    const wrongIssuer = {...options, jwt: {...options.jwt, issuer: 'wrong'}};
    expect(await getCookieCache(request, wrongIssuer)).toBeNull();
    expect(await reference(request, wrongIssuer)).toBeNull();
  });

  it('honors the first matching JWK and validates imported key operation metadata', async () => {
    const {publicKey, privateKey} = await generateKeyPair('EdDSA', {extractable: true});
    const key = {...await exportJWK(publicKey), kid: 'key', alg: 'EdDSA'};
    const claims = {...JSON.parse(JSON.stringify(payload())), iss: 'issuer', sub: 'user', sid: 'opaque', aud: 'better-auth:session-cache'};
    const token = await new SignJWT(claims).setProtectedHeader({alg: 'EdDSA', kid: 'key', typ: 'better-auth.session-cache+jwt'}).sign(privateKey);
    const request = headers(token);
    for (const [metadata, valid] of [[{key_ops: ['verify']}, true], [{use: 'enc'}, true], [{key_ops: []}, false], [{key_ops: ['sign']}, false], [{key_ops: ['verify', 'verify']}, false], [{ext: 'true'}, false]] as const) {
      const options = {strategy: 'jwt' as const, jwt: {jwks: {keys: [{...key, ...metadata}]}}};
      const actual = await getCookieCache(request, options);
      expect(actual).toEqual(await reference(request, options as any));
      expect(actual !== null).toBe(valid);
    }
    const other = await exportJWK((await generateKeyPair('EdDSA', {extractable: true})).publicKey);
    const options = {strategy: 'jwt' as const, jwt: {jwks: {keys: [{...other, kid: 'key', alg: 'EdDSA'}, key]}}};
    expect(await getCookieCache(request, options)).toBeNull();
    expect(await reference(request, options)).toBeNull();
  });
});
