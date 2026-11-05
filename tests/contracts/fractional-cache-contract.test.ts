import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {SignJWT, decodeJwt, jwtVerify} from 'jose';
import {symmetricDecodeJWT as referenceDecrypt} from 'better-auth/crypto';
import {getTestInstance} from '../harness/test-instance.js';
import {jwt} from '../harness/plugins.js';
import {parseSetCookieHeader} from '../harness/cookies.js';
import {signJWT, verifyJWT, symmetricEncodeJWT, symmetricDecodeJWT} from '../harness/crypto.js';

const NOW = Date.UTC(2030, 0, 1) + 123;
const SECRET = 'fractional-cache-contract-secret-at-least-32-bytes';
const seconds = Math.floor(NOW / 1000);
const cacheToken = (response: Response) => parseSetCookieHeader(response.headers.get('set-cookie')!).get('better-auth.session_data')!;

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); });
afterEach(() => { vi.useRealTimers(); });

describe('fractional native cache lifetimes', () => {
  for (const configuration of ['global', 'cookie'] as const) {
    it.each(['compact', 'jwt', 'jwe', 'jwks'] as const)(`${configuration} lifetime preserves %s payload precision and cache read boundaries`, async strategy => {
      const lifetime = 12.50075;
      const {auth, testUser, cookieSetter, db} = await getTestInstance({secret: SECRET,
        plugins: strategy === 'jwks' ? [jwt({sessionCookieCache: true})] : [],
        session: {cookieCache: {enabled: true, strategy: strategy === 'jwks' ? 'jwt' : strategy, maxAge: configuration === 'global' ? lifetime : 300}},
        advanced: configuration === 'cookie' ? {cookies: {session_data: {attributes: {maxAge: lifetime}}}} : {},
      });
      const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
      const cookie = cacheToken(response);
      expect(cookie['max-age']).toBe(12);
      let deadline: number;
      if (strategy === 'compact') {
        const outer = JSON.parse(Buffer.from(cookie.value, 'base64url').toString());
        deadline = outer.expiresAt;
        expect(deadline).toBe(Math.trunc(NOW + lifetime * 1000));
      } else {
        const claims = strategy === 'jwe' ? await referenceDecrypt<any>(cookie.value, SECRET, 'better-auth-session') : decodeJwt(cookie.value);
        expect(claims?.exp).toBe(seconds + lifetime);
        expect(claims?.iat).toBe(seconds);
        deadline = claims!.exp! * 1000;
      }
      const headers = new Headers(); cookieSetter(headers)({response});
      const session = await auth.api.getSession({headers});
      expect(session?.user.email).toBe(testUser.email);
      expect(await db.deleteMany({model: 'session', where: [{field: 'userId', value: session!.user.id}]})).toBeGreaterThan(0);
      // With all database sessions removed, a hit proves the exact fractional
      // cache window survived decoding rather than falling back to storage.
      vi.setSystemTime(Math.floor(deadline));
      expect((await auth.api.getSession({headers}))?.user.email).toBe(testUser.email);
      vi.setSystemTime(Math.floor(deadline) + 1);
      expect(await auth.api.getSession({headers})).toBeNull();
    });
  }

  it('keeps negative fractional Max-Age absent and zero as the compact fallback', async () => {
    for (const age of [-0.5, 0, 0.00075]) {
      const {auth, testUser} = await getTestInstance({secret: SECRET, session: {cookieCache: {enabled: true}}, advanced: {cookies: {session_data: {attributes: {maxAge: age}}}}});
      const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
      const cookie = cacheToken(response);
      expect(cookie['max-age']).toBe(age < 0 ? undefined : 0);
      const outer = JSON.parse(Buffer.from(cookie.value, 'base64url').toString());
      expect(outer.expiresAt).toBe(Math.trunc(NOW + (age || 60) * 1000));
    }
  });

  it('uses a fractional stateless refresh threshold without refreshing at equality', async () => {
    const {auth, testUser, cookieSetter} = await getTestInstance({secret: SECRET, database: undefined,
      session: {cookieCache: {enabled: true, strategy: 'compact', maxAge: 12.5, refreshCache: {updateAge: 2.25}}},
    });
    const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const headers = new Headers(); cookieSetter(headers)({response});
    vi.setSystemTime(NOW + 10250);
    const equal: Response = await auth.api.getSession({headers, asResponse: true});
    expect(equal.headers.getSetCookie()).toEqual([]);
    vi.setSystemTime(NOW + 10251);
    const due: Response = await auth.api.getSession({headers, asResponse: true});
    const refreshed = cacheToken(due);
    expect(refreshed['max-age']).toBe(12);
    const outer = JSON.parse(Buffer.from(refreshed.value, 'base64url').toString());
    expect(outer.expiresAt).toBe(NOW + 10251 + 12500);
  });

  it('emits fractional HMAC and JWE NumericDates interoperable with JOSE', async () => {
    const token = await signJWT({value: 'signed'}, SECRET, 0.5);
    expect((await jwtVerify(token, new TextEncoder().encode(SECRET))).payload.exp).toBe(seconds + 0.5);
    expect((await verifyJWT(token, SECRET))?.value).toBe('signed');
    const encrypted = await symmetricEncodeJWT({value: 'encrypted'}, SECRET, 'better-auth-session', 0.5);
    expect((await referenceDecrypt<any>(encrypted, SECRET, 'better-auth-session'))?.exp).toBe(seconds + 0.5);
    vi.setSystemTime((seconds + 1) * 1000);
    expect(await verifyJWT(token, SECRET)).toBeNull();
    expect((await symmetricDecodeJWT(encrypted, SECRET, 'better-auth-session'))?.value).toBe('encrypted');
    vi.setSystemTime((seconds + 16) * 1000);
    expect(await symmetricDecodeJWT(encrypted, SECRET, 'better-auth-session')).toBeNull();
  });

  it.each(['HS256', 'HS384', 'HS512'])('validates fractional claims and iat types for %s helpers', async alg => {
    const key = new TextEncoder().encode(SECRET);
    for (const [claims, valid] of [[{exp: seconds + 0.5}, true], [{nbf: seconds + 0.5}, false], [{iat: 'invalid'}, false]] as const) {
      const token = await new SignJWT(claims as any).setProtectedHeader({alg}).sign(key);
      const native = await verifyJWT(token, SECRET);
      let expected: unknown = null;
      try { expected = (await jwtVerify(token, key)).payload; } catch {}
      expect(native).toEqual(expected);
      expect(native !== null).toBe(valid);
    }
  });
});
