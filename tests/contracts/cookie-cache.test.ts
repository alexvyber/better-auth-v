import { createHmac, hkdfSync } from 'node:crypto';
import { EncryptJWT, calculateJwkThumbprint } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseCookies, parseSetCookieHeader } from 'better-auth/cookies';
import { symmetricDecodeJWT, verifyJWT } from 'better-auth/crypto';
import { getTestInstance } from '../harness/test-instance.js';

afterEach(() => vi.useRealTimers());
const secret = 'cache-interop-secret-that-is-at-least-32-bytes';
const strategies = ['compact', 'jwt', 'jwe'] as const;

describe('native cookie-cache cryptography and binding', () => {
  it.each(['A256CBC-HS512', 'A256GCM'])('accepts independently encrypted %s cache payloads', async enc => {
    const {auth, testUser, cookieSetter} = await getTestInstance({secret, session: {cookieCache: {enabled: true, strategy: 'jwe'}}});
    const response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const headers = new Headers();
    cookieSetter(headers)({response});
    const original = parseCookies(headers.get('cookie')!).get('better-auth.session_data')!;
    const payload = await symmetricDecodeJWT(original, secret, 'better-auth-session');
    expect(payload).not.toBeNull();
    const key = new Uint8Array(hkdfSync('sha256', secret, 'better-auth-session', 'BetterAuth.js Generated Encryption Key', enc === 'A256GCM' ? 32 : 64));
    const kid = await calculateJwkThumbprint({kty: 'oct', k: Buffer.from(key).toString('base64url')}, 'sha256');
    const independentlyEncrypted = await new EncryptJWT({...payload!, user: {...payload!.user, name: 'Independent JOSE payload'}})
      .setProtectedHeader({alg: 'dir', enc, kid}).setIssuedAt().setExpirationTime('5m').encrypt(key);
    const token = parseCookies(headers.get('cookie')!).get('better-auth.session_token')!;
    headers.set('cookie', `better-auth.session_token=${token}; better-auth.session_data=${independentlyEncrypted}`);
    const {adapter} = await auth.$context;
    const findOne = vi.spyOn(adapter, 'findOne');
    expect((await auth.api.getSession({headers}))?.user.name).toBe('Independent JOSE payload');
    expect(findOne).not.toHaveBeenCalled();
  });
  it.each(strategies)('emits independently verifiable %s cookies with filtered fields', async strategy => {
    const { auth, testUser } = await getTestInstance({ secret, session: {
      cookieCache: { enabled: true, strategy },
      additionalFields: { confidential: { type: 'string', returned: false, defaultValue: 'do-not-cache' } },
    } });
    const response = await auth.api.signInEmail({ body: testUser, asResponse: true });
    const encoded = parseSetCookieHeader(response.headers.get('set-cookie')!).get('better-auth.session_data')!.value;
    let payload;
    if (strategy === 'compact') {
      const cache = JSON.parse(Buffer.from(encoded, 'base64url').toString());
      const signature = createHmac('sha256', secret).update(JSON.stringify({...cache.session, expiresAt: cache.expiresAt})).digest('base64url');
      expect(cache.signature).toBe(signature);
      payload = cache.session;
    } else if (strategy === 'jwt') {
      payload = await verifyJWT(encoded, secret);
    } else {
      payload = await symmetricDecodeJWT(encoded, secret, 'better-auth-session');
      expect(encoded.split('.')).toHaveLength(5);
      expect(encoded).not.toContain(testUser.email);
    }
    expect(payload?.user.email).toBe(testUser.email);
    expect(payload?.session).not.toHaveProperty('confidential');
    expect(payload?.version).toBe('1');
  });

  it.each(strategies)('rejects a valid %s cache paired with another session token', async strategy => {
    const { auth, cookieSetter } = await getTestInstance({ secret, session: { cookieCache: { enabled: true, strategy } } }, {disableTestUser: true});
    const first = new Headers();
    const second = new Headers();
    for (const [email, headers] of [['first@example.com', first], ['second@example.com', second]] as const) {
      const response = await auth.api.signUpEmail({ body: {email, name: email, password: 'password123'}, asResponse: true });
      cookieSetter(headers)({response});
    }
    const firstCookies = parseCookies(first.get('cookie')!);
    const secondCookies = parseCookies(second.get('cookie')!);
    const headers = new Headers({cookie: `better-auth.session_token=${secondCookies.get('better-auth.session_token')}; better-auth.session_data=${firstCookies.get('better-auth.session_data')}`});
    const context = await auth.$context;
    const findOne = vi.spyOn(context.adapter, 'findOne');
    const actual = await auth.api.getSession({headers});
    expect(actual?.user.email).toBe('second@example.com');
    expect(findOne).toHaveBeenCalledOnce();
  });

  it.each(strategies)('keeps %s cache refresh nonpersistent for rememberMe:false', async strategy => {
    const { auth, testUser, cookieSetter } = await getTestInstance({ database: undefined, session: {cookieCache: {enabled: true, strategy, maxAge: 300, refreshCache: {updateAge: 60}}} });
    const headers = new Headers();
    const signedIn = await auth.api.signInEmail({body: {...testUser, rememberMe: false}, asResponse: true});
    cookieSetter(headers)({response: signedIn});
    const initial = await auth.api.getSession({headers});
    expect(initial).not.toBeNull();
    vi.useFakeTimers();
    await vi.advanceTimersByTimeAsync(241_000);
    const refreshed = await auth.api.getSession({headers, asResponse: true});
    expect((await refreshed.json()).session.expiresAt).toBe(initial!.session.expiresAt.toISOString());
    for (const [name, cookie] of parseSetCookieHeader(refreshed.headers.get('set-cookie') ?? '')) {
      if (cookie['max-age'] !== 0) expect(cookie['max-age'], name).toBeUndefined();
    }
  });

  it('chunks large cookies and removes stale chunks when a mutation shrinks the cache', async () => {
    const { auth, testUser, cookieSetter } = await getTestInstance({ session: {
      cookieCache: {enabled: true, strategy: 'jwe'},
      additionalFields: {note: {type: 'string', defaultValue: 'x'.repeat(12000)}},
    } });
    const response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const headers = new Headers();
    cookieSetter(headers)({response});
    expect([...parseCookies(headers.get('cookie')!).keys()].filter(name => name.startsWith('better-auth.session_data.')).length).toBeGreaterThan(1);
    for (const line of response.headers.getSetCookie()) expect(line.length).toBeLessThanOrEqual(4050);
    const {adapter} = await auth.$context;
    const findOne = vi.spyOn(adapter, 'findOne');
    expect((await auth.api.getSession({headers}))?.session).toHaveProperty('note', 'x'.repeat(12000));
    expect(findOne).not.toHaveBeenCalled();
    const updated = await auth.api.updateSession({headers, body: {note: 'short'}, asResponse: true});
    cookieSetter(headers)({response: updated});
    const cookies = parseCookies(headers.get('cookie')!);
    expect([...cookies.keys()].filter(name => name.startsWith('better-auth.session_data.'))).toEqual([]);
    expect(cookies.has('better-auth.session_data')).toBe(true);
    findOne.mockClear();
    expect((await auth.api.getSession({headers}))?.session).toHaveProperty('note', 'short');
    expect(findOne).not.toHaveBeenCalled();
  });

  it('serves a stateless cookie on another instance whose adapter never held the session', async () => {
    const options = { secret, database: undefined, session: {cookieCache: {enabled: true, strategy: 'jwe' as const}} };
    const first = await getTestInstance(options);
    const response = await first.auth.api.signInEmail({body: first.testUser, asResponse: true});
    const headers = new Headers();
    first.cookieSetter(headers)({response});
    const second = await getTestInstance(options, {disableTestUser: true});
    const {adapter} = await second.auth.$context;
    const findOne = vi.spyOn(adapter, 'findOne');
    expect((await second.auth.api.getSession({headers}))?.user.email).toBe(first.testUser.email);
    expect(findOne).not.toHaveBeenCalled();
  });
});
