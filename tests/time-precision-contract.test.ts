import {afterEach, describe, expect, it, vi} from 'vitest';
import {parseCookies} from 'better-auth/cookies';
import {getTestInstance} from './harness/test-instance.js';

afterEach(() => vi.useRealTimers());
function startTime() {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-01-01T00:00:00.900Z'));
  return Date.now();
}

describe('native millisecond authentication clocks', () => {
  it('preserves user, account and session record timestamps within one second', async () => {
    const now = startTime();
    const {auth, cookieSetter, db} = await getTestInstance({session: {expiresIn: 10}}, {disableTestUser: true});
    const response: Response = await auth.api.signUpEmail({body: {email: 'precision@test.com', password: 'password123', name: 'Precision'}, asResponse: true});
    const headers = new Headers();
    cookieSetter(headers)({response});
    const session = await auth.api.getSession({headers});
    expect(session!.user.createdAt.getTime()).toBe(now);
    expect(session!.session.createdAt.getTime()).toBe(now);
    expect(session!.session.expiresAt.getTime()).toBe(now + 10_000);
    const accounts = await db.findMany<{createdAt: Date; updatedAt: Date}>({model: 'account'});
    expect(accounts[0]!.createdAt.getTime()).toBe(now);
    vi.advanceTimersByTime(1);
    await auth.api.updateUser({headers, body: {name: 'Updated'}});
    expect((await auth.api.getSession({headers}))!.user.updatedAt.getTime()).toBe(now + 1);
  });

  it('checks freshness and database expiry against exact millisecond boundaries', async () => {
    startTime();
    const {auth, signInWithTestUser} = await getTestInstance({session: {freshAge: 1, expiresIn: 2, disableSessionRefresh: true}});
    const {headers} = await signInWithTestUser();
    vi.advanceTimersByTime(999);
    expect(await auth.api.listSessions({headers})).not.toHaveLength(0);
    vi.advanceTimersByTime(1);
    await expect(auth.api.listSessions({headers})).rejects.toMatchObject({statusCode: 403, body: {code: 'SESSION_NOT_FRESH'}});
    vi.advanceTimersByTime(1000);
    expect(await auth.api.getSession({headers})).not.toBeNull();
    vi.advanceTimersByTime(1);
    expect(await auth.api.getSession({headers})).toBeNull();
  });

  it('keeps an opaque reset link valid exactly at expiry and rejects it one millisecond later', async () => {
    startTime();
    const {auth, testUser, emails} = await getTestInstance({emailAndPassword: {sendResetPassword: vi.fn(), resetPasswordTokenExpiresIn: 1}});
    await auth.api.requestPasswordReset({body: {email: testUser.email}});
    const token = emails.at(-1).token;
    const link = () => auth.handler(new Request(`http://localhost:3000/api/auth/reset-password/${token}?callbackURL=/done`));
    vi.advanceTimersByTime(999);
    expect((await link()).status).toBe(302);
    vi.advanceTimersByTime(1);
    expect((await link()).status).toBe(302);
    vi.advanceTimersByTime(1);
    await expect(auth.api.resetPassword({body: {token, newPassword: 'replacement123'}})).rejects.toMatchObject({statusCode: 400, body: {code: 'INVALID_TOKEN'}});
  });

  it('uses exact compact-cookie timestamps and falls back only after cache expiry', async () => {
    const now = startTime();
    const {auth, signInWithTestUser} = await getTestInstance({session: {cookieCache: {enabled: true, maxAge: 1}, disableSessionRefresh: true}});
    const {headers} = await signInWithTestUser();
    const encoded = parseCookies(headers.get('cookie')!).get('better-auth.session_data')!;
    const cache = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    expect(cache.expiresAt).toBe(now + 1000);
    expect(cache.session.updatedAt).toBe(now);
    const context = await auth.$context;
    const findOne = vi.spyOn(context.adapter, 'findOne');
    vi.advanceTimersByTime(999);
    expect(await auth.api.getSession({headers})).not.toBeNull();
    expect(findOne).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(await auth.api.getSession({headers})).not.toBeNull();
    expect(findOne).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(await auth.api.getSession({headers})).not.toBeNull();
    expect(findOne).toHaveBeenCalled();
  });

  it('keeps secondary references in milliseconds and floors remaining TTL in seconds', async () => {
    const now = startTime();
    const store = new Map<string, string>();
    const set = vi.fn((key: string, value: string, _ttl?: number) => {store.set(key, value);});
    const {auth, signInWithTestUser} = await getTestInstance({session: {expiresIn: 10}, secondaryStorage: {
      set, get: key => store.get(key) ?? null, delete: key => {store.delete(key);},
      getAndDelete: key => {const value = store.get(key) ?? null; store.delete(key); return value;},
      increment: key => {const count = Number(store.get(key) ?? 0) + 1; store.set(key, String(count)); return count;},
    }});
    const {headers, user} = await signInWithTestUser();
    const references = JSON.parse(store.get('active-sessions-' + user.id)!);
    expect(references).not.toHaveLength(0);
    for (const reference of references) expect(reference.expiresAt).toBe(now + 10_000);
    set.mockClear();
    vi.advanceTimersByTime(1);
    await auth.api.updateUser({headers, body: {name: 'Precise cache'}});
    expect(set).toHaveBeenCalled();
    for (const [, , ttl] of set.mock.calls) expect(ttl).toBe(9);
  });

  it('does not reset an HTTP rate-limit window early at the next whole second', async () => {
    startTime();
    const {auth} = await getTestInstance({rateLimit: {enabled: true, max: 1, window: 1}});
    const request = () => auth.handler(new Request('http://localhost:3000/api/auth/ok'));
    expect((await request()).status).toBe(200);
    vi.advanceTimersByTime(100);
    expect((await request()).status).toBe(429);
    vi.advanceTimersByTime(899);
    expect((await request()).status).toBe(429);
    vi.advanceTimersByTime(1);
    expect((await request()).status).toBe(200);
  });
});
