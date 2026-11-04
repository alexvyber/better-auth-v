import { describe, expect, it, vi } from 'vitest';
import { getTestInstance } from './harness/test-instance.js';

async function callback(auth: {handler(request: Request): Promise<Response>}, token: string, headers: Headers, suffix = '') {
  return auth.handler(new Request(`http://localhost:3000/api/auth/delete-user/callback?token=${token}${suffix}`, {headers}));
}

describe('native user deletion boundaries', () => {
  it('disables deletion by default and keeps the account intact', async () => {
    const {auth, signInWithTestUser} = await getTestInstance();
    const {headers} = await signInWithTestUser();
    await expect(auth.api.deleteUser({headers})).rejects.toMatchObject({statusCode: 404});
    expect(await auth.api.getSession({headers})).not.toBeNull();
  });

  it('burns wrong-owner tokens and rejects expired tokens without deleting either user', async () => {
    vi.useFakeTimers();
    try {
      let token = '';
      const beforeDelete = vi.fn();
      const {auth, signInWithTestUser, cookieSetter, db} = await getTestInstance({user: {deleteUser: {
        enabled: true, deleteTokenExpiresIn: 2, beforeDelete,
        sendDeleteAccountVerification: async data => {token = data.token;},
      }}});
      const {headers} = await signInWithTestUser();
      const otherHeaders = new Headers();
      cookieSetter(otherHeaders)({response: await auth.api.signUpEmail({body: {email: 'other-delete@test.com', password: 'password123', name: 'Other'}, asResponse: true})});
      await auth.api.deleteUser({headers});
      expect(token).toMatch(/^[a-z0-9]{32}$/);
      expect(await db.findMany({model: 'verification', where: [{field: 'identifier', value: `delete-account-${token}`}]})).toHaveLength(1);
      expect((await callback(auth, token, otherHeaders)).status).toBe(404);
      expect(await db.findMany({model: 'verification', where: [{field: 'identifier', value: `delete-account-${token}`}]})).toHaveLength(0);
      expect((await callback(auth, token, headers)).status).toBe(404);
      await auth.api.deleteUser({headers});
      vi.advanceTimersByTime(2000);
      expect((await callback(auth, token, headers)).status).toBe(404);
      expect(beforeDelete).not.toHaveBeenCalled();
      expect(await auth.api.getSession({headers})).not.toBeNull();
      expect(await auth.api.getSession({headers: otherHeaders})).not.toBeNull();
    } finally { vi.useRealTimers(); }
  });

  it('rejects a revoked backing session even when its valid cache cookies are retained', async () => {
    let token = '';
    const beforeDelete = vi.fn();
    const {auth, signInWithTestUser, cookieSetter, db} = await getTestInstance({
      session: {cookieCache: {enabled: true, maxAge: 60}},
      user: {deleteUser: {enabled: true, beforeDelete, sendDeleteAccountVerification: async data => {token = data.token;}}},
    });
    const {headers} = await signInWithTestUser();
    cookieSetter(headers)({response: await auth.api.getSession({headers, asResponse: true})});
    expect(headers.get('cookie')).toContain('better-auth.session_data=');
    const session = await auth.api.getSession({headers});
    await auth.api.deleteUser({headers});
    await db.delete({model: 'session', where: [{field: 'token', value: session!.session.token}]});
    expect((await auth.api.getSession({headers}))?.session.token).toBe(session!.session.token);
    expect((await callback(auth, token, headers)).status).toBe(404);
    await expect(auth.api.deleteUser({headers, body: {token}})).rejects.toMatchObject({statusCode: 401});
    expect(beforeDelete).not.toHaveBeenCalled();
    expect(await db.findMany({model: 'verification', where: [{field: 'identifier', value: `delete-account-${token}`}]})).toHaveLength(1);
  });

  it('consumes tokens before callbacks and keeps deletion durable when afterDelete fails', async () => {
    let token = '';
    const beforeDelete = vi.fn(async (): Promise<void> => {throw new Error('stop deletion');});
    const afterDelete = vi.fn(async () => {throw new Error('after deletion');});
    const {auth, signInWithTestUser, db} = await getTestInstance({user: {deleteUser: {
      enabled: true, beforeDelete, afterDelete, sendDeleteAccountVerification: async data => {token = data.token;},
    }}});
    const {headers} = await signInWithTestUser();
    await auth.api.deleteUser({headers});
    expect((await callback(auth, token, headers)).status).toBe(500);
    beforeDelete.mockResolvedValue(undefined);
    expect((await callback(auth, token, headers)).status).toBe(404);
    expect(await auth.api.getSession({headers})).not.toBeNull();
    await auth.api.deleteUser({headers});
    expect((await callback(auth, token, headers)).status).toBe(500);
    expect(afterDelete).toHaveBeenCalledOnce();
    expect(await auth.api.getSession({headers})).toBeNull();
    expect(await db.findMany({model: 'user'})).toHaveLength(0);
  });

  it('completes the email GET callback and preserves the trusted redirect query', async () => {
    let token = '';
    const beforeDelete = vi.fn();
    const afterDelete = vi.fn();
    const {auth, signInWithTestUser, db} = await getTestInstance({user: {deleteUser: {
      enabled: true, beforeDelete, afterDelete, sendDeleteAccountVerification: async data => {token = data.token;},
    }}});
    const {headers} = await signInWithTestUser();
    await auth.api.deleteUser({headers});
    const response = await callback(auth, token, headers, '&callbackURL=' + encodeURIComponent('/goodbye?source=email&done=1'));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('/goodbye?source=email&done=1');
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(beforeDelete).toHaveBeenCalledOnce();
    expect(afterDelete).toHaveBeenCalledOnce();
    expect(await db.findMany({model: 'user'})).toHaveLength(0);
    expect(await db.findMany({model: 'verification'})).toHaveLength(0);
  });

  it('keeps setPassword server-only and reports native policy errors', async () => {
    const {auth, signInWithTestUser} = await getTestInstance();
    const {headers} = await signInWithTestUser();
    await expect(auth.api.setPassword({body: {newPassword: 'password123'}})).rejects.toMatchObject({statusCode: 401});
    await expect(auth.api.setPassword({headers, body: {newPassword: 'x'.repeat(129)}})).rejects.toMatchObject({statusCode: 400, body: {code: 'PASSWORD_TOO_LONG'}});
    await expect(auth.api.setPassword({headers, body: {newPassword: 'password123'}})).rejects.toMatchObject({statusCode: 400, body: {code: 'PASSWORD_ALREADY_SET'}});
    expect((await auth.handler(new Request('http://localhost:3000/api/auth/set-password', {method: 'POST', headers: {origin: 'http://localhost:3000', 'content-type': 'application/json', cookie: headers.get('cookie')!}, body: '{"newPassword":"password123"}'}))).status).toBe(404);
  });
});
