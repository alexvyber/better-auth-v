import { describe, expect, it, vi } from 'vitest';
import { jwtVerify, SignJWT } from 'jose';
import { getTestInstance } from '../harness/test-instance.js';

const secret = 'mail-interop-secret-is-at-least-thirty-two-characters';

describe('native verification-token contracts', () => {
  it('exchanges HS256 verification tokens with independent JOSE and rejects invalid algorithms and expiry', async () => {
    const {auth, testUser, emails} = await getTestInstance({secret,
      emailAndPassword: {requireEmailVerification: true},
      emailVerification: {sendOnSignUp: false, sendVerificationEmail: vi.fn()},
    });
    await auth.api.sendVerificationEmail({body: {email: testUser.email}});
    const key = new TextEncoder().encode(secret);
    const issued = await jwtVerify(emails.at(-1).token, key, {algorithms: ['HS256']});
    expect(issued.payload.email).toBe(testUser.email);
    expect(issued.payload.exp! - issued.payload.iat!).toBe(3600);
    const external = await new SignJWT({email: testUser.email}).setProtectedHeader({alg: 'HS256'}).setIssuedAt().setExpirationTime('5m').sign(key);
    expect(await auth.api.verifyEmail({query: {token: external}})).toEqual({status: true, user: null});
    expect((await auth.api.signInEmail({body: testUser})).user.emailVerified).toBe(true);
    const wrongAlgorithm = await new SignJWT({email: testUser.email}).setProtectedHeader({alg: 'HS512'}).setExpirationTime('5m').sign(key);
    await expect(auth.api.verifyEmail({query: {token: wrongAlgorithm}})).rejects.toMatchObject({statusCode: 401, body: {code: 'INVALID_TOKEN'}});
    const expired = await new SignJWT({email: testUser.email}).setProtectedHeader({alg: 'HS256'}).setExpirationTime(1).sign(key);
    await expect(auth.api.verifyEmail({query: {token: expired}})).rejects.toMatchObject({statusCode: 401, body: {code: 'TOKEN_EXPIRED'}});
    await expect(auth.api.verifyEmail({query: {token: 'invalid.token.bytes'}})).rejects.toMatchObject({statusCode: 401});
  });

  it('binds email changes to the token user and preserves the canonical credential account', async () => {
    let token = '';
    const {auth, testUser, signInWithTestUser, db} = await getTestInstance({secret,
      emailVerification: {sendVerificationEmail: async input => {token = input.token;}},
      user: {changeEmail: {enabled: true}},
    });
    const {headers} = await signInWithTestUser();
    await auth.api.changeEmail({headers, body: {newEmail: 'changed@example.com'}});
    const other = await auth.api.signUpEmail({body: {email: 'other@example.com', name: 'Other', password: 'password123'}, returnHeaders: true});
    const otherHeaders = new Headers({cookie: other.headers.getSetCookie()[0]});
    await expect(auth.api.verifyEmail({headers: otherHeaders, query: {token}})).rejects.toMatchObject({statusCode: 401, body: {code: 'INVALID_USER'}});
    expect((await auth.api.getSession({headers}))?.user.email).toBe(testUser.email);
    await auth.api.verifyEmail({headers, query: {token}});
    const session = await auth.api.getSession({headers});
    if (!session) throw new Error('Email change lost the authenticated session');
    expect(session.user.email).toBe('changed@example.com');
    expect(session.user.emailVerified).toBe(true);
    const accounts = await db.findMany({model: 'account', where: [{field: 'userId', value: session.user.id}]});
    expect(accounts).toHaveLength(1);
    expect(accounts[0].accountId).toBe(session.user.id);
    expect((await auth.api.signInEmail({body: {email: 'changed@example.com', password: testUser.password}})).user.id).toBe(session.user.id);
  });
});
