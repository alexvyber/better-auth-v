import {createHash} from 'node:crypto';
import {describe, expect, it} from 'vitest';
import {getTestInstance} from './harness/test-instance.js';
import {oneTimeToken} from './harness/plugins.js';
const hashed = (value: string) => createHash('sha256').update(value).digest('base64url');

describe('unified core verification records', () => {
 it('stores reset proofs as UUID records with hashed identifiers and consumes them through the trusted API', async () => {
  let token = '';
  const {auth, testUser} = await getTestInstance({advanced: {database: {generateId: 'uuid'}}, verification: {storeIdentifier: 'hashed'}, emailAndPassword: {sendResetPassword: async data => {token = data.token;}}});
  await auth.api.requestPasswordReset({body: {email: testUser.email}});
  expect(token).toMatch(/^[a-zA-Z0-9]{24}$/);
  const adapter = (await auth.$context).internalAdapter;
  const proof = await adapter.findVerificationValue('reset-password:' + token);
  expect(proof.id).toMatch(/^[\da-f]{8}-[\da-f]{4}-4/);
  expect(proof.identifier).toBe(hashed('reset-password:' + token));
  await auth.api.resetPassword({body: {token, newPassword: 'changed-password'}});
  expect(await adapter.findVerificationValue('reset-password:' + token)).toBeNull();
  expect((await auth.api.signInEmail({body: {email: testUser.email, password: 'changed-password'}})).user.id).toBe(proof.value);
  await expect(auth.api.resetPassword({body: {token, newPassword: 'other-password'}})).rejects.toMatchObject({body: {code: 'INVALID_TOKEN'}});
 });

 it('accepts a reset proof created through the server verification API', async () => {
  const {auth, testUser} = await getTestInstance({verification: {storeIdentifier: 'hashed'}});
  const adapter = (await auth.$context).internalAdapter;
  const user = await adapter.findUserByEmail(testUser.email);
  await adapter.createVerificationValue({identifier: 'reset-password:external-proof', value: user.user.id, expiresAt: new Date(Date.now() + 60000)});
  expect(await auth.api.resetPassword({body: {token: 'external-proof', newPassword: 'changed-password'}})).toEqual({status: true});
 });

 it('uses hashed deletion proofs while preserving irreversible single-use semantics', async () => {
  let token = '';
  const {auth, signInWithTestUser} = await getTestInstance({advanced: {database: {generateId: 'uuid'}}, verification: {storeIdentifier: 'hashed'}, user: {deleteUser: {enabled: true, sendDeleteAccountVerification: async data => {token = data.token;}}}});
  const {headers} = await signInWithTestUser();
  await auth.api.deleteUser({headers});
  const adapter = (await auth.$context).internalAdapter;
  const proof = await adapter.findVerificationValue('delete-account-' + token);
  expect(proof.identifier).toBe(hashed('delete-account-' + token));
  const response = await auth.handler(new Request('http://localhost:3000/api/auth/delete-user/callback?token=' + token, {headers}));
  expect(response.status).toBe(200);
  expect(await adapter.findUserById(proof.value)).toBeNull();
  expect(await adapter.findVerificationValue('delete-account-' + token)).toBeNull();
 });

 it('updates session cookies and OTT headers after a hashed magic-link proof revokes unproven access', async () => {
  const {auth, signInWithTestUser, testUser, emails} = await getTestInstance({verification: {storeIdentifier: 'hashed'}, advanced: {database: {generateId: 'uuid'}}, plugins: [oneTimeToken({setOttHeaderOnNewSession: true})]}, {magicLink: true});
  const {headers} = await signInWithTestUser();
  const previous = await auth.api.getSession({headers});
  await auth.handler(new Request('http://localhost:3000/api/auth/sign-in/magic-link', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({email: testUser.email})}));
  const response = await auth.handler(new Request(emails.at(-1).url));
  expect(response.status).toBe(200);
  expect(await auth.api.getSession({headers})).toBeNull();
  expect(await (await auth.$context).internalAdapter.findAccounts(previous!.user.id)).toEqual([]);
  const ott = response.headers.get('set-ott');
  expect(ott).toHaveLength(32);
  expect((await auth.api.verifyOneTimeToken({body: {token: ott}})).user.emailVerified).toBe(true);
 });
});
