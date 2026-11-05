import {afterEach, describe, expect, it, vi} from 'vitest';
import {createHash} from 'node:crypto';
import {getTestInstance} from '../harness/test-instance.js';
import {createAuthEndpoint, freshSessionMiddleware} from '../harness/endpoint.js';
import {oneTimeToken, jwt} from '../harness/plugins.js';

const NOW = 2000000000123;
afterEach(() => vi.useRealTimers());

describe('native OTT and trusted verification contracts', () => {
 it('stores the independent SHA256 digest and redeems the existing session without creating another', async () => {
  const {auth, signInWithTestUser} = await getTestInstance({plugins: [oneTimeToken({storeToken: 'hashed', generateToken: async () => 'known-token'})]});
  const {headers} = await signInWithTestUser();
  const original = await auth.api.getSession({headers});
  const generated = await auth.api.generateOneTimeToken({headers});
  const {internalAdapter} = await auth.$context;
  const sessionCount = (await internalAdapter.listSessions(original!.user.id)).length;
  const digest = createHash('sha256').update(generated.token).digest('base64url');
  expect((await internalAdapter.findVerificationValue('one-time-token:' + digest))?.value).toBe(original!.session.token);
  const redeemed = await auth.api.verifyOneTimeToken({body: generated});
  expect(redeemed.session.id).toBe(original!.session.id);
  expect(redeemed.session.token).toBe(original!.session.token);
  expect(await internalAdapter.listSessions(original!.user.id)).toHaveLength(sessionCount);
 });

 it('burns an OTT even when the underlying session is revoked', async () => {
  const {auth, signInWithTestUser} = await getTestInstance({plugins: [oneTimeToken()]});
  const {headers} = await signInWithTestUser();
  const generated = await auth.api.generateOneTimeToken({headers});
  const {internalAdapter} = await auth.$context;
  const session = await auth.api.getSession({headers});
  await internalAdapter.deleteSession(session!.session.token);
  await expect(auth.api.verifyOneTimeToken({body: generated})).rejects.toMatchObject({body: {message: 'Session not found'}});
  await expect(auth.api.verifyOneTimeToken({body: generated})).rejects.toMatchObject({body: {message: 'Invalid token'}});
 });

 it('enforces millisecond expiry and accepts the exact upstream expiry boundary', async () => {
  vi.useFakeTimers({toFake: ['Date']}); vi.setSystemTime(NOW);
  const {auth, signInWithTestUser} = await getTestInstance({plugins: [oneTimeToken({expiresIn: 0.0005})]});
  const {headers} = await signInWithTestUser();
  const first = await auth.api.generateOneTimeToken({headers});
  vi.setSystemTime(NOW + 30);
  expect((await auth.api.verifyOneTimeToken({body: first})).user.email).toBeDefined();
  const second = await auth.api.generateOneTimeToken({headers});
  vi.setSystemTime(NOW + 61);
  await expect(auth.api.verifyOneTimeToken({body: second})).rejects.toMatchObject({body: {message: 'Invalid token'}});
 });

 it('coexists with the JWT plugin and emits redeemable session headers', async () => {
  const {auth} = await getTestInstance({plugins: [oneTimeToken({setOttHeaderOnNewSession: true}), jwt()]}, {disableTestUser: true});
  const response = await auth.api.signUpEmail({body: {email: 'ott@example.com', password: 'password123', name: 'OTT'}, asResponse: true});
  const token = response.headers.get('set-ott');
  expect(token).toHaveLength(32);
  const redeemed = await auth.api.verifyOneTimeToken({body: {token}});
  expect(redeemed.user.email).toBe('ott@example.com');
  expect(response.headers.get('access-control-expose-headers')).toContain('set-ott');
 });

 it('issues another OTT when redemption sets a session cookie', async () => {
  const {auth, signInWithTestUser} = await getTestInstance({plugins: [oneTimeToken({setOttHeaderOnNewSession: true})]});
  const {headers} = await signInWithTestUser();
  const generated = await auth.api.generateOneTimeToken({headers});
  const response = await auth.api.verifyOneTimeToken({body: generated, asResponse: true});
  const next = response.headers.get('set-ott');
  expect(next).toHaveLength(32);
  expect(next).not.toBe(generated.token);
  expect((await auth.api.verifyOneTimeToken({body: {token: next}})).user.email).toBeDefined();
 });

 it('does not issue OTT headers for allocating an internal session without setting cookies', async () => {
  const {auth, signInWithTestUser} = await getTestInstance({plugins: [oneTimeToken({setOttHeaderOnNewSession: true}), {
   id: 'allocate-session-only', endpoints: {allocateSession: createAuthEndpoint('/allocate-session-only', {method: 'POST', use: [freshSessionMiddleware]}, async context => { const session = context.context.session; if (!session) throw new Error('Session middleware did not provide a session'); return context.context.internalAdapter.createSession(session.user.id); })},
  }]});
  const {headers} = await signInWithTestUser();
  const requestHeaders = new Headers(headers); requestHeaders.set('content-type', 'application/json'); requestHeaders.set('origin', 'http://localhost:3000');
  const response = await auth.handler(new Request('http://localhost:3000/api/auth/allocate-session-only', {method: 'POST', headers: requestHeaders, body: '{}'}));
  expect(response.status).toBe(200);
  expect(response.headers.has('set-ott')).toBe(false);
 });

 it('cleans expired verification records after returning the captured result once', async () => {
  const {auth} = await getTestInstance({}, {disableTestUser: true});
  const {internalAdapter} = await auth.$context;
  await internalAdapter.createVerificationValue({identifier: 'expired', value: 'value', expiresAt: new Date(Date.now() - 1000)});
  expect((await internalAdapter.findVerificationValue('expired'))?.value).toBe('value');
  expect(await internalAdapter.findVerificationValue('expired')).toBeNull();
 });

 it('applies prefix identifier policies and consumes the latest record, invalidating older duplicates', async () => {
  vi.useFakeTimers({toFake: ['Date']}); vi.setSystemTime(NOW);
  const {auth} = await getTestInstance({verification: {storeIdentifier: {default: 'plain', overrides: {'secure:': 'hashed'}}}}, {disableTestUser: true});
  const {internalAdapter} = await auth.$context;
  const older = await internalAdapter.createVerificationValue({identifier: 'secure:handoff', value: 'older', expiresAt: new Date(NOW + 60000)});
  expect(older.identifier).toBe(createHash('sha256').update('secure:handoff').digest('base64url'));
  vi.setSystemTime(NOW + 1);
  await internalAdapter.createVerificationValue({identifier: 'secure:handoff', value: 'newer', expiresAt: new Date(NOW + 60000)});
  expect((await internalAdapter.consumeVerificationValue('secure:handoff'))?.value).toBe('newer');
  expect(await internalAdapter.findVerificationValue('secure:handoff')).toBeNull();
 });

 it('preserves supplied creation metadata and persists before-create hook changes', async () => {
  const {auth} = await getTestInstance({databaseHooks: {verification: {create: {before: async data => ({data: {...data, value: 'changed'}})}}}}, {disableTestUser: true});
  const {internalAdapter} = await auth.$context;
  const createdAt = new Date(2000000000000);
  const value = await internalAdapter.createVerificationValue({identifier: 'patched', value: 'original', expiresAt: new Date(Date.now() + 60000), createdAt});
  expect(value.createdAt).toEqual(createdAt);
  expect((await internalAdapter.consumeVerificationValue('patched'))?.value).toBe('changed');
 });
});
