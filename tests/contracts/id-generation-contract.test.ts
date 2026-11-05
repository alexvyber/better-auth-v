import {createHash, randomUUID} from 'node:crypto';
import {describe, expect, it, vi} from 'vitest';
import {jwt, oneTimeToken} from '../harness/plugins.js';
import {getTestInstance} from '../harness/test-instance.js';
const uuid = /^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/;

describe('Brand Map persisted identity generation', () => {
 it('uses UUIDs for users, sessions, accounts, trusted verification and signing keys', async () => {
  const {auth, signInWithTestUser} = await getTestInstance({advanced: {database: {generateId: 'uuid'}}, plugins: [jwt(), oneTimeToken()]});
  const {headers} = await signInWithTestUser();
  const context = await auth.$context;
  const current = await auth.api.getSession({headers});
  expect(current!.user.id).toMatch(uuid); expect(current!.session.id).toMatch(uuid);
  const accounts = await context.internalAdapter.findAccounts(current!.user.id);
  expect(accounts[0].id).toMatch(uuid);
  const verification = await context.internalAdapter.createVerificationValue({identifier: 'handoff', value: current!.user.id, expiresAt: new Date(Date.now() + 60000)});
  expect(verification.id).toMatch(uuid);
  const keys = await (await auth.api.getJwks({})).keys;
  expect(keys[0].kid).toMatch(uuid);
 });

 it('passes model names to a custom generator and retains generated IDs through hooks', async () => {
  const generator = vi.fn(({model}) => model + ':' + randomUUID());
  const {auth, signInWithTestUser} = await getTestInstance({advanced: {database: {generateId: generator}}});
  const {headers} = await signInWithTestUser();
  const current = await auth.api.getSession({headers});
  expect(current!.user.id).toMatch(/^user:/); expect(current!.session.id).toMatch(/^session:/);
  expect(generator.mock.calls.map(([input]) => input.model)).toContain('account');
  const proof = await (await auth.$context).internalAdapter.createVerificationValue({identifier: 'custom', value: 'value', expiresAt: new Date(Date.now() + 60000)});
  expect(proof.id).toMatch(/^verification:/);
 });

 it('encodes the deterministic reservation digest as a stable version-five UUID', async () => {
  const {auth} = await getTestInstance({advanced: {database: {generateId: 'uuid'}}}, {disableTestUser: true});
  const adapter = (await auth.$context).internalAdapter;
  const input = {identifier: 'reserve:uuid', value: 'guard', expiresAt: new Date(Date.now() + 60000)};
  expect(await adapter.reserveVerificationValue(input)).toBe(true);
  const digest = createHash('sha256').update('reserve:' + input.identifier).digest().subarray(0, 16);
  digest[6] = (digest[6]! & 15) | 0x50; digest[8] = (digest[8]! & 63) | 0x80;
  const hex = digest.toString('hex');
  expect((await adapter.findVerificationValue(input.identifier)).id).toBe(`${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`);
  expect(await adapter.reserveVerificationValue(input)).toBe(false);
 });
});
