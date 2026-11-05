import {createHash} from 'node:crypto';
import {describe, expect, it, vi} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';

describe('trusted verification contracts', () => {
 it('uses ordered custom hash policies for create, update, consume and deletion', async () => {
  const first = vi.fn(async (identifier: string) => 'first:' + identifier);
  const second = vi.fn(async (identifier: string) => 'second:' + identifier);
  const {auth} = await getTestInstance({verification: {storeIdentifier: {
   default: 'hashed', overrides: {'handoff:': {hash: first}, 'handoff:specific:': {hash: second}},
  }}}, {disableTestUser: true});
  const adapter = (await auth.$context).internalAdapter;
  const identifier = 'handoff:specific:token';
  const value = await adapter.createVerificationValue({identifier, value: 'original', expiresAt: new Date(Date.now() + 60000)});
  expect(value.identifier).toBe('first:' + identifier);
  await adapter.updateVerificationByIdentifier(identifier, {value: 'changed'});
  expect((await adapter.consumeVerificationValue(identifier)).value).toBe('changed');
  expect(await adapter.findVerificationValue(identifier)).toBeNull();
  await adapter.createVerificationValue({identifier, value: 'delete', expiresAt: new Date(Date.now() + 60000)});
  await adapter.deleteVerificationByIdentifier(identifier);
  expect(await adapter.findVerificationValue(identifier)).toBeNull();
  expect(second).not.toHaveBeenCalled();
  expect(first).toHaveBeenCalled();
 });

 it('uses deterministic reservation keys and bypasses replaceable create hooks', async () => {
  const createHook = vi.fn(async () => ({data: {id: 'unsafe-replacement'}}));
  const {auth} = await getTestInstance({databaseHooks: {verification: {create: {before: createHook}}}}, {disableTestUser: true});
  const adapter = (await auth.$context).internalAdapter;
  const input = {identifier: 'reserve:durable', value: 'guard', expiresAt: new Date(Date.now() + 60000)};
  expect(await adapter.reserveVerificationValue(input)).toBe(true);
  const found = await adapter.findVerificationValue(input.identifier);
  expect(found.id).toBe(createHash('sha256').update('reserve:' + input.identifier).digest('base64url'));
  expect(await adapter.reserveVerificationValue(input)).toBe(false);
  expect(createHook).not.toHaveBeenCalled();
  await adapter.deleteVerificationByIdentifier(input.identifier);
  expect(await adapter.reserveVerificationValue(input)).toBe(true);
 });
});
