import {describe, expect, it, vi} from 'vitest';
import {anonymous, emailOTP} from '../harness/plugins.js';
import {getTestInstance} from '../harness/test-instance.js';

describe('Brand Map anonymous account contracts', () => {
 it('lets the domain merge callback inspect the guest and update the destination before cleanup', async () => {
  let otp = '';
  const merge = vi.fn(async ({anonymousUser, newUser, ctx}) => {
   const guest = await ctx.context.internalAdapter.findUserById(anonymousUser.user.id);
   expect(guest.isAnonymous).toBe(true);
   expect(newUser.user.isAnonymous).toBe(false);
   await ctx.context.internalAdapter.updateUser(newUser.user.id, {mergedGuestId: guest.id});
  });
  const {auth, cookieSetter, testUser} = await getTestInstance({
   user: {additionalFields: {mergedGuestId: {type: 'string', input: false}}},
   plugins: [anonymous({onLinkAccount: merge}), emailOTP({storeOTP: 'hashed', sendVerificationOTP: async data => {otp = data.otp;}})],
  });
  const headers = new Headers();
  const guestResponse = await auth.api.signInAnonymous({asResponse: true});
  cookieSetter(headers)({response: guestResponse});
  const guest = await auth.api.getSession({headers});
  await auth.api.sendVerificationOTP({body: {email: testUser.email, type: 'sign-in'}});
  const signed = await auth.api.signInEmailOTP({headers, body: {email: testUser.email, otp}});
  expect(merge).toHaveBeenCalledTimes(1);
  const adapter = (await auth.$context).internalAdapter;
  expect((await adapter.findUserById(signed.user.id)).mergedGuestId).toBe(guest!.user.id);
  expect(await adapter.findUserById(guest!.user.id)).toBeNull();
  expect(await auth.api.getSession({headers})).toBeNull();
 });

 it('preserves the guest when cleanup is disabled and rejects explicit guest deletion', async () => {
  const merge = vi.fn();
  const {auth, cookieSetter, testUser} = await getTestInstance({plugins: [anonymous({disableDeleteAnonymousUser: true, onLinkAccount: merge})]});
  const headers = new Headers();
  cookieSetter(headers)({response: await auth.api.signInAnonymous({asResponse: true})});
  const guest = await auth.api.getSession({headers});
  await expect(auth.api.deleteAnonymousUser({headers})).rejects.toMatchObject({body: {code: 'DELETE_ANONYMOUS_USER_DISABLED'}});
  await auth.api.signInEmail({headers, body: testUser});
  expect(merge).toHaveBeenCalledTimes(1);
  expect((await (await auth.$context).internalAdapter.findUserById(guest!.user.id)).isAnonymous).toBe(true);
 });

 it('deletes only an authenticated anonymous user and revokes its bearer token', async () => {
  const {auth, cookieSetter, signInWithTestUser} = await getTestInstance({plugins: [anonymous()]});
  await expect(auth.api.deleteAnonymousUser({})).rejects.toMatchObject({statusCode: 401});
  const regular = await signInWithTestUser();
  await expect(auth.api.deleteAnonymousUser({headers: regular.headers})).rejects.toMatchObject({body: {code: 'USER_IS_NOT_ANONYMOUS'}});
  const headers = new Headers();
  const response = await auth.api.signInAnonymous({asResponse: true});
  const guest = await response.clone().json();
  cookieSetter(headers)({response});
  expect(await auth.api.deleteAnonymousUser({headers})).toEqual({success: true});
  expect(await auth.api.getSession({headers: {authorization: `Bearer ${guest.token}`}})).toBeNull();
 });
});
