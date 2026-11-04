import {createHash} from 'node:crypto';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {emailOTP} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
afterEach(()=>vi.useRealTimers());

describe('Brand Map email OTP contracts', () => {
 it('stores hashed rotated codes and enforces five attempts without replay', async () => {
  vi.useFakeTimers();vi.setSystemTime(Date.UTC(2035,0,1,0,0,0,123));
  let generated = 100000;
  let delivered = '';
  const {auth, testUser} = await getTestInstance({plugins: [emailOTP({
   storeOTP: 'hashed', resendStrategy: 'rotate', allowedAttempts: 5,
   generateOTP: () => String(++generated),
   sendVerificationOTP: async ({otp}) => { delivered = otp; },
   changeEmail: {enabled: true}, sendVerificationOnSignUp: false,
  })]});
  const send = () => auth.api.sendVerificationOTP({body: {email: testUser.email, type: 'sign-in'}});
  await send(); const old = delivered;
  await send(); const current = delivered;
  expect(current).not.toBe(old);
  const adapter = (await auth.$context).internalAdapter;
  const stored = await adapter.findVerificationValue(`sign-in-otp-${testUser.email}`);
  expect(stored.value).toBe(createHash('sha256').update(current).digest('base64url') + ':0');
  const signIn = (otp: string) => auth.api.signInEmailOTP({body: {email: testUser.email, otp}});
  for (let attempt = 0; attempt < 5; attempt++) await expect(signIn(old)).rejects.toMatchObject({body: {code: 'INVALID_OTP'}});
  await expect(signIn(current)).rejects.toMatchObject({body: {code: 'TOO_MANY_ATTEMPTS'}});
  await expect(signIn(current)).rejects.toMatchObject({body: {code: 'INVALID_OTP'}});
  await send();
  expect((await signIn(delivered)).user.emailVerified).toBe(true);
  await expect(signIn(delivered)).rejects.toMatchObject({body: {code: 'INVALID_OTP'}});
 });

 it('routes the core verification API to OTP delivery', async () => {
  let delivered = '';
  const {auth, testUser} = await getTestInstance({plugins: [emailOTP({
   overrideDefaultEmailVerification: true,
   sendVerificationOTP: async ({otp}) => { delivered = otp; },
  })]});
  expect(await auth.api.sendVerificationEmail({body: {email: testUser.email}})).toEqual({status: true});
  expect(delivered).toMatch(/^\d{6}$/);
  expect((await auth.api.verifyEmailOTP({body: {email: testUser.email, otp: delivered}})).user.emailVerified).toBe(true);
 });

 it('requires both hashed email proofs when changing the current verified email', async () => {
  const codes = new Map<string, string>();
  const {auth, testUser, signInWithTestUser} = await getTestInstance({plugins: [emailOTP({
   storeOTP: 'hashed', allowedAttempts: 5,
   changeEmail: {enabled: true, verifyCurrentEmail: true},
   sendVerificationOTP: async ({email, otp}) => { codes.set(email, otp); },
  })]});
  const {headers} = await signInWithTestUser();
  await auth.api.sendVerificationOTP({body: {email: testUser.email, type: 'email-verification'}});
  await auth.api.verifyEmailOTP({body: {email: testUser.email, otp: codes.get(testUser.email)}});
  await auth.api.sendVerificationOTP({body: {email: testUser.email, type: 'email-verification'}});
  await auth.api.requestEmailChangeEmailOTP({headers, body: {newEmail: 'changed@example.com', otp: codes.get(testUser.email)}});
  await expect(auth.api.changeEmailEmailOTP({headers, body: {newEmail: 'changed@example.com', otp: 'wrong'}})).rejects.toMatchObject({body: {code: 'INVALID_OTP'}});
  const changed = await auth.api.changeEmailEmailOTP({headers, body: {newEmail: 'changed@example.com', otp: codes.get('changed@example.com')}});
  expect(changed).toEqual({success: true});
  expect((await auth.api.getSession({headers}))?.user.email).toBe('changed@example.com');
 });
});


describe('PostgreSQL same-millisecond OTP rotation',()=>{
 it('replaces the earlier hashed proof when resends have identical createdAt values',async()=>{
  vi.useFakeTimers();vi.setSystemTime(Date.UTC(2035,0,1,0,0,0,123));
  let generated = 200000;
  let delivered = '';
  const {auth,testUser} = await postgresInstance({plugins:[emailOTP({storeOTP:'hashed',resendStrategy:'rotate',generateOTP:()=>String(++generated),sendVerificationOTP:async({otp})=>{delivered=otp;}})]});
  await auth.api.sendVerificationOTP({body:{email:testUser.email,type:'sign-in'}});
  const previous = delivered;
  await auth.api.sendVerificationOTP({body:{email:testUser.email,type:'sign-in'}});
  const adapter = (await auth.$context).internalAdapter;
  expect((await adapter.findVerificationValue('sign-in-otp-'+testUser.email)).value).toBe(createHash('sha256').update(delivered).digest('base64url')+':0');
  await expect(auth.api.signInEmailOTP({body:{email:testUser.email,otp:previous}})).rejects.toMatchObject({body:{code:'INVALID_OTP'}});
  expect((await auth.api.signInEmailOTP({body:{email:testUser.email,otp:delivered}})).user.emailVerified).toBe(true);
 });
});
