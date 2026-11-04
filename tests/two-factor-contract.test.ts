import {describe, expect, it} from 'vitest';
import {createOTP} from '@better-auth/utils/otp';
import {symmetricDecrypt} from 'better-auth/crypto';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as pgInstance, postgresOptions, postgresSQL} from './harness/postgres-fixture.js';
import {twoFactor, oneTimeToken, jwt} from './harness/plugins.js';
import {convertSetCookieToCookie} from './harness/two-factor.js';
import {DEFAULT_SECRET} from './harness/constants.js';

describe('Brand Map two-factor integration contracts', () => {
 it('issues JWT and OTT headers only after the second factor succeeds', async () => {
  const {auth, signInWithTestUser, testUser, db} = await getTestInstance({secret: DEFAULT_SECRET, plugins: [twoFactor(), jwt(), oneTimeToken({setOttHeaderOnNewSession: true})]});
  const {headers, user} = await signInWithTestUser();
  await auth.api.enableTwoFactor({headers, body:{password:testUser.password}});
  const row = await db.findOne<any>({model:'twoFactor',where:[{field:'userId',value:user.id}]});
  const secret = await symmetricDecrypt({key:DEFAULT_SECRET,data:row.secret});
  const code = await createOTP(secret).totp();
  await auth.api.verifyTOTP({headers,body:{code}});
  const pending = await auth.api.signInEmail({body:{email:testUser.email,password:testUser.password},asResponse:true});
  expect(pending.headers.has('set-auth-jwt')).toBe(false);
  expect(pending.headers.has('set-ott')).toBe(false);
  expect(await auth.api.getSession({headers:convertSetCookieToCookie(pending.headers)})).toBeNull();
  const complete = await auth.api.verifyTOTP({headers:convertSetCookieToCookie(pending.headers),body:{code},asResponse:true});
  expect(complete.status).toBe(200);
  const verified = await auth.api.getSession({headers:convertSetCookieToCookie(complete.headers),asResponse:true});
  expect(verified.headers.get('set-auth-jwt')?.split('.')).toHaveLength(3);
  const token = complete.headers.get('set-ott');
  expect(token).toHaveLength(32);
  expect((await auth.api.verifyOneTimeToken({body:{token}})).user.id).toBe(user.id);
 });

 it('supports supplied fixed-code storage and enforces the five-attempt budget', async () => {
  let delivered = '';
  const {auth, signInWithTestUser, testUser} = await getTestInstance({plugins:[twoFactor({otpOptions:{allowedAttempts:5,storeOTP:{encrypt:async ()=>'fixed-proof',decrypt:async ()=>'123456'},sendOTP:({otp})=>{delivered=otp;}}})]});
  const {headers} = await signInWithTestUser();
  await auth.api.enableTwoFactor({headers,body:{password:testUser.password,method:'otp'}});
  const start = async () => convertSetCookieToCookie((await auth.api.signInEmail({body:{email:testUser.email,password:testUser.password},asResponse:true})).headers);
  const challenge = await start();
  await auth.api.sendTwoFactorOTP({headers:challenge});
  expect(delivered).toMatch(/^\d{6}$/);
  for (let attempt=0;attempt<5;attempt++) expect((await auth.api.verifyTwoFactorOTP({headers:challenge,body:{code:'invalid'},asResponse:true})).status).toBe(401);
  expect((await auth.api.verifyTwoFactorOTP({headers:challenge,body:{code:'123456'},asResponse:true})).status).toBe(400);
  const fresh = await start();
  await auth.api.sendTwoFactorOTP({headers:fresh});
  expect((await auth.api.verifyTwoFactorOTP({headers:fresh,body:{code:'123456'},asResponse:true})).status).toBe(200);
 });

 it('stores encrypted mapped UUID factors and redeems a shared PostgreSQL challenge once', async () => {
  const configuration = await postgresOptions();
  const options = {secret:DEFAULT_SECRET,verification:{storeIdentifier:'hashed' as const},plugins:[twoFactor({skipVerificationOnEnable:true})]};
  const first = await pgInstance(options,{nativePostgres:configuration});
  const {headers,user} = await first.signInWithTestUser();
  await first.auth.api.enableTwoFactor({headers,body:{password:first.testUser.password}});
  const second = await pgInstance(options,{nativePostgres:configuration,disableTestUser:true});
  const rows = JSON.parse(await postgresSQL(configuration,`SELECT row_to_json(f) FROM "${configuration.schema}".auth_two_factor f LIMIT 1`));
  expect(rows.id).toMatch(/^[\da-f]{8}-[\da-f]{4}-4/);
  expect(rows.user_id).toBe(user.id);
  expect(rows.verified).toBe(true);
  expect(rows.backup_codes.startsWith('[')).toBe(false);
  const secret = await symmetricDecrypt({key:DEFAULT_SECRET,data:rows.secret});
  const before = Number(await postgresSQL(configuration,`SELECT count(*) FROM "${configuration.schema}".auth_session`));
  const pending = await first.auth.api.signInEmail({body:{email:first.testUser.email,password:first.testUser.password},asResponse:true});
  const challenge = convertSetCookieToCookie(pending.headers);
  const code = await createOTP(secret).totp();
  const results = await Promise.all([first,second].map(instance=>instance.auth.api.verifyTOTP({headers:challenge,body:{code},asResponse:true})));
  expect(results.map(result=>result.status).sort()).toEqual([200,401]);
  expect(await postgresSQL(configuration,`SELECT count(*) FROM "${configuration.schema}".auth_session`)).toBe(String(before+1));
 });
});

describe('two-factor plugin HTTP limits', () => {
 it('applies the upstream three-per-ten-second override while trusted calls bypass it', async () => {
  const {auth} = await getTestInstance({plugins:[twoFactor()],rateLimit:{enabled:true,max:100,window:60}},{disableTestUser:true});
  const request = () => new Request('http://localhost:3000/api/auth/two-factor/verify-totp',{method:'POST',headers:{origin:'http://localhost:3000','content-type':'application/json'},body:JSON.stringify({code:'invalid'})});
  for (let index=0;index<3;index++) expect((await auth.handler(request())).status).toBe(401);
  expect((await auth.handler(request())).status).toBe(429);
  expect((await auth.api.verifyTOTP({body:{code:'invalid'},asResponse:true})).status).toBe(401);
 });
});
