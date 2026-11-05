import {createHash} from 'node:crypto';
import {APIError} from '@better-auth/core/error';
import {OAuth2Server} from 'oauth2-mock-server';
import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import {genericOAuth} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from './harness/mongo-fixture.js';

const provider = new OAuth2Server();
let issuer = '';
let email = 'provisioned@example.com';
let verified = true;
let tokenRequest: {authorization?: string; verifier?: string; secret?: string} = {};
beforeAll(async () => {
 await provider.start(); issuer = provider.issuer.url!;
 await provider.issuer.keys.generate('RS256');
 provider.service.on('beforeTokenSigning', token => {Object.assign(token.payload, {email, email_verified: verified, name: 'Nabu operator'});});
 provider.service.on('beforeResponse', (_response, request) => {
  if (request.url?.startsWith('/token')) tokenRequest = {authorization: request.headers.authorization, verifier: request.body.code_verifier, secret: request.body.client_secret};
 });
});
afterAll(async () => {await provider.stop();});

async function instance(overrides: Record<string, any> = {}, dependencies: {factory?:typeof getTestInstance;config?:Record<string,any>;provision?:(email:string)=>Promise<void>} = {}) {
 const configuration = genericOAuth({config: [{
  providerId: 'tinyauth', name: 'Code & Money', discoveryUrl: `${issuer}/.well-known/openid-configuration`,
  clientId: 'nabu-client', clientSecret: 'nabu-secret', requireIdTokenVerification: true,
  tokenEndpointAuth: {method: 'client_secret_basic'}, scopes: ['openid', 'profile', 'email'], pkce: true,
  disableImplicitSignUp: true, disableSignUp: true, disableProviderLogout: true,
  async mapProfileToUser(profile) {
   if (profile.email_verified !== true || typeof profile.email !== 'string' || !profile.email.trim()) throw new APIError('FORBIDDEN', {message: 'A verified SSO email is required'});
   const normalized = profile.email.trim().toLowerCase();
   if (normalized !== 'provisioned@example.com') throw new APIError('FORBIDDEN', {message: 'This SSO identity is not provisioned for Nabu'});
   await dependencies.provision?.(normalized);
   return {email: normalized, emailVerified: true};
  },
 }]});
 const ready = await (dependencies.factory ?? getTestInstance)({
  plugins: [configuration], account: {accountLinking: {enabled: true, trustedProviders: ['tinyauth'], allowDifferentEmails: false}},
  emailAndPassword: {enabled: false, disableSignUp: true, minPasswordLength: 12},
  ...overrides,
 }, {disableTestUser: true,...dependencies.config});
 const adapter = (await ready.auth.$context).internalAdapter;
 expect((await ready.auth.$context).socialProviders.find(provider=>provider.id==='tinyauth')?.name).toBe('Code & Money');
 const user = await adapter.createUser({email: 'provisioned@example.com', name: 'Provisioned', emailVerified: true}, {method: 'test'});
 return {...ready, user};
}
async function authorize(ready: Awaited<ReturnType<typeof instance>>, formPost=false, callbackFields:Record<string,string>={}) {
 const headers = new Headers();
 const response = await ready.auth.api.signInSocial({body: {provider: 'tinyauth', callbackURL: 'http://localhost:3000/nabu'}, asResponse: true});
 ready.cookieSetter(headers)({response});
 const {url} = await response.json();
 const authorization = new URL(url);
 const redirect = await fetch(url, {redirect: 'manual'});
 const callback = redirect.headers.get('location')!;
 const adjusted=new URL(callback);for(const [key,value] of Object.entries(callbackFields))adjusted.searchParams.set(key,value);
 let finalCallback=adjusted.href;
 if(formPost){
  const target=new URL(finalCallback);
  const post=await ready.auth.handler(new Request(target.origin+target.pathname,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:issuer,'sec-fetch-site':'cross-site'},body:target.searchParams}));
  expect(post.status).toBe(302);expect(post.headers.getSetCookie()).toEqual([]);
  finalCallback=post.headers.get('location')!;
  const adapter=(await ready.auth.$context).internalAdapter;
  expect(await adapter.findAccounts(ready.user.id)).toEqual([]);
  expect((await ready.auth.handler(new Request(finalCallback))).status).toBe(403);
 }
 const result = await ready.auth.handler(new Request(finalCallback, {headers}));
 return {authorization, callback, headers, result};
}

it('preserves missing, empty and configured provider display names',async()=>{
 const ready=await getTestInstance({plugins:[genericOAuth({config:[
  {providerId:'fallback-name',authorizationUrl:'https://provider.example/authorize',tokenUrl:'https://provider.example/token',clientId:'name-client',clientSecret:'name-secret'},
  {providerId:'empty-name',name:'',authorizationUrl:'https://provider.example/authorize',tokenUrl:'https://provider.example/token',clientId:'name-client',clientSecret:'name-secret'},
  {providerId:'configured-name',name:'Code & Money / Nabu',authorizationUrl:'https://provider.example/authorize',tokenUrl:'https://provider.example/token',clientId:'name-client',clientSecret:'name-secret'},
 ]})]},{disableTestUser:true});
 const names=Object.fromEntries((await ready.auth.$context).socialProviders.map(provider=>[provider.id,provider.name]));
 expect(names).toMatchObject({'fallback-name':'fallback-name','empty-name':'','configured-name':'Code & Money / Nabu'});
});

describe('Nabu provisioned OIDC configuration', () => {
 for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
  it(`retains the provisioned user after an unexpected account-link hook failure on ${backend}`,async()=>{
   email='provisioned@example.com';verified=true;
   const ready=await instance({databaseHooks:{account:{create:{before:async()=>{throw new Error('private link failure')}}}}},{factory});
   const {result,headers,callback}=await authorize(ready);expect(result.status).toBe(302);
   const location=new URL(result.headers.get('location')!);expect(location.searchParams.get('error')).toBe('unable_to_link_account');expect(location.searchParams.has('error_description')).toBe(false);expect(location.href).not.toContain('private');
   const adapter=(await ready.auth.$context).internalAdapter;expect(await adapter.findAccounts(ready.user.id)).toEqual([]);expect((await adapter.findUserById(ready.user.id)).emailVerified).toBe(true);expect(await ready.auth.api.getSession({headers})).toBeNull();
   expect(result.headers.getSetCookie().some(cookie=>cookie.startsWith('better-auth.state=')&&cookie.includes('Max-Age=0'))).toBe(true);
   expect((await ready.auth.handler(new Request(callback,{headers}))).status).toBe(400);
  });
  it(`uses verified default linking and respects an explicit opt-out on ${backend}`,async()=>{
   email='provisioned@example.com';verified=true;
   const allowed=await instance({account:undefined},{factory});
   expect((await authorize(allowed)).result.headers.get('location')).toBe('http://localhost:3000/nabu');
   const linked=await (await allowed.auth.$context).internalAdapter.findAccounts(allowed.user.id);
   expect(linked).toHaveLength(1);expect(linked[0].refreshTokenExpiresAt).toBeNull();
   const denied=await instance({account:{accountLinking:{enabled:false}}},{factory});
   expect((await authorize(denied)).result.headers.get('location')).toContain('error=account_not_linked');
   expect(await (await denied.auth.$context).internalAdapter.findAccounts(denied.user.id)).toEqual([]);
   expect((await (await denied.auth.$context).internalAdapter.findUserById(denied.user.id)).emailVerified).toBe(true);
  });
  it(`rejects an issuer mismatch before exchanging a code on ${backend}`,async()=>{
   email='provisioned@example.com';verified=true;
   const ready=await instance({},{factory});tokenRequest={};
   const failed=await authorize(ready,false,{iss:'https://different-issuer.example'});
   expect(failed.result.status).toBe(302);expect(new URL(failed.result.headers.get('location')!).searchParams.get('error')).toBe('issuer_mismatch');
   expect(tokenRequest).toEqual({});expect(await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).toEqual([]);
   expect(await ready.auth.api.getSession({headers:failed.headers})).toBeNull();
   expect((await ready.auth.handler(new Request(failed.callback,{headers:failed.headers}))).status).toBe(400);
   expect((await authorize(ready,false,{iss:issuer})).result.headers.get('location')).toBe('http://localhost:3000/nabu');
  });
  it(`rolls back linking and redirects the original session-hook error on ${backend}`,async()=>{
   email='provisioned@example.com';verified=true;
   const ready=await instance({trustedOrigins:['https://frontend.example.com'],databaseHooks:{session:{create:{before:async()=>{throw new APIError('FORBIDDEN',{code:'HOOK_REJECTED',message:'Session hook rejected this user'})}}}}},{factory});
   const headers=new Headers();const start=await ready.auth.api.signInSocial({body:{provider:'tinyauth',callbackURL:'https://frontend.example.com/nabu',errorCallbackURL:'https://frontend.example.com/auth-error?preserved=yes'},asResponse:true});ready.cookieSetter(headers)({response:start});
   const authorization=await fetch((await start.json()).url,{redirect:'manual'});const callback=authorization.headers.get('location')!;
   const response=await ready.auth.handler(new Request(callback,{headers}));expect(response.status).toBe(302);
   const location=new URL(response.headers.get('location')!);expect(location.origin+location.pathname).toBe('https://frontend.example.com/auth-error');expect(location.searchParams.get('preserved')).toBe('yes');expect(location.searchParams.get('error')).toBe('HOOK_REJECTED');expect(location.searchParams.get('error_description')).toBe('Session hook rejected this user');
   expect(await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).toEqual([]);expect(await ready.auth.api.getSession({headers})).toBeNull();
   expect((await ready.auth.handler(new Request(callback,{headers}))).status).toBe(400);
  });

  it(`completes a cookie-less OIDC form POST through a browser-bound GET on ${backend}`,async()=>{
   email='provisioned@example.com';verified=true;
   const ready=await instance({},{factory});
   const {authorization,result,headers,callback}=await authorize(ready,true);
   expect(result.status).toBe(302);expect(result.headers.get('location')).toBe('http://localhost:3000/nabu');
   expect(createHash('sha256').update(tokenRequest.verifier!).digest('base64url')).toBe(authorization.searchParams.get('code_challenge'));
   expect(tokenRequest.authorization).toBe('Basic '+Buffer.from('nabu-client:nabu-secret').toString('base64'));
   const replay=new Headers(headers);ready.cookieSetter(headers)({response:result});
   expect((await ready.auth.api.getSession({headers}))?.user.id).toBe(ready.user.id);
   expect((await ready.auth.handler(new Request(callback,{headers:replay}))).status).toBe(400);
  });
 }

 it('executes Nabu provisioning and signed OIDC login against real MongoDB storage', async()=>{
  email='Provisioned@Example.com';verified=true;
  const configuration=await mongoOptions();
  const ready=await instance({session:{expiresIn:30*86400,updateAge:86400},rateLimit:{enabled:true,storage:'database'}},{factory:mongoInstance,config:{nativeMongo:configuration},provision:async normalized=>{
   const result=await mongoCommand(configuration,{update:'user',updates:[{q:{email:normalized},u:{$set:{emailVerified:true},$currentDate:{updatedAt:true}}}]});
   expect(result.n).toBe(1);
  }});
  const adapter=(await ready.auth.$context).internalAdapter;
  await adapter.updateUser(ready.user.id,{emailVerified:false});
  const {authorization,result,headers,callback}=await authorize(ready);
  expect(result.headers.get('location')).toBe('http://localhost:3000/nabu');
  expect(createHash('sha256').update(tokenRequest.verifier!).digest('base64url')).toBe(authorization.searchParams.get('code_challenge'));
  expect(tokenRequest.authorization).toBe('Basic '+Buffer.from('nabu-client:nabu-secret').toString('base64'));
  const replay=new Headers(headers);ready.cookieSetter(headers)({response:result});
  const current=await ready.auth.api.getSession({headers});
  expect(current?.user).toMatchObject({id:ready.user.id,emailVerified:true});
  expect(new Date(current!.session.expiresAt).getTime()-new Date(current!.session.createdAt).getTime()).toBe(30*86400*1000);
  const accounts=await mongoCommand(configuration,{find:'account',filter:{providerId:'tinyauth'}});
  expect(accounts.cursor.firstBatch[0].userId.$oid).toBe(ready.user.id);
  expect((await adapter.findAccounts(ready.user.id)).map((a:any)=>a.providerId)).toEqual(['tinyauth']);
  expect((await ready.auth.handler(new Request(callback,{headers:replay}))).status).toBe(400);
 });
 it('rejects an unprovisioned signed SSO identity on MongoDB without creating a binding',async()=>{
  email='outsider@example.com';verified=true;
  const ready=await instance({},{factory:mongoInstance});
  const {result,headers}=await authorize(ready);
  expect(result.status).toBe(403);expect(result.headers.get('location')).toBeNull();expect(await result.json()).toEqual({message:'This SSO identity is not provisioned for Nabu'});
  expect(await ready.auth.api.getSession({headers})).toBeNull();
  expect(await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).toEqual([]);
 });

 it('allows the Nabu provisioning callback to verify the local row before implicit linking', async () => {
  email = 'provisioned@example.com'; verified = true;
  const configuration = await postgresOptions();
  const ready = await instance({}, {factory:postgresInstance,config:{nativePostgres:configuration},provision:async()=>{
   const changed = await postgresSQL(configuration,`UPDATE "${configuration.schema}".auth_user SET email_verified=true WHERE email='provisioned@example.com' RETURNING id`);
   expect(changed).toBeTruthy();
  }});
  const adapter = (await ready.auth.$context).internalAdapter;
  await adapter.updateUser(ready.user.id,{emailVerified:false});
  const {result,headers} = await authorize(ready);
  expect(result.headers.get('location')).toBe('http://localhost:3000/nabu');
  ready.cookieSetter(headers)({response:result});
  expect((await ready.auth.api.getSession({headers}))?.user.emailVerified).toBe(true);
  expect(await adapter.findAccounts(ready.user.id)).toHaveLength(1);
 });

 it('rejects an authorized signed identity when the local account is still unverified', async () => {
  email = 'provisioned@example.com'; verified = true;
  const ready = await instance();
  const adapter = (await ready.auth.$context).internalAdapter;
  await adapter.updateUser(ready.user.id,{emailVerified:false});
  const {result,headers} = await authorize(ready);
  expect(result.headers.get('location')).toContain('error=account_not_linked');
  expect(await adapter.findAccounts(ready.user.id)).toEqual([]);
  expect(await ready.auth.api.getSession({headers})).toBeNull();
 });
 it('honors the explicit legacy local-verification opt-out for a preprovisioned account', async () => {
  email = 'provisioned@example.com'; verified = true;
  const ready = await instance({account:{accountLinking:{enabled:true,trustedProviders:['tinyauth'],requireLocalEmailVerified:false}}});
  const adapter = (await ready.auth.$context).internalAdapter;
  await adapter.updateUser(ready.user.id,{emailVerified:false});
  const {result} = await authorize(ready);
  expect(result.headers.get('location')).toBe('http://localhost:3000/nabu');
  expect((await adapter.findUserById(ready.user.id)).emailVerified).toBe(true);
  expect(await adapter.findAccounts(ready.user.id)).toHaveLength(1);
 });
 it('honors the implicit-linking switch even for an authorized trusted identity', async () => {
  email = 'provisioned@example.com'; verified = true;
  const ready = await instance({account:{accountLinking:{enabled:true,trustedProviders:['tinyauth'],disableImplicitLinking:true}}});
  expect((await authorize(ready)).result.headers.get('location')).toContain('error=account_not_linked');
  expect(await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).toEqual([]);
 });

 it('verifies signed identity, uses Basic and PKCE, and links only the provisioned user', async () => {
  email = 'Provisioned@Example.com'; verified = true;
  const ready = await instance();
  const {authorization, result, callback, headers} = await authorize(ready);
  expect(result.status).toBe(302); expect(result.headers.get('location')).toBe('http://localhost:3000/nabu');
  expect(tokenRequest.authorization).toBe('Basic ' + Buffer.from('nabu-client:nabu-secret').toString('base64'));
  expect(tokenRequest.secret).toBeUndefined();
  expect(createHash('sha256').update(tokenRequest.verifier!).digest('base64url')).toBe(authorization.searchParams.get('code_challenge'));
  expect(authorization.searchParams.get('nonce')).toBeTruthy();
  const replayHeaders = new Headers(headers);
  ready.cookieSetter(headers)({response: result});
  expect((await ready.auth.api.getSession({headers}))?.user.id).toBe(ready.user.id);
  expect((await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).map((account: any) => account.providerId)).toEqual(['tinyauth']);
  expect((await ready.auth.handler(new Request(callback, {headers: replayHeaders}))).status).toBe(400);
 });

 it('rejects a signed but unprovisioned identity without registering it', async () => {
  email = 'outsider@example.com'; verified = true;
  const ready = await instance();
  const {result} = await authorize(ready);
  expect(result.status).toBe(403);expect(result.headers.get('location')).toBeNull();expect(await result.json()).toEqual({message:'This SSO identity is not provisioned for Nabu'});
  const adapter = (await ready.auth.$context).internalAdapter;
  expect(await adapter.findUserByEmail(email)).toBeNull();
  expect(await adapter.findAccounts(ready.user.id)).toEqual([]);
  expect(result.headers.getSetCookie().some(value => value.startsWith('better-auth.session_token='))).toBe(false);
 });

 it('rejects a signed profile whose email is unverified', async () => {
  email = 'provisioned@example.com'; verified = false;
  const ready = await instance();
  const rejected=(await authorize(ready)).result;expect(rejected.status).toBe(403);expect(rejected.headers.get('location')).toBeNull();expect(await rejected.json()).toEqual({message:'A verified SSO email is required'});
  expect(await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).toEqual([]);
 });

 it('disables public password registration while retaining provisioned password login', async () => {
  const {auth} = await getTestInstance({emailAndPassword: {enabled: true, disableSignUp: true, minPasswordLength: 12}}, {disableTestUser: true});
  await expect(auth.api.signUpEmail({body: {email: 'outsider@example.com', name: 'Outsider', password: 'long-password'}})).rejects.toMatchObject({body: {code: 'EMAIL_PASSWORD_SIGN_UP_DISABLED'}});
  const context = await auth.$context;
  const user = await context.internalAdapter.createUser({email: 'operator@example.com', name: 'Operator', emailVerified: true}, {method: 'test'});
  await context.internalAdapter.createAccount({userId: user.id, providerId: 'credential', accountId: user.id, password: await context.password.hash('long-password')});
  expect((await auth.api.signInEmail({body: {email: user.email, password: 'long-password'}})).user.id).toBe(user.id);
 });
 it('stores UUID OAuth state under hashed secondary keys and consumes it before the exchange', async () => {
  email = 'provisioned@example.com'; verified = true;
  const values = new Map<string, string>();
  const storage = {
   set(key: string, value: string) {values.set(key, value);},
   get(key: string) {return values.get(key) ?? null;},
   getAndDelete(key: string) {const value = values.get(key) ?? null; values.delete(key); return value;},
   delete(key: string) {values.delete(key);},
   increment(key: string) {const next = Number(values.get(key) ?? 0) + 1; values.set(key, String(next)); return next;},
  };
  const ready = await instance({secondaryStorage: storage, verification: {storeIdentifier: 'hashed'}, advanced: {database: {generateId: 'uuid'}}});
  const headers = new Headers();
  const start = await ready.auth.api.signInSocial({body: {provider: 'tinyauth', callbackURL: 'http://localhost:3000/nabu'}, asResponse: true});
  ready.cookieSetter(headers)({response: start});
  const {url} = await start.json();
  const state = new URL(url).searchParams.get('state')!;
  const identifier = 'oauth-state:' + state;
  const key = 'verification:' + createHash('sha256').update(identifier).digest('base64url');
  const proof = JSON.parse(values.get(key)!);
  expect(proof.id).toMatch(/^[\da-f]{8}-[\da-f]{4}-4/);
  expect(values.has('verification:' + identifier)).toBe(false);
  const redirect = await fetch(url, {redirect: 'manual'});
  const response = await ready.auth.handler(new Request(redirect.headers.get('location')!, {headers}));
  expect(response.headers.get('location')).toBe('http://localhost:3000/nabu');
  expect(values.has(key)).toBe(false);
 });

});
