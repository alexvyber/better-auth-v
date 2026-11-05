import {APIError} from '@better-auth/core/error';
import {OAuth2Server} from 'oauth2-mock-server';
import {afterAll,beforeAll,it,expect,vi} from 'vitest';
import {genericOAuth} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
const provider=new OAuth2Server();let issuer='';
beforeAll(async()=>{
 await provider.start();issuer=provider.issuer.url!;await provider.issuer.keys.generate('RS256');
 provider.service.on('beforeTokenSigning',token=>Object.assign(token.payload,{sub:'new-policy-user',email:'new-policy@example.com',email_verified:true,name:'Policy user',custom_field:'raw-profile-claim'}));
});
afterAll(async()=>{await provider.stop()});
async function begin(ready:Awaited<ReturnType<typeof getTestInstance>>){
 const response=await ready.auth.api.signInSocial({body:{provider:'policy',callbackURL:'http://localhost:3000/complete',errorCallbackURL:'https://frontend.example.com/auth-error?keep=1'},asResponse:true});
 const headers=new Headers();ready.cookieSetter(headers)({response});
 const authorization=await fetch((await response.json()).url,{redirect:'manual'});
 const callback=authorization.headers.get('location')!;
 const result=await ready.auth.handler(new Request(callback,{headers}));return {result,callback,headers};
}
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 for(const mode of ['return','throw','account-hook'] as const){
  it(`preserves application rejection details and rolls back ${mode} writes on ${backend}`,async()=>{
   const afterUser=vi.fn(async()=>{});const observed:any[]=[];
   const errorCode=mode==='account-hook'?'LinkCreationDenied':'MixedCasePolicy';const description='Application declined <user> & "details"';
   const reject=(value:any)=>{observed.push(value);if(mode==='throw')throw new APIError('FORBIDDEN',{code:errorCode,message:description});return {error:errorCode,errorDescription:description}};
   const ready=await factory({
    plugins:[genericOAuth({config:[{providerId:'policy',discoveryUrl:issuer+'/.well-known/openid-configuration',clientId:'policy-client',clientSecret:'policy-secret',requireIdTokenVerification:true,tokenEndpointAuth:{method:'client_secret_basic'},pkce:true,scopes:['openid','email','profile']}]})],
    trustedOrigins:['https://frontend.example.com'],
    user:mode==='account-hook'?{}:{validateUserInfo:reject},
    databaseHooks:{user:{create:{after:afterUser}},...(mode==='account-hook'?{account:{create:{before:async()=>{throw new APIError('FORBIDDEN',{code:errorCode,message:description})}}}}:{})},
   },{disableTestUser:true});
   const {result,callback,headers}=await begin(ready);expect(result.status).toBe(302);
   const location=new URL(result.headers.get('location')!);expect(location.origin+location.pathname).toBe('https://frontend.example.com/auth-error');expect(location.searchParams.get('keep')).toBe('1');expect(location.searchParams.get('error')).toBe(errorCode);expect(location.searchParams.get('error_description')).toBe(description);
   const adapter=(await ready.auth.$context).internalAdapter;expect(await adapter.findUserByEmail('new-policy@example.com')).toBeNull();expect(await ready.auth.api.getSession({headers})).toBeNull();expect(afterUser).not.toHaveBeenCalled();
   expect(result.headers.getSetCookie().some(cookie=>cookie.startsWith('better-auth.session_token='))).toBe(false);
   if(mode!=='account-hook')expect(observed).toMatchObject([{source:{action:'create-user',method:'oauth',oauth:{providerId:'policy',profile:{custom_field:'raw-profile-claim'}}}}]);
   expect((await ready.auth.handler(new Request(callback,{headers}))).status).toBe(400);
  });
 }
}
