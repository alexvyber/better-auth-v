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
const cases=[
 {name:'token exception',phase:'token',failure:'plain',status:302,redirect:'invalid_code'},
 {name:'token API error',phase:'token',failure:'coded',status:302,redirect:'invalid_code'},
 {name:'policy return',phase:'policy',failure:'decision',status:302,redirect:'ApplicationDenied'},
 {name:'policy coded API error',phase:'policy',failure:'coded',status:302,redirect:'ApplicationDenied'},
 {name:'account coded API error',phase:'account',failure:'coded',status:302,redirect:'ApplicationDenied'},
 {name:'policy exception',phase:'policy',failure:'plain',status:302,redirect:'unable_to_create_user'},
 {name:'account exception',phase:'account',failure:'plain',status:302,redirect:'unable_to_create_user'},
 {name:'session exception',phase:'session',failure:'plain',status:500},
 {name:'policy API error without code',phase:'policy',failure:'no-code',status:403},
 {name:'session API error without code',phase:'session',failure:'no-code',status:403},
 {name:'profile API error without code',phase:'profile',failure:'no-code',status:403},
 {name:'profile coded API error',phase:'profile',failure:'coded',status:403},
 {name:'profile exception',phase:'profile',failure:'plain',status:500},
 {name:'policy explicit server API error',phase:'policy',failure:'server-api',status:302,redirect:'ApplicationDenied'},
 {name:'profile explicit server API error',phase:'profile',failure:'server-api',status:500},
] as const;
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 for(const sample of cases){
  it(`matches ${sample.name} behavior and rolls back on ${backend}`,async()=>{
   const afterUser=vi.fn(async()=>{});const observed:any[]=[];
   const errorCode='ApplicationDenied';const description='Application declined <user> & "details"';
   const reject=(value:any)=>{
    observed.push(value);
    if(sample.failure==='plain')throw new Error('private application failure');
    if(sample.failure==='decision')return {error:errorCode,errorDescription:description};
    throw new APIError(sample.failure==='server-api'?'INTERNAL_SERVER_ERROR':'FORBIDDEN',{message:description,...(sample.failure==='no-code'?{}:{code:errorCode})});
   };
   const ready=await factory({
    plugins:[genericOAuth({config:[{providerId:'policy',discoveryUrl:issuer+'/.well-known/openid-configuration',clientId:'policy-client',clientSecret:'policy-secret',requireIdTokenVerification:true,tokenEndpointAuth:{method:'client_secret_basic'},pkce:true,scopes:['openid','email','profile'],...(sample.phase==='profile'?{mapProfileToUser:reject}:{}),...(sample.phase==='token'?{getToken:async(value:any)=>{reject(value);throw new Error('Unexpected token callback return')}}:{})}]})],
    trustedOrigins:['https://frontend.example.com'],
    user:sample.phase==='policy'?{validateUserInfo:reject}:{},
    databaseHooks:{user:{create:{after:afterUser}},...(sample.phase==='account'?{account:{create:{before:async(value:any)=>{reject(value)}}}}:{}),...(sample.phase==='session'?{session:{create:{before:async(value:any)=>{reject(value)}}}}:{})},
   },{disableTestUser:true});
   const {result,callback,headers}=await begin(ready);expect(result.status).toBe(sample.status);
   if('redirect' in sample){
    const location=new URL(result.headers.get('location')!);expect(location.origin+location.pathname).toBe('https://frontend.example.com/auth-error');expect(location.searchParams.get('keep')).toBe('1');expect(location.searchParams.get('error')).toBe(sample.redirect);
    expect(location.searchParams.get('error_description')).toBe(sample.failure==='plain'||sample.phase==='token'?null:description);
    expect(location.href).not.toContain('private');
   }else{
    expect(result.headers.get('location')).toBeNull();const body=await result.json();
    if(sample.failure==='plain'){expect(body).toEqual({code:'INTERNAL_SERVER_ERROR',message:'Internal server error'})}
    else{expect(body).toEqual({message:description,...(sample.failure==='no-code'?{}:{code:errorCode})})}
   }
   const adapter=(await ready.auth.$context).internalAdapter;expect(await adapter.findUserByEmail('new-policy@example.com')).toBeNull();expect(await ready.auth.api.getSession({headers})).toBeNull();expect(afterUser).not.toHaveBeenCalled();
   expect(result.headers.getSetCookie().some(cookie=>cookie.startsWith('better-auth.session_token='))).toBe(false);
   expect(result.headers.getSetCookie().some(cookie=>cookie.startsWith('better-auth.state=')&&cookie.includes('Max-Age=0'))).toBe(true);
   if(sample.phase==='policy')expect(observed).toMatchObject([{source:{action:'create-user',method:'oauth',oauth:{providerId:'policy',profile:{custom_field:'raw-profile-claim'}}}}]);
   expect((await ready.auth.handler(new Request(callback,{headers}))).status).toBe(400);
  });
 }
}
