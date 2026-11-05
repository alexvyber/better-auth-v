import {describe,it,expect} from 'vitest';
import {openAPI} from 'better-auth/plugins';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
// Upstream's SDK types can still require function-defaulted fields. Exercise
// omitted/default/null inputs through JSON HTTP, without changing those types.
async function signUp(ready:{auth:{handler(request:Request):Promise<Response>}},body:Record<string,unknown>){
 const response=await ready.auth.handler(new Request('http://localhost:3000/api/auth/sign-up/email',{method:'POST',headers:{'content-type':'application/json',origin:'http://localhost:3000'},body:JSON.stringify(body)}));
 const value=await response.json();if(!response.ok)throw new Error(value.message);return value;
}
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Functional field defaults on '+backend,()=>{
  it('evaluates new defaults at creation and preserves them through reads, updates and trusted creates',async()=>{
   let userSequence=0;let sessionSequence=0;
   const ready=await factory({plugins:[openAPI()],user:{additionalFields:{code:{type:'string',required:true,defaultValue:()=>`user-${++userSequence}`},dateField:{type:'date',defaultValue:()=>new Date('2030-01-01T00:00:00Z')},payload:{type:'json',defaultValue:()=>({dateField:'2030-01-01T00:00:00Z',createdAt:'2030-01-01T00:00:00Z'})}}},session:{additionalFields:{nonce:{type:'string',input:false,defaultValue:()=>`session-${++sessionSequence}`}}}},{disableTestUser:true});
   const schema=await ready.auth.api.generateOpenAPISchema();expect(userSequence).toBe(0);expect(sessionSequence).toBe(0);expect(schema.components.schemas.User.properties.code.default).toBeUndefined();expect(schema.paths['/sign-up/email'].post.requestBody.content['application/json'].schema.required).not.toContain('code');
   const explicit=await signUp(ready,{name:'Explicit',email:'explicit@example.com',password:'password',code:'provided'});expect(explicit.user.code).toBe('provided');expect(userSequence).toBe(0);expect(sessionSequence).toBe(1);
   const headers=new Headers({authorization:`Bearer ${explicit.token}`});const current=await ready.auth.api.getSession({headers});expect(current?.session.nonce).toBe('session-1');expect(current?.user.dateField).toBeInstanceOf(Date);expect(current?.user.payload).toEqual({dateField:'2030-01-01T00:00:00Z',createdAt:'2030-01-01T00:00:00Z'});
   await ready.auth.api.updateUser({headers,body:{name:'Updated'}});await ready.auth.api.getSession({headers});expect(userSequence).toBe(0);expect(sessionSequence).toBe(1);
   const generated=await signUp(ready,{name:'Generated',email:'generated@example.com',password:'password'});expect(generated.user.code).toBe('user-1');expect(userSequence).toBe(1);
   const context=await ready.auth.$context;const internal=await context.internalAdapter.createUser({name:'Internal',email:'internal@example.com'});expect(internal.code).toBe('user-2');expect(userSequence).toBe(2);
   const trusted=await context.internalAdapter.createUser({name:'Trusted',email:'trusted@example.com',code:'trusted'});expect(trusted.code).toBe('trusted');expect(userSequence).toBe(2);
   const created=await (context.internalAdapter.createSession as any)(internal.id,false,{nonce:'ignored'},false);expect(created.nonce).toBe(`session-${sessionSequence}`);expect(created.nonce).not.toBe('ignored');
   const overridden=await (context.internalAdapter.createSession as any)(internal.id,false,{nonce:'trusted'},true);expect(overridden.nonce).toBe('trusted');
  });
  it('keeps optional explicit nulls and creates a fresh default for each missing value',async()=>{
   let sequence=0;const ready=await factory({user:{additionalFields:{value:{type:'string',defaultValue:()=>`value-${++sequence}`}}}},{disableTestUser:true});
   const first=await signUp(ready,{name:'Null',email:'null@example.com',password:'password',value:null});expect(first.user.value).toBeNull();expect(sequence).toBe(0);
   const second=await signUp(ready,{name:'Second',email:'second@example.com',password:'password'});const third=await signUp(ready,{name:'Third',email:'third@example.com',password:'password'});expect(second.user.value).toBe('value-1');expect(third.user.value).toBe('value-2');expect(sequence).toBe(2);
  });
  it('rolls back a failed factory and allows a clean retry',async()=>{
   let fail=true;const ready=await factory({session:{additionalFields:{code:{type:'string',defaultValue:()=>{if(fail)throw new Error('private generator failure');return 'ready'}}}}},{disableTestUser:true});
   const body={name:'Retry',email:'retry@example.com',password:'password'};
   await expect(ready.auth.api.signUpEmail({body})).rejects.toThrow('Internal server error');
   const context=await ready.auth.$context;expect(await context.internalAdapter.findUserByEmail(body.email)).toBeNull();
   fail=false;const created=await ready.auth.api.signUpEmail({body});const session=await ready.auth.api.getSession({headers:{authorization:`Bearer ${created.token}`}});expect(session?.session.code).toBe('ready');
  });
 });
}
