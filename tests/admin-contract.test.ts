import {describe,it,expect} from 'vitest';
import type {UserWithRole} from 'better-auth/plugins/admin';
import {adminAc,userAc} from 'better-auth/plugins/admin/access';
import {admin} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
const options={plugins:[admin({adminRoles:['platform-admin'],defaultRole:'user',roles:{'platform-admin':adminAc,curator:userAc,user:userAc}})],databaseHooks:{user:{create:{before:async(user:any)=>({data:{...user,...(user.email==='test@test.com'?{role:'platform-admin'}:{})}})}}}};
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Brand Map admin contracts on '+backend,()=>{
  it('uses the configured platform-admin and curator permissions, and rejects empty actions',async()=>{
   const ready=await factory(options);const {headers}=await ready.signInWithTestUser();
   const created=await ready.auth.api.createUser({headers,body:{name:'Curator',email:'curator@example.com',password:'password',role:'curator'}});
   const curator=await ready.signInWithUser(created.user.email,'password');
   expect((await ready.auth.api.listUsers({headers})).total).toBe(2);
   await expect(ready.auth.api.listUsers({headers:curator.headers})).rejects.toMatchObject({body:{code:'YOU_ARE_NOT_ALLOWED_TO_LIST_USERS'}});
   expect(await ready.auth.api.userHasPermission({body:{role:'platform-admin',permissions:{user:['list']}}})).toMatchObject({success:true});
   expect(await ready.auth.api.userHasPermission({body:{role:'platform-admin',permissions:{user:[]}}})).toMatchObject({success:false});
   await expect(ready.auth.api.setRole({headers,body:{userId:created.user.id,role:'missing'}})).rejects.toMatchObject({body:{code:'YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE'}});
  });
  it('checks current permissions and revocation even with a stale admin cookie snapshot',async()=>{
   const ready=await factory({...options,session:{cookieCache:{enabled:true,maxAge:300}}});const {headers:root}=await ready.signInWithTestUser();
   const attacker=await ready.auth.api.createUser({headers:root,body:{name:'Admin',email:'attacker@example.com',password:'password',role:'platform-admin'}});
   const headers=new Headers();const response=await ready.auth.api.signInEmail({body:{email:attacker.user.email,password:'password'},asResponse:true});ready.cookieSetter(headers)({response});
   await ready.auth.api.setRole({headers:root,body:{userId:attacker.user.id,role:'curator'}});
   expect(((await ready.auth.api.getSession({headers}))?.user as UserWithRole)?.role).toBe('platform-admin');
   await expect(ready.auth.api.setRole({headers,body:{userId:attacker.user.id,role:'platform-admin'}})).rejects.toMatchObject({status:'FORBIDDEN'});
   expect(await ready.auth.api.userHasPermission({headers,body:{permissions:{user:['set-role']}}})).toMatchObject({success:false});
   await ready.auth.api.banUser({headers:root,body:{userId:attacker.user.id}});
   await expect(ready.auth.api.listUsers({headers})).rejects.toMatchObject({status:'UNAUTHORIZED'});
  });
  it('keeps trusted provisioning separate from HTTP and revokes individual session tokens',async()=>{
   const ready=await factory(options);const {headers}=await ready.signInWithTestUser();
   const unauthenticated=await ready.auth.handler(new Request('http://localhost:3000/api/auth/admin/create-user',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Intruder',email:'intruder@example.com'})}));expect(unauthenticated.status).toBe(401);
   const created=await ready.auth.api.createUser({body:{name:'Provisioned',email:'provisioned@example.com',password:'password'}});
   const target=await ready.signInWithUser(created.user.email,'password');const current=await ready.auth.api.getSession({headers:target.headers});
   await ready.auth.api.revokeUserSession({headers,body:{sessionToken:current!.session.token}});
   expect(await ready.auth.api.getSession({headers:target.headers})).toBeNull();
  });
 });
}
it('maps Brand Map ban columns and preserves the current PostgreSQL row when resetting a password',async()=>{
 const configuration=await postgresOptions();
 const ready=await postgresInstance({...options,plugins:[admin({adminRoles:['platform-admin'],roles:{'platform-admin':adminAc,user:userAc},schema:{user:{fields:{banExpires:'ban_expires',banReason:'ban_reason'}}}})]},{nativePostgres:configuration});
 const {headers}=await ready.signInWithTestUser();const target=await ready.auth.api.createUser({headers,body:{name:'Target',email:'target@example.com'}});
 await ready.auth.api.setUserPassword({headers,body:{userId:target.user.id,newPassword:'password123'}});
 await ready.auth.api.banUser({headers,body:{userId:target.user.id,banReason:'Policy',banExpiresIn:60}});
 expect(await postgresSQL(configuration,`SELECT ban_reason FROM "${configuration.schema}".auth_user WHERE id='${target.user.id}'`)).toBe('Policy');
 await ready.auth.api.unbanUser({headers,body:{userId:target.user.id}});
 expect((await ready.auth.api.signInEmail({body:{email:target.user.email,password:'password123'}})).user.id).toBe(target.user.id);
 await expect(ready.auth.api.getUser({headers,query:{id:'invalid-uuid'}})).rejects.toMatchObject({status:'NOT_FOUND'});
});
it('denies an explicitly empty role table instead of restoring default admin powers',async()=>{
 const ready=await getTestInstance({plugins:[admin({roles:{}})]});
 expect(await ready.auth.api.userHasPermission({body:{role:'admin',permissions:{user:['create']}}})).toMatchObject({success:false});
});
it('rechecks primary secondary-storage revocation before accepting an admin cookie cache',async()=>{
 const values=new Map<string,string>();const secondaryStorage={set:(key:string,value:string)=>{values.set(key,value)},get:(key:string)=>values.get(key)??null,delete:(key:string)=>{values.delete(key)},getAndDelete:(key:string)=>{const value=values.get(key)??null;values.delete(key);return value},increment:(key:string)=>{const count=Number(values.get(key)??0)+1;values.set(key,String(count));return count}};
 const ready=await getTestInstance({...options,secondaryStorage,session:{cookieCache:{enabled:true,maxAge:300}}});
 const headers=new Headers();const response=await ready.auth.api.signInEmail({body:{email:'test@test.com',password:'test123456'},asResponse:true});
 ready.cookieSetter(headers)({response});const current=await ready.auth.api.getSession({headers});
 await ready.auth.api.revokeUserSession({headers,body:{sessionToken:current!.session.token}});
 expect(((await ready.auth.api.getSession({headers}))?.user as UserWithRole)?.role).toBe('platform-admin');
 await expect(ready.auth.api.listUsers({headers})).rejects.toMatchObject({status:'UNAUTHORIZED'});
});
it('honors default ban reason and duration, retaining fractional milliseconds',async()=>{
 const ready=await getTestInstance({...options,plugins:[admin({defaultBanReason:'Configured policy',defaultBanExpiresIn:120})]});
 const adapter=(await ready.auth.$context).internalAdapter;await adapter.updateUser((await adapter.findUserByEmail('test@test.com')).user.id,{role:'admin'});
 const {headers}=await ready.signInWithTestUser();const user=await ready.auth.api.createUser({headers,body:{name:'Target',email:'precision@example.com'}});
 for(const [seconds,expected] of [[0,120000],[0.5,500]]){
  const result=await ready.auth.api.banUser({headers,body:{userId:user.user.id,banReason:'',banExpiresIn:seconds}});
  expect(result.user.banReason).toBe('Configured policy');
  expect(new Date(result.user.banExpires).getTime()-new Date(result.user.updatedAt).getTime()).toBe(expected);
 }
});
