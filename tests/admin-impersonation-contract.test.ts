import {describe,it,expect} from 'vitest';
import {adminAc,userAc} from 'better-auth/plugins/admin/access';
import {admin} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
const options={advanced:{cookiePrefix:'bm'},plugins:[admin({adminRoles:['platform-admin'],roles:{'platform-admin':adminAc,curator:userAc,user:userAc},impersonationSessionDuration:600})],databaseHooks:{user:{create:{before:async(user:any)=>({data:{...user,...(user.email==='test@test.com'?{role:'platform-admin'}:{})}})}}}};
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('admin impersonation on '+backend,()=>{
  for(const rememberMe of [true,false])it('restores the original '+(rememberMe?'persistent':'browser-only')+' session and destroys the impersonation session',async()=>{
   const ready=await factory(options);const rootHeaders=new Headers();
   const signin=await ready.auth.api.signInEmail({body:{email:'test@test.com',password:'test123456',rememberMe},asResponse:true});ready.cookieSetter(rootHeaders)({response:signin});
   const root=await ready.auth.api.getSession({headers:rootHeaders});const target=await ready.auth.api.createUser({headers:rootHeaders,body:{name:'Target',email:'target@example.com'}});
   const headers=new Headers(rootHeaders);const response=await ready.auth.api.impersonateUser({headers,body:{userId:target.user.id},asResponse:true});
   const changed=await response.clone().json();ready.cookieSetter(headers)({response});
   expect(changed.session.impersonatedBy).toBe(root!.user.id);expect(new Date(changed.session.expiresAt).getTime()-new Date(changed.session.createdAt).getTime()).toBe(600000);
   expect(response.headers.getSetCookie().filter((c:string)=>c.startsWith('bm.session_token=')).at(-1)).not.toContain('Max-Age');
   expect((await ready.auth.api.getSession({headers}))?.user.id).toBe(target.user.id);
   expect(await ready.auth.api.listSessions({headers})).toEqual([]);
   expect((await ready.auth.api.listUserSessions({headers:rootHeaders,body:{userId:target.user.id}})).sessions).toHaveLength(1);
   const restored=await ready.auth.api.stopImpersonating({headers,asResponse:true});const body=await restored.clone().json();
   expect(body.session.id).toBe(root!.session.id);expect(body.user.id).toBe(root!.user.id);
   const tokenCookie=restored.headers.getSetCookie().filter((c:string)=>c.startsWith('bm.session_token=')).at(-1)!;
   expect(tokenCookie.includes('Max-Age')).toBe(rememberMe);
   expect(restored.headers.getSetCookie()).toEqual(expect.arrayContaining([expect.stringMatching(/^bm.admin_session=;.*Max-Age=0/)]));
   const oldHeaders=new Headers(headers);ready.cookieSetter(headers)({response:restored});
   expect((await ready.auth.api.getSession({headers}))?.session.id).toBe(root!.session.id);
   expect(await (await ready.auth.$context).internalAdapter.findSession(changed.session.token)).toBeNull();
   await expect(ready.auth.api.stopImpersonating({headers:oldHeaders})).rejects.toMatchObject({status:'UNAUTHORIZED'});
  });
  it('rejects a forged restoration cookie and refuses a revoked original admin session',async()=>{
   const ready=await factory(options);const root=await ready.signInWithTestUser();
   const target=await ready.auth.api.createUser({headers:root.headers,body:{name:'Target',email:'target@example.com'}});
   const headers=new Headers(root.headers);const response=await ready.auth.api.impersonateUser({headers,body:{userId:target.user.id},asResponse:true});ready.cookieSetter(headers)({response});
   const forged=new Headers(headers);forged.set('cookie',forged.get('cookie')!.replace(/(bm\.admin_session=)[^;]+/,'$1forged'));
   await expect(ready.auth.api.stopImpersonating({headers:forged})).rejects.toMatchObject({status:'INTERNAL_SERVER_ERROR'});
   expect((await ready.auth.api.getSession({headers:forged}))?.user.id).toBe(target.user.id);
   await ready.auth.api.revokeUserSession({headers:root.headers,body:{sessionToken:root.session.token}});
   await expect(ready.auth.api.stopImpersonating({headers})).rejects.toMatchObject({status:'INTERNAL_SERVER_ERROR'});
   expect((await ready.auth.api.getSession({headers}))?.user.id).toBe(target.user.id);
  });
  it('restores the current role after the original admin is demoted',async()=>{
   const ready=await factory(options);const root=await ready.signInWithTestUser();const target=await ready.auth.api.createUser({headers:root.headers,body:{name:'Target',email:'target@example.com'}});
   const headers=new Headers(root.headers);const response=await ready.auth.api.impersonateUser({headers,body:{userId:target.user.id},asResponse:true});ready.cookieSetter(headers)({response});
   await ready.auth.api.setRole({headers:root.headers,body:{userId:root.user.id,role:'curator'}});
   const restored=await ready.auth.api.stopImpersonating({headers,asResponse:true});expect((await restored.clone().json()).user.role).toBe('curator');ready.cookieSetter(headers)({response:restored});
   await expect(ready.auth.api.listUsers({headers})).rejects.toMatchObject({status:'FORBIDDEN'});
  });
 });
}
