import {describe,it,expect} from 'vitest';
import {organization} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Organization denied-selection cleanup on '+backend,()=>{
  for(const path of ['get-organization','get-full-organization','set-active']){
   it('persists cleanup after a forbidden '+path+' response with cookie caching',async()=>{
    const ready=await factory({plugins:[organization()],session:{cookieCache:{enabled:true,maxAge:3600}}});const root=await ready.signInWithTestUser();const own=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Own',slug:'own'}});
    const user=await ready.auth.api.signUpEmail({body:{name:'Other',email:'other@example.com',password:'password'}});const foreign=await ready.auth.api.createOrganization({body:{userId:user.user.id,name:'Foreign',slug:'foreign'}});
    const active=await ready.auth.api.setActiveOrganization({headers:root.headers,body:{organizationId:own.id},asResponse:true});ready.cookieSetter(root.headers)({response:active});
    expect((await ready.auth.api.getSession({headers:root.headers}))?.session.activeOrganizationId).toBe(own.id);
    const headers=new Headers(root.headers);const method=path==='set-active'?'POST':'GET';if(method==='POST'){headers.set('origin','http://localhost:3000');headers.set('content-type','application/json')}
    const url='http://localhost:3000/api/auth/organization/'+path+(method==='GET'?'?organizationId='+foreign.id:'');
    const denied=await ready.auth.handler(new Request(url,{method,headers,body:method==='POST'?JSON.stringify({organizationId:foreign.id}):undefined}));
    expect(denied.status).toBe(403);expect(await denied.clone().json()).toMatchObject({code:'USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION'});ready.cookieSetter(root.headers)({response:denied});
    expect((await ready.auth.api.getSession({headers:root.headers,query:{disableCookieCache:true}}))?.session.activeOrganizationId).toBeNull();
    expect((await ready.auth.api.getSession({headers:root.headers}))?.session.activeOrganizationId).toBeNull();
    expect(await ready.auth.api.getFullOrganization({headers:root.headers})).toBeNull();expect(await ready.auth.api.listOrganizations({headers:root.headers})).toHaveLength(1);
   });
  }
  it('preserves valid selection on a missing organization read but clears it on failed activation',async()=>{
   const ready=await factory({plugins:[organization()]});const root=await ready.signInWithTestUser();const own=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Own',slug:'own'}});
   const missing='00000000-0000-4000-8000-000000000000';
   await expect(ready.auth.api.getOrganization({headers:root.headers,query:{organizationId:missing}})).rejects.toMatchObject({status:'BAD_REQUEST'});
   expect((await ready.auth.api.getSession({headers:root.headers}))?.session.activeOrganizationId).toBe(own.id);
   await expect(ready.auth.api.setActiveOrganization({headers:root.headers,body:{organizationId:missing}})).rejects.toMatchObject({status:'FORBIDDEN'});
   expect((await ready.auth.api.getSession({headers:root.headers}))?.session.activeOrganizationId).toBeNull();
  });
 });
}
