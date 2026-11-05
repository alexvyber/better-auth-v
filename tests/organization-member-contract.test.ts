import {it,describe,expect,vi} from 'vitest';
import {organization} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Organization member contracts on '+backend,()=>{
  it('joins and pages every user when the organization contains more than 100 members',async()=>{
   const ready=await factory({plugins:[organization({membershipLimit:500})]});const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Large',slug:'large'}});
   const context=await ready.auth.$context;
   for(let index=0;index<110;index++){
    const user=await context.internalAdapter.createUser({email:`member-${index}@example.com`,name:`Member ${index}`});
    await ready.auth.api.addMember({body:{organizationId:org.id,userId:user.id,role:'member'}});
   }
   const full=await ready.auth.api.listMembers({headers:root.headers,query:{organizationId:org.id}});
   expect(full.total).toBe(111);expect(full.members).toHaveLength(111);expect(new Set(full.members.map((member:any)=>member.user.id)).size).toBe(111);
   expect(full.members.every((member:any)=>member.user.id===member.userId&&typeof member.user.email==='string')).toBe(true);
   const page=await ready.auth.api.listMembers({headers:root.headers,query:{organizationId:org.id,offset:100,limit:20}});expect(page.total).toBe(111);expect(page.members).toHaveLength(11);
   const filtered=await ready.auth.api.listMembers({headers:root.headers,query:{organizationId:org.id,filterField:'role',filterOperator:'eq',filterValue:'member',limit:5}});expect(filtered.total).toBe(110);expect(filtered.members).toHaveLength(5);
  });
  it('enforces tenant and last-owner boundaries and rolls back failed removal hooks',async()=>{
   let fail=true;const before=vi.fn();const after=vi.fn(async()=>{if(fail)throw new Error('domain removal failed')});
   const ready=await factory({plugins:[organization({organizationHooks:{beforeRemoveMember:before,afterRemoveMember:after}})]});const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Members',slug:'members'}});
   const user=await ready.auth.api.signUpEmail({body:{name:'Alice',email:'alice@example.com',password:'password'}});const member=await ready.auth.api.addMember({body:{organizationId:org.id,userId:user.user.id,role:'member'}});const alice=await ready.signInWithUser(user.user.email,'password');
   await expect(ready.auth.api.removeMember({headers:alice.headers,body:{organizationId:org.id,memberIdOrEmail:root.user.email}})).rejects.toMatchObject({status:'BAD_REQUEST'});
   await expect(ready.auth.api.removeMember({headers:root.headers,body:{organizationId:org.id,memberIdOrEmail:member.id}})).rejects.toThrow('Internal server error');
   expect((await ready.auth.api.getFullOrganization({headers:root.headers,query:{organizationId:org.id}}))!.members).toHaveLength(2);expect(before).toHaveBeenCalledTimes(1);expect(after).toHaveBeenCalledTimes(1);
   const other=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Other',slug:'other'}});
   await expect(ready.auth.api.removeMember({headers:root.headers,body:{organizationId:other.id,memberIdOrEmail:member.id}})).rejects.toMatchObject({status:'BAD_REQUEST'});
   fail=false;const removed=await ready.auth.api.removeMember({headers:root.headers,body:{organizationId:org.id,memberIdOrEmail:'ALICE@example.com'}});expect(removed.member.id).toBe(member.id);
   await expect(ready.auth.api.getFullOrganization({headers:alice.headers,query:{organizationId:org.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   await expect(ready.auth.api.leaveOrganization({headers:root.headers,body:{organizationId:org.id}})).rejects.toThrow('You cannot leave the organization as the only owner');
   await expect(ready.auth.api.removeMember({headers:root.headers,body:{organizationId:org.id,memberIdOrEmail:root.user.email}})).rejects.toThrow('You cannot leave the organization as the only owner');
  });
  it('clears the current active organization on leave and returns the deleted organization',async()=>{
   const ready=await factory({plugins:[organization()],session:{cookieCache:{enabled:true,maxAge:3600}}});const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Active',slug:'active'}});
   const user=await ready.auth.api.signUpEmail({body:{name:'Alice',email:'alice@example.com',password:'password'}});await ready.auth.api.addMember({body:{organizationId:org.id,userId:user.user.id,role:'member'}});const alice=await ready.signInWithUser(user.user.email,'password');
   const activation=await ready.auth.api.setActiveOrganization({headers:alice.headers,body:{organizationId:org.id},asResponse:true});ready.cookieSetter(alice.headers)({response:activation});
   const left=await ready.auth.api.leaveOrganization({headers:alice.headers,body:{organizationId:org.id},asResponse:true});expect(left.status).toBe(200);ready.cookieSetter(alice.headers)({response:left});
   expect((await ready.auth.api.getSession({headers:alice.headers}))?.session.activeOrganizationId).toBeNull();
   await expect(ready.auth.api.getActiveMemberRole({headers:alice.headers,query:{organizationId:org.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   const deleted=await ready.auth.api.deleteOrganization({headers:root.headers,body:{organizationId:org.id},asResponse:true});expect(deleted.status).toBe(200);ready.cookieSetter(root.headers)({response:deleted});expect(await deleted.json()).toMatchObject({id:org.id,name:'Active',slug:'active'});
   expect((await ready.auth.api.getSession({headers:root.headers}))?.session.activeOrganizationId).toBeNull();expect(await ready.auth.api.listOrganizations({headers:root.headers})).toEqual([]);
  });
 });
}
