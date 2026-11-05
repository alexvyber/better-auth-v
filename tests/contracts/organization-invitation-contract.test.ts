import {describe,it,expect,vi} from 'vitest';
import {organization} from '../harness/plugins.js';
import {getTestInstance} from '../harness/test-instance.js';
import {getTestInstance as postgresInstance} from '../harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from '../harness/mongo-fixture.js';

for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Organization invitation contracts on '+backend,()=>{
  it('delivers Brand Map invitation data, preserves protected fields and checks current tenant authority',async()=>{
   const send=vi.fn();const before=vi.fn();const after=vi.fn();
   const ready=await factory({plugins:[organization({invitationExpiresIn:3600,sendInvitationEmail:send,
    schema:{invitation:{modelName:'brand_map_invitation',fields:{organizationId:'organization_id',inviterId:'inviter_id',expiresAt:'expires_at',createdAt:'created_at'},additionalFields:{review:{type:'string',input:false,defaultValue:'pending'}}}},
    organizationHooks:{beforeCreateInvitation:before,afterCreateInvitation:after}})]});
   const root=await ready.signInWithTestUser();
   const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Brand Map',slug:'brand-map'}});
   const invite=await ready.auth.api.createInvitation({headers:root.headers,body:{organizationId:org.id,email:'Invite@Example.com',role:['admin','member'],review:'approved',inviterId:'spoofed'}});
   expect(invite).toMatchObject({email:'invite@example.com',role:'admin,member',status:'pending',review:'pending',inviterId:root.user.id,organizationId:org.id});
   expect(send).toHaveBeenCalledTimes(1);expect(send.mock.calls[0][0]).toMatchObject({id:invite.id,email:invite.email,role:invite.role,organization:{id:org.id},inviter:{user:{id:root.user.id}},invitation:{id:invite.id,review:'pending'}});
   expect(send.mock.calls[0][0].invitation.expiresAt).toBeInstanceOf(Date);
   expect(before).toHaveBeenCalledTimes(1);expect(after).toHaveBeenCalledTimes(1);
   const outsider=await ready.auth.api.signUpEmail({body:{name:'Outsider',email:'outsider@example.com',password:'password'}});
   const other=await ready.signInWithUser(outsider.user.email,'password');
   await expect(ready.auth.api.getInvitation({headers:other.headers,query:{id:invite.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   await expect(ready.auth.api.listInvitations({headers:other.headers,query:{organizationId:org.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   await expect(ready.auth.api.cancelInvitation({headers:other.headers,body:{invitationId:invite.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   const leaked=await ready.auth.handler(new Request('http://localhost:3000/api/auth/organization/list-user-invitations?email=invite%40example.com'));
   expect(leaked.status).toBe(400);
   expect(await ready.auth.api.listUserInvitations({query:{email:invite.email}})).toHaveLength(1);
   const canceled=await ready.auth.api.cancelInvitation({headers:root.headers,body:{invitationId:invite.id}});expect(canceled.status).toBe('canceled');
   expect(await ready.auth.api.listUserInvitations({query:{email:invite.email}})).toEqual([]);
  });
  it('rolls back a failed acceptance and allows one successful retry with an active organization',async()=>{
   let fail=true;
   const ready=await factory({plugins:[organization({organizationHooks:{afterAcceptInvitation:async()=>{if(fail)throw new Error('application membership failed')}}})]});
   const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Retry',slug:'retry'}});
   const invite=await ready.auth.api.createInvitation({headers:root.headers,body:{organizationId:org.id,email:'recipient@example.com',role:'member'}});
   await ready.auth.api.signUpEmail({body:{name:'Recipient',email:invite.email,password:'password'}});const recipient=await ready.signInWithUser(invite.email,'password');
   const previousActive=(await ready.auth.api.getSession({headers:recipient.headers}))?.session.activeOrganizationId;
   await expect(ready.auth.api.acceptInvitation({headers:recipient.headers,body:{invitationId:invite.id}})).rejects.toThrow('Internal server error');
   expect((await ready.auth.api.getInvitation({headers:recipient.headers,query:{id:invite.id}})).status).toBe('pending');
   expect((await ready.auth.api.getFullOrganization({headers:root.headers,query:{organizationId:org.id}}))!.members).toHaveLength(1);
   expect((await ready.auth.api.getSession({headers:recipient.headers}))?.session.activeOrganizationId).toEqual(previousActive);
   fail=false;
   const accepted=await ready.auth.api.acceptInvitation({headers:recipient.headers,body:{invitationId:invite.id}});expect(accepted).toMatchObject({invitation:{status:'accepted'},member:{organizationId:org.id,userId:recipient.user.id,role:'member'}});
   expect((await ready.auth.api.getSession({headers:recipient.headers}))?.session.activeOrganizationId).toBe(org.id);
   await expect(ready.auth.api.acceptInvitation({headers:recipient.headers,body:{invitationId:invite.id}})).rejects.toMatchObject({status:'BAD_REQUEST'});
   expect((await ready.auth.api.getFullOrganization({headers:root.headers,query:{organizationId:org.id}}))!.members).toHaveLength(2);
  });
  it('rolls back failed invitation delivery and refuses acceptance at the membership limit',async()=>{
   let fail=true;
   const ready=await factory({plugins:[organization({membershipLimit:1,sendInvitationEmail:async()=>{if(fail)throw new Error('mail failed')}})]});const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Limits',slug:'limits'}});
   const args={headers:root.headers,body:{organizationId:org.id,email:'limit@example.com',role:'member' as const}};
   await expect(ready.auth.api.createInvitation(args)).rejects.toThrow('Internal server error');expect(await ready.auth.api.listInvitations({headers:root.headers,query:{organizationId:org.id}})).toEqual([]);
   fail=false;const invite=await ready.auth.api.createInvitation(args);
   await ready.auth.api.signUpEmail({body:{name:'Limit',email:invite.email,password:'password'}});const recipient=await ready.signInWithUser(invite.email,'password');
   await expect(ready.auth.api.acceptInvitation({headers:recipient.headers,body:{invitationId:invite.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   expect((await ready.auth.api.getInvitation({headers:recipient.headers,query:{id:invite.id}})).status).toBe('pending');
  });
 });
}

import {postgresOptions} from '../harness/postgres-fixture.js';
import {mongoOptions} from '../harness/mongo-fixture.js';
for(const backend of ['postgres','mongo'] as const){
 it('allows one concurrent invitation acceptance across independent '+backend+' connections',async()=>{
  const storage=backend==='postgres'?{nativePostgres:await postgresOptions()}:{nativeMongo:await mongoOptions()};
  const factory=backend==='postgres'?postgresInstance:mongoInstance;
  let arrivals=0;let release!:()=>void;const barrier=new Promise<void>(resolve=>{release=resolve});
  const options={plugins:[organization({organizationHooks:{beforeAcceptInvitation:async()=>{arrivals++;if(arrivals===2)release();await barrier}}})]};
  const first=await factory(options,storage);const root=await first.signInWithTestUser();const org=await first.auth.api.createOrganization({headers:root.headers,body:{name:'Concurrent',slug:'concurrent'}});
  const invite=await first.auth.api.createInvitation({headers:root.headers,body:{organizationId:org.id,email:'concurrent@example.com',role:'member'}});
  await first.auth.api.signUpEmail({body:{name:'Concurrent',email:invite.email,password:'password'}});const recipient=await first.signInWithUser(invite.email,'password');
  const second=await factory(options,{...storage,disableTestUser:true});
  const results=await Promise.allSettled([first,second].map(instance=>instance.auth.api.acceptInvitation({headers:recipient.headers,body:{invitationId:invite.id}})));
  expect(arrivals).toBe(2);expect(results.filter(result=>result.status==='fulfilled')).toHaveLength(1);
  const full=await first.auth.api.getFullOrganization({headers:root.headers,query:{organizationId:org.id}});
  expect(full!.members.filter(member=>member.userId===recipient.user.id)).toHaveLength(1);
  expect(full!.invitations.find((invitation:any)=>invitation.id===invite.id).status).toBe('accepted');
 });
}
