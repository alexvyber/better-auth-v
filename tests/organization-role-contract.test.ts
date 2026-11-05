import {describe,it,expect} from 'vitest';
import {createAccessControl} from 'better-auth/plugins/access';
import {defaultStatements,ownerAc,memberAc} from 'better-auth/plugins/organization/access';
import {organization} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Organization role contracts on '+backend,()=>{
  it('rechecks stored membership and permission edits despite session cookie caching',async()=>{
   const ac=createAccessControl({...defaultStatements,product:['read','publish']});
   const options={plugins:[organization({ac,roles:{owner:ac.newRole({...ownerAc.statements,product:['read','publish']}),member:ac.newRole(memberAc.statements)},dynamicAccessControl:{enabled:true},schema:{organizationRole:{modelName:'brand_map_organization_role',fields:{organizationId:'organization_id',createdAt:'created_at',updatedAt:'updated_at'}}}})],session:{cookieCache:{enabled:true,maxAge:3600}}};
   const ready=await factory(options);const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Roles',slug:'roles'}});
   const role=await ready.auth.api.createOrgRole({headers:root.headers,body:{organizationId:org.id,role:'Publisher',permission:{product:['publish']}}});expect(role.roleData.role).toBe('publisher');
   const user=await ready.auth.api.signUpEmail({body:{name:'Publisher',email:'publisher@example.com',password:'password'}});
   await ready.auth.api.addMember({body:{organizationId:org.id,userId:user.user.id,role:'publisher'}} as any);const publisher=await ready.signInWithUser(user.user.email,'password');
   const permission={headers:publisher.headers,body:{organizationId:org.id,permissions:{product:['publish']}}};
   expect((await ready.auth.api.hasPermission(permission)).success).toBe(true);
   const response=await ready.auth.api.getSession({headers:publisher.headers,asResponse:true});ready.cookieSetter(publisher.headers)({response});
   await ready.auth.api.updateOrgRole({headers:root.headers,body:{organizationId:org.id,roleId:role.roleData.id,data:{permission:{product:['read']}}}});
   expect((await ready.auth.api.hasPermission(permission)).success).toBe(false);
   const member=(await ready.auth.api.listMembers({headers:root.headers,query:{organizationId:org.id}})).members.find((member:any)=>member.userId===user.user.id);
   await ready.auth.api.updateMemberRole({headers:root.headers,body:{organizationId:org.id,memberId:member!.id,role:'member'}});
   expect((await ready.auth.api.hasPermission({headers:publisher.headers,body:{organizationId:org.id,permissions:{product:['read']}}})).success).toBe(false);
   await ready.auth.api.deleteOrgRole({headers:root.headers,body:{organizationId:org.id,roleId:role.roleData.id}});
  });
  it('merges app-provisioned permissions with Brand Map grants and respects the ac resource boundary',async()=>{
   const ac=createAccessControl({organization:['read','update'],member:['read','update','delete'],invitation:['create','read','cancel'],accessControl:['create','read','update','delete'],product:['read','publish']});
   const owner=ac.newRole({organization:['read','update'],member:['read','update','delete'],invitation:['create','read','cancel'],accessControl:['create','read','update','delete'],product:['read']});
   const ready=await factory({plugins:[organization({ac,roles:{owner},dynamicAccessControl:{enabled:true}})]});const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Brand Map',slug:'brand-map'}});
   expect((await ready.auth.api.hasPermission({headers:root.headers,body:{organizationId:org.id,permissions:{accessControl:['update']}}})).success).toBe(true);
   await expect(ready.auth.api.createOrgRole({headers:root.headers,body:{organizationId:org.id,role:'publisher',permission:{product:['publish']}}})).rejects.toThrow('You are not allowed to create a role');
   await expect(ready.auth.api.deleteOrganization({headers:root.headers,body:{organizationId:org.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   await ready.db.create({model:'organizationRole',data:{organizationId:org.id,role:'owner',permission:JSON.stringify({product:['publish']}),createdAt:new Date()}});
   expect((await ready.auth.api.hasPermission({headers:root.headers,body:{organizationId:org.id,permissions:{product:['read','publish'],organization:['update']}}})).success).toBe(true);
   await ready.db.delete({model:'organizationRole',where:[{field:'organizationId',value:org.id}]});
   expect((await ready.auth.api.hasPermission({headers:root.headers,body:{organizationId:org.id,permissions:{product:['publish']}}})).success).toBe(false);
  });
  it('fails closed on malformed persisted permission data and enforces the role cap',async()=>{
   const ac=createAccessControl(defaultStatements);
   const ready=await factory({plugins:[organization({ac,dynamicAccessControl:{enabled:true,maximumRolesPerOrganization:1}})]});const root=await ready.signInWithTestUser();const org=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Malformed',slug:'malformed'}});
   await ready.auth.api.createOrgRole({headers:root.headers,body:{organizationId:org.id,role:'one',permission:{member:['update']}}});
   await expect(ready.auth.api.createOrgRole({headers:root.headers,body:{organizationId:org.id,role:'two',permission:{member:['update']}}})).rejects.toThrow('This organization has too many roles');
   await ready.db.delete({model:'organizationRole',where:[{field:'organizationId',value:org.id}]});
   await ready.db.create({model:'organizationRole',data:{organizationId:org.id,role:'owner',permission:'{"member":"update"}',createdAt:new Date()}});
   await expect(ready.auth.api.hasPermission({headers:root.headers,body:{organizationId:org.id,permissions:{member:['update']}}})).rejects.toThrow('Internal server error');
  });
 });
}
