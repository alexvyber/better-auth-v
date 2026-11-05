import {it,expect,vi} from 'vitest';
import {createAccessControl} from 'better-auth/plugins/access';
import {defaultStatements} from 'better-auth/plugins/organization/access';
import {openAPI} from 'better-auth/plugins';
import {organization} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
import {getTestInstance as postgresInstance} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from './harness/mongo-fixture.js';
const postPaths=['create','update','delete','check-slug','set-active','invite-member','accept-invitation','reject-invitation','cancel-invitation','has-permission','update-member-role','create-role','update-role','delete-role','remove-member','leave'];
const getPaths=['get-full-organization','get-organization','list','get-active-member','list-members','get-invitation','list-invitations','list-user-invitations','list-roles','get-role','get-active-member-role'];
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 it(`documents Brand Map organization inputs and exercises their HTTP shapes on ${backend}`,async()=>{
  const factoryDefault=vi.fn(()=> 'generated label');const lifecycle=vi.fn(async({organization:org,user}:any)=>({data:{...org,creator_id:user.id}}));const send=vi.fn(async()=>{});
  const ready=await factory({plugins:[openAPI(),organization({ac:createAccessControl(defaultStatements),allowUserToCreateOrganization:false,dynamicAccessControl:{enabled:true},sendInvitationEmail:send,organizationHooks:{beforeCreateOrganization:lifecycle},schema:{
   organization:{modelName:'brand_map_org_docs',additionalFields:{status:{type:'string',input:false,defaultValue:'pending_review'},creator_id:{type:'string',input:false},reviewed_at:{type:'date',input:false},label:{type:'string',required:true,defaultValue:factoryDefault}}},
   invitation:{additionalFields:{note:{type:'string',required:false}}},
   organizationRole:{additionalFields:{label:{type:'string',required:false},internalNote:{type:'string',input:false,defaultValue:'server'}}},
  }})]});
  const schema=await ready.auth.api.generateOpenAPISchema();expect(await ready.auth.api.generateOpenAPISchema()).toEqual(schema);
  expect(factoryDefault).not.toHaveBeenCalled();expect(lifecycle).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();
  const body=(name:string)=>schema.paths['/organization/'+name].post.requestBody.content['application/json'].schema;
  const response=(name:string,method='post')=>schema.paths['/organization/'+name][method].responses['200'].content['application/json'].schema;
  for(const path of postPaths)expect(schema.paths['/organization/'+path].post.requestBody.content['application/json'].schema.type).toBe('object');
  for(const path of getPaths)expect(schema.paths['/organization/'+path].get.responses['200']).toBeDefined();
  const operations=[...postPaths.map(path=>schema.paths['/organization/'+path].post),...getPaths.map(path=>schema.paths['/organization/'+path].get)];
  expect(new Set(operations.map(operation=>operation.operationId)).size).toBe(27);expect(operations.every(operation=>operation.tags.includes('Organization'))).toBe(true);
  expect(body('create').required).toEqual(['name','slug']);expect(body('create').properties.label.type).toBe('string');expect(body('create').properties.label.default).toBeUndefined();
  for(const field of ['status','creator_id','reviewed_at']){expect(body('create').properties[field]).toBeUndefined();expect(body('update').properties.data.properties[field]).toBeUndefined();expect(schema.components.schemas.Organization.properties[field].readOnly).toBe(true)}
  expect(body('create').properties.userId.description).toContain('server API');expect(schema.components.schemas.Organization.properties.metadata.type).toBe('object');
  expect(body('has-permission').properties.permissions).toEqual({type:'object',additionalProperties:{type:'array',items:{type:'string'}}});
  expect(schema.components.schemas.OrganizationRole.properties.permission).toEqual(body('create-role').properties.permission);
  expect(body('create-role').required).toEqual(['role','permission']);expect(body('create-role').properties.additionalFields.properties.internalNote).toBeUndefined();
  expect(body('update-role').anyOf).toEqual([{required:['roleId']},{required:['roleName']}]);expect(body('update-role').properties.data.properties.permission.type).toBe('object');
  const query=schema.paths['/organization/list-members'].get.parameters;
  expect(query.find((item:any)=>item.name==='limit').schema).toEqual({type:'integer',minimum:0});expect(query.find((item:any)=>item.name==='filterValue').schema.anyOf).toEqual([{type:'string'},{type:'array',items:{type:'string'}}]);
  expect(schema.paths['/organization/list-user-invitations'].get.parameters??[]).toEqual([]);expect(schema.paths['/internal/organization/add-member']).toBeUndefined();
  expect(response('list','get')).toEqual({type:'array',items:{$ref:'#/components/schemas/Organization'}});
  expect(response('reject-invitation').properties.member).toEqual({type:'null'});expect(response('list-members','get').properties.total.type).toBe('integer');
  const root=await ready.signInWithTestUser();expect(factoryDefault).not.toHaveBeenCalled();
  // The trusted API supplies the owner; protected review values remain server-owned.
  const created=await ready.auth.api.createOrganization({body:{userId:root.user.id,name:'Documented',slug:'documented',label:'Explicit label',metadata:{nested:{enabled:true}}}});
  expect(created).toMatchObject({status:'pending_review',creator_id:root.user.id,label:'Explicit label',metadata:{nested:{enabled:true}}});
  expect(lifecycle).toHaveBeenCalledTimes(1);expect(factoryDefault).not.toHaveBeenCalled();
  // Raw trusted JSON verifies runtime defaults independently of SDK required-field inference.
  const defaulted=await ready.auth.api.createOrganization({body:JSON.parse(JSON.stringify({userId:root.user.id,name:'Defaults',slug:'defaults'}))});
  expect(defaulted.label).toBe('generated label');expect(factoryDefault).toHaveBeenCalledTimes(1);
  await ready.auth.api.generateOpenAPISchema();expect(factoryDefault).toHaveBeenCalledTimes(1);
  const http=async(path:string,data:unknown,headers:Headers=root.headers)=>{
   const outgoing=new Headers(headers);outgoing.set('content-type','application/json');outgoing.set('origin','http://localhost:3000');
   return ready.auth.handler(new Request('http://localhost:3000/api/auth/organization/'+path,{method:'POST',headers:outgoing,body:JSON.stringify(data)}));
  };
  const role=await http('create-role',{organizationId:created.id,role:'documented-reader',permission:{organization:['update']},additionalFields:{label:'Documented role',internalNote:'spoof'}});expect(role.status).toBe(200);const roleData=await role.json();
  expect(roleData).toMatchObject({success:true,roleData:{label:'Documented role',internalNote:'server',permission:{organization:['update']}},statements:{organization:['update']}});
  const changed=await http('update-role',{organizationId:created.id,roleId:roleData.roleData.id,data:{roleName:'documented-reader-renamed',label:'Updated'}});expect(changed.status).toBe(200);expect((await changed.json()).roleData.role).toBe('documented-reader-renamed');
  const memberRole=await http('update-member-role',{organizationId:created.id,memberId:created.members[0].id,role:['owner']});expect(memberRole.status).toBe(200);expect((await memberRole.json()).role).toBe('owner');
  const invitation=await http('invite-member',{organizationId:created.id,email:'docs-recipient@example.com',role:['member'],note:'Documented invitation'});expect(invitation.status).toBe(200);const invite=await invitation.json();expect(invite).toMatchObject({status:'pending',note:'Documented invitation'});expect(send).toHaveBeenCalledTimes(1);
  const signup=await ready.auth.api.signUpEmail({body:{email:'docs-recipient@example.com',name:'Recipient',password:'password123'}});const recipient=await ready.signInWithUser(signup.user.email,'password123');
  const accepted=await http('accept-invitation',{invitationId:invite.id},recipient.headers);expect(accepted.status).toBe(200);expect(await accepted.json()).toMatchObject({invitation:{status:'accepted'},member:{userId:signup.user.id,role:'member'}});
  const members=await ready.auth.handler(new Request('http://localhost:3000/api/auth/organization/list-members?organizationId='+created.id+'&filterField=role&filterOperator=in&filterValue=owner&filterValue=admin&limit=1&offset=0',{headers:root.headers}));expect(members.status).toBe(200);expect(await members.json()).toMatchObject({total:1,members:[{role:'owner',user:{id:root.user.id,email:root.user.email,image:null}}]});
 });
}
it('hides disabled dynamic-role endpoints without hiding static member-role operations',async()=>{
 const ready=await getTestInstance({plugins:[openAPI(),organization()]});const schema=await ready.auth.api.generateOpenAPISchema();
 for(const name of ['create-role','update-role','delete-role','list-roles','get-role'])expect(schema.paths['/organization/'+name]).toBeUndefined();
 expect(schema.paths['/organization/update-member-role'].post.requestBody).toBeDefined();expect(schema.components.schemas.OrganizationRole).toBeDefined();
});
