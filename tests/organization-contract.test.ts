import {it,expect} from 'vitest';
import {createAuthClient} from 'better-auth/client';
import {organizationClient} from 'better-auth/client/plugins';
import {organization} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';
it('round-trips organization metadata through the native HTTP transport',async()=>{
 const ready=await getTestInstance({plugins:[organization()]});const {headers}=await ready.signInWithTestUser();headers.set('origin','http://localhost:3000');
 const client=createAuthClient({plugins:[organizationClient()],baseURL:'http://localhost:3000/api/auth',fetchOptions:{customFetchImpl:async(url,init)=>ready.auth.handler(new Request(url,init))}});
 const result=await client.organization.create({name:'Metadata',slug:'metadata',metadata:{nested:{constructor:'ordinary data'}},fetchOptions:{headers}});
 if(result.error)throw new Error(JSON.stringify(result.error));
 expect(result.data?.metadata).toEqual({nested:{constructor:'ordinary data'}});
 const full=await client.organization.getFullOrganization({query:{organizationId:result.data!.id},fetchOptions:{headers}});
 if(full.error)throw new Error(JSON.stringify(full.error));
 expect(full.data?.metadata).toEqual(result.data!.metadata);
});

import {describe} from 'vitest';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from './harness/mongo-fixture.js';
const brandMapOrganization=()=>organization({allowUserToCreateOrganization:false,schema:{
 organization:{modelName:'brand_map_organization',fields:{createdAt:'created_at'},additionalFields:{status:{type:'string',input:false,defaultValue:'pending_review'},status_reason:{type:'string',input:false},creator_id:{type:'string',input:false},reviewed_at:{type:'date',input:false},reviewed_by:{type:'string',input:false}}},
 member:{modelName:'brand_map_member',fields:{organizationId:'organization_id',userId:'user_id',createdAt:'created_at'}},
},organizationHooks:{beforeCreateOrganization:async({organization,user})=>({data:{...organization,creator_id:user.id}})}});
for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 describe('Brand Map organizations on '+backend,()=>{
  it('requires trusted creation and preserves protected review fields and creator ownership',async()=>{
   const ready=await factory({plugins:[brandMapOrganization()]});const root=await ready.signInWithTestUser();
   const body={name:'Brand Map',slug:'brand-map',userId:root.user.id,status:'approved',creator_id:'spoofed'};
   await expect(ready.auth.api.createOrganization({headers:root.headers,body})).rejects.toMatchObject({status:'FORBIDDEN'});
   const blocked=await ready.auth.handler(new Request('http://localhost:3000/api/auth/organization/create',{method:'POST',headers:{'content-type':'application/json','origin':'http://localhost:3000'},body:JSON.stringify(body)}));expect(blocked.status).toBe(401);
   const created=await ready.auth.api.createOrganization({body});expect(created).toMatchObject({status:'pending_review',creator_id:root.user.id});expect(created.members[0]).toMatchObject({userId:root.user.id,role:'owner'});
   await ready.auth.api.setActiveOrganization({headers:root.headers,body:{organizationId:created.id}});
   expect((await ready.auth.api.getSession({headers:root.headers}))?.session).toHaveProperty('activeOrganizationId',created.id);
   const renamed=await ready.auth.api.updateOrganization({headers:root.headers,body:{organizationId:created.id,data:{name:'Renamed',status:'approved',creator_id:'spoofed'}}});expect(renamed).toMatchObject({name:'Renamed',status:'pending_review',creator_id:root.user.id});
   const other=await ready.auth.api.signUpEmail({body:{email:'outsider@example.com',name:'Outsider',password:'password'}});const outsider=await ready.signInWithUser(other.user.email,'password');
   await expect(ready.auth.api.getFullOrganization({headers:outsider.headers,query:{organizationId:created.id}})).rejects.toMatchObject({status:'FORBIDDEN'});
   const hidden=await ready.auth.handler(new Request('http://localhost:3000/api/auth/internal/organization/add-member',{method:'POST',headers:{'content-type':'application/json','origin':'http://localhost:3000','cookie':outsider.headers.get('cookie')!},body:JSON.stringify({organizationId:created.id,userId:other.user.id,role:'owner'})}));expect(hidden.status).toBe(404);
   await ready.auth.api.addMember({body:{organizationId:created.id,userId:other.user.id,role:'member'}});
   expect((await ready.auth.api.getFullOrganization({headers:outsider.headers,query:{organizationId:created.id}})).members).toHaveLength(2);
   await expect(ready.auth.api.updateOrganization({headers:outsider.headers,body:{organizationId:created.id,data:{name:'Taken over'}}})).rejects.toMatchObject({status:'FORBIDDEN'});
  });
  it('rolls back organization and owner membership when an organization hook fails',async()=>{
   const ready=await factory({plugins:[organization({organizationHooks:{afterCreateOrganization:async()=>{throw new Error('domain hook failed')}}})]});const root=await ready.signInWithTestUser();
   await expect(ready.auth.api.createOrganization({body:{userId:root.user.id,name:'Rollback',slug:'rollback'}})).rejects.toThrow();
   expect(await ready.auth.api.listOrganizations({headers:root.headers})).toEqual([]);
  });
 });
}
it('reads current PostgreSQL moderation state after a concurrent application update',async()=>{
 const configuration=await postgresOptions();
 const ready=await postgresInstance({plugins:[organization({schema:{organization:{additionalFields:{status:{type:'string',input:false,defaultValue:'pending_review'}}}},organizationHooks:{beforeUpdateOrganization:async data=>{await postgresSQL(configuration,`UPDATE "${configuration.schema}".organization SET status='rejected'`);return {data:data.organization}}}})]},{nativePostgres:configuration});
 const root=await ready.signInWithTestUser();const created=await ready.auth.api.createOrganization({headers:root.headers,body:{name:'Review',slug:'review'}});
 const updated=await ready.auth.api.updateOrganization({headers:root.headers,body:{organizationId:created.id,data:{name:'Renamed'}}});expect(updated).toMatchObject({name:'Renamed',status:'rejected'});
});
it('stores mapped MongoDB organization references and dates using native BSON types',async()=>{
 const configuration=await mongoOptions();const ready=await mongoInstance({plugins:[brandMapOrganization()]},{nativeMongo:configuration});const root=await ready.signInWithTestUser();
 const created=await ready.auth.api.createOrganization({body:{userId:root.user.id,name:'Physical',slug:'physical'}});
 const organization=(await mongoCommand(configuration,{find:'brand_map_organization',filter:{slug:'physical'}})).cursor.firstBatch[0];
 expect(organization).toMatchObject({_id:{$oid:created.id},creator_id:root.user.id,status:'pending_review'});expect(organization.created_at.$date).toBeTypeOf('string');
 const member=(await mongoCommand(configuration,{find:'brand_map_member',filter:{role:'owner'}})).cursor.firstBatch[0];expect(member.organization_id.$oid).toBe(created.id);expect(member.user_id.$oid).toBe(root.user.id);
});
