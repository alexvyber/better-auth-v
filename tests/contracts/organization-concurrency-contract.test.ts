import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {afterEach,expect,it,vi} from 'vitest';
import {createAccessControl} from 'better-auth/plugins/access';
import {defaultStatements} from 'better-auth/plugins/organization/access';
import {organization} from '../harness/plugins.js';
import {getTestInstance} from '../harness/test-instance.js';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from '../harness/postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from '../harness/mongo-fixture.js';

const cleanup:(()=>Promise<unknown>)[]=[];
afterEach(async()=>{for(const close of cleanup.splice(0).reverse())await close()});
const settled=<T>(operation:Promise<T>)=>operation.then(value=>({status:'fulfilled' as const,value}),reason=>({status:'rejected' as const,reason}));

it('uses migrated MongoDB coordination on cold instances and requires migration when it is missing',async()=>{
 const f=await fixture('mongo');const org=await f.createOrg();
 const names=async()=>{const reply=await mongoCommand(f.config.nativeMongo,{listCollections:1,nameOnly:true});return reply.cursor.firstBatch.map((entry:any)=>entry.name).sort() as string[]};
 const original=await names();const coordinator=original.find(name=>name.startsWith('_ba_organization_lock_'))!;expect(coordinator).toBeTruthy();
 const cold=await f.factory(f.server,{...f.config,deferMigrations:true});cleanup.push(()=>cold.bridge.close());
 const a=await f.signup('cold-a@concurrency.example');
 await cold.auth.api.addMember({body:{organizationId:org.id,userId:a.user.id,role:'member'}});
 expect(await names()).toEqual(original);
 await mongoCommand(f.config.nativeMongo,{drop:coordinator});
 const missing=await f.factory(f.server,{...f.config,deferMigrations:true});cleanup.push(()=>missing.bridge.close());
 const b=await f.signup('cold-b@concurrency.example');
 await expect(missing.auth.api.addMember({body:{organizationId:org.id,userId:b.user.id,role:'member'}})).rejects.toMatchObject({statusCode:500});
 expect(await names()).not.toContain(coordinator);
 expect((await f.first.auth.api.listMembers({headers:f.root.headers,query:{organizationId:org.id}})).total).toBe(2);
 await f.first.bridge.send('migrate');
 await missing.auth.api.addMember({body:{organizationId:org.id,userId:b.user.id,role:'member'}});
 expect((await f.first.auth.api.listMembers({headers:f.root.headers,query:{organizationId:org.id}})).total).toBe(3);
});
function oneWinner(results:PromiseSettledResult<any>[]){
 expect(results.filter(result=>result.status==='fulfilled')).toHaveLength(1);
 expect(results.filter(result=>result.status==='rejected')).toHaveLength(1);
 return (results.find(result=>result.status==='rejected') as PromiseRejectedResult).reason;
}
async function fixture(backend:string,options:Record<string,any>={}){
 let config:Record<string,any>={disableTestUser:true};
 let factory=getTestInstance;
 if(backend==='postgres'){
  factory=postgresInstance;const storage=await postgresOptions();config.nativePostgres=storage;
  cleanup.push(()=>postgresSQL(storage,`DROP SCHEMA IF EXISTS "${storage.schema}" CASCADE`));
 }else if(backend==='mongo'){
  factory=mongoInstance;const storage=await mongoOptions();config.nativeMongo=storage;
  cleanup.push(()=>mongoCommand(storage,{dropDatabase:1}));
 }else{
  const directory=await mkdtemp(join(tmpdir(),'better-auth-org-concurrency-'));config.nativeSqlite=join(directory,'auth.sqlite');
  cleanup.push(()=>rm(directory,{recursive:true,force:true}));
 }
 const server:Parameters<typeof getTestInstance>[0]={plugins:[organization({ac:createAccessControl(defaultStatements),dynamicAccessControl:{enabled:true},...options})]};
 const first=await factory(server,config);cleanup.push(()=>first.bridge.close());
 const second=await factory(server,config);cleanup.push(()=>second.bridge.close());
 const signup=async(email:string)=>{
  const response=await first.auth.api.signUpEmail({body:{email,name:email,password:'password123'},asResponse:true});
  const headers=new Headers();first.cookieSetter(headers)({response});const user=(await response.json()).user;
  expect(response.status).toBe(200);return {user,headers};
 };
 const root=await signup('owner@concurrency.example');
 const createOrg=async(slug='concurrency')=>first.auth.api.createOrganization({headers:root.headers,body:{name:slug,slug}});
 return {first,second,root,signup,createOrg,config,factory,server};
}

for(const backend of ['sqlite','postgres','mongo']){
 it(`serializes membership-limit checks across independent ${backend} connections`,async()=>{
  const f=await fixture(backend,{membershipLimit:2,organizationHooks:{beforeAddMember:async()=>{await delay(40)}}});
  const org=await f.createOrg();const a=await f.signup('a@concurrency.example');const b=await f.signup('b@concurrency.example');
  const results=await Promise.allSettled([f.first,f.second].map((ready,index)=>ready.auth.api.addMember({body:{organizationId:org.id,userId:[a,b][index].user.id,role:'member'}})));
  expect(oneWinner(results)).toMatchObject({body:{code:'ORGANIZATION_MEMBERSHIP_LIMIT_REACHED'}});
  expect((await f.first.auth.api.listMembers({headers:f.root.headers,query:{organizationId:org.id}})).total).toBe(2);
 });

 it(`prevents both owners from concurrently demoting themselves on ${backend}`,async()=>{
  const f=await fixture(backend,{organizationHooks:{beforeUpdateMemberRole:async()=>{await delay(40)}}});
  const org=await f.createOrg();const other=await f.signup('co-owner@concurrency.example');
  const coOwner=await f.first.auth.api.addMember({body:{organizationId:org.id,userId:other.user.id,role:'owner'}});
  const results=await Promise.allSettled([
   f.first.auth.api.updateMemberRole({headers:f.root.headers,body:{organizationId:org.id,memberId:org.members[0].id,role:'member'}}),
   f.second.auth.api.updateMemberRole({headers:other.headers,body:{organizationId:org.id,memberId:coOwner.id,role:'member'}}),
  ]);
  expect(oneWinner(results)).toMatchObject({body:{code:'YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER'}});
  const members=(await f.first.auth.api.listMembers({headers:f.root.headers,query:{organizationId:org.id}})).members;
  expect(members.filter((member:any)=>member.role.split(',').includes('owner'))).toHaveLength(1);
 });

 it(`enforces the dynamic-role cap across independent ${backend} connections`,async()=>{
  const fallback=vi.fn(()=>{Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,40);return 'generated'});
  const f=await fixture(backend,{dynamicAccessControl:{enabled:true,maximumRolesPerOrganization:1},schema:{organizationRole:{additionalFields:{label:{type:'string',defaultValue:fallback}}}}});
  const org=await f.createOrg();
  const results=await Promise.allSettled([f.first,f.second].map((ready,index)=>ready.auth.api.createOrgRole({headers:f.root.headers,body:{organizationId:org.id,role:'role-'+index,permission:{organization:['update']}}})));
  expect(oneWinner(results)).toMatchObject({body:{code:'TOO_MANY_ROLES'}});expect(fallback).toHaveBeenCalledTimes(1);
  expect(await f.first.auth.api.listOrgRoles({headers:f.root.headers,query:{organizationId:org.id}})).toHaveLength(1);
 });

 it(`enforces a user-wide organization cap across different sessions on ${backend}`,async()=>{
  const f=await fixture(backend,{organizationLimit:1,organizationHooks:{beforeCreateOrganization:async()=>{await delay(40)}}});
  const otherSession=await f.first.signInWithUser(f.root.user.email,'password123');
  const results=await Promise.allSettled([
   f.first.auth.api.createOrganization({headers:f.root.headers,body:{name:'First',slug:'first'}}),
   f.second.auth.api.createOrganization({headers:otherSession.headers,body:{name:'Second',slug:'second'}}),
  ]);
  expect(oneWinner(results)).toMatchObject({body:{code:'YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS'}});
  expect(await f.first.auth.api.listOrganizations({headers:f.root.headers})).toHaveLength(1);
 });

 it(`serializes role assignment against deletion on ${backend}`,async()=>{
  let deleting:ReturnType<typeof settled>|undefined;
  let startDelete:(()=>void)|undefined;
  const f=await fixture(backend,{organizationHooks:{beforeUpdateMemberRole:async(data:any)=>{
   if(data.newRole==='editor'){startDelete!();await delay(60)}
  }}});
  const org=await f.createOrg();const target=await f.signup('editor@concurrency.example');
  const member=await f.first.auth.api.addMember({body:{organizationId:org.id,userId:target.user.id,role:'member'}});
  const role=await f.first.auth.api.createOrgRole({headers:f.root.headers,body:{organizationId:org.id,role:'editor',permission:{organization:['update']}}});
  startDelete=()=>{deleting=settled(f.second.auth.api.deleteOrgRole({headers:f.root.headers,body:{organizationId:org.id,roleId:role.roleData.id}}))};
  await f.first.auth.api.updateMemberRole({headers:f.root.headers,body:{organizationId:org.id,memberId:member.id,role:'editor'}});
  const result=await deleting!;expect(result.status).toBe('rejected');
  if(result.status==='rejected')expect(result.reason).toMatchObject({body:{code:'ROLE_IS_ASSIGNED_TO_MEMBERS'}});
  expect(await f.first.auth.api.getOrgRole({headers:f.root.headers,query:{organizationId:org.id,roleId:role.roleData.id}})).toHaveProperty('role','editor');
 });

 it(`rolls back the losing invitation claim when concurrent acceptances exceed the member cap on ${backend}`,async()=>{
  const f=await fixture(backend,{membershipLimit:2,organizationHooks:{beforeAddMember:async()=>{await delay(40)}}});
  const org=await f.createOrg();const users=await Promise.all(['invite-a@concurrency.example','invite-b@concurrency.example'].map(email=>f.signup(email)));
  const invitations:{id:string}[]=[];
  for(const user of users){
   await (await f.first.auth.$context).internalAdapter.updateUser(user.user.id,{emailVerified:true});
   invitations.push(await f.first.auth.api.createInvitation({headers:f.root.headers,body:{organizationId:org.id,email:user.user.email,role:'member'}}));
  }
  const results=await Promise.allSettled([f.first,f.second].map((ready,index)=>ready.auth.api.acceptInvitation({headers:users[index].headers,body:{invitationId:invitations[index].id}})));
  expect(oneWinner(results)).toMatchObject({body:{code:'ORGANIZATION_MEMBERSHIP_LIMIT_REACHED'}});
  expect((await f.first.auth.api.listMembers({headers:f.root.headers,query:{organizationId:org.id}})).total).toBe(2);
  const stored=await f.first.auth.api.listInvitations({headers:f.root.headers,query:{organizationId:org.id}});
  expect(stored.map((invitation:any)=>invitation.status).sort()).toEqual(['accepted','pending']);
 });

 it(`releases the organization barrier after a failed hook on ${backend}`,async()=>{
  const f=await fixture(backend,{organizationLimit:1,organizationHooks:{beforeCreateOrganization:async()=>{await delay(40)},afterCreateOrganization:async(data:any)=>{if(data.organization.slug==='rollback')throw new Error('domain rejected organization')}}});
  const results=await Promise.allSettled([
   f.first.auth.api.createOrganization({headers:f.root.headers,body:{name:'Rejected',slug:'rollback'}}),
   f.second.auth.api.createOrganization({headers:f.root.headers,body:{name:'Retained',slug:'retained'}}),
  ]);
  expect(results[0].status).toBe('rejected');expect(results[1].status).toBe('fulfilled');
  const stored=await f.first.auth.api.listOrganizations({headers:f.root.headers});expect(stored).toHaveLength(1);expect(stored[0].slug).toBe('retained');
 });
}
