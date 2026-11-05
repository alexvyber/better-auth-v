import {describe,it,expect} from 'vitest';
import {getTestInstance,mongoOptions,mongoCommand} from './harness/mongo-fixture.js';
describe('native MongoDB contracts',()=>{
 it('stores ObjectId references, BSON dates and indexed plain session tokens',async()=>{
  const configuration=await mongoOptions();const instance=await getTestInstance({}, {nativeMongo:configuration});
  expect((await mongoCommand({...configuration,database:'admin'},{getParameter:1,ttlMonitorEnabled:1})).ttlMonitorEnabled).toBe(false);
  const {headers}=await instance.signInWithTestUser();const current=await instance.auth.api.getSession({headers});
  expect(current?.user.id).toMatch(/^[0-9a-f]{24}$/);
  const users=await mongoCommand(configuration,{find:'user',filter:{}});
  expect(users.cursor.firstBatch[0]._id.$oid).toBe(current!.user.id);
  expect(users.cursor.firstBatch[0].createdAt.$date).toBeTypeOf('string');
  const sessions=await mongoCommand(configuration,{find:'session',filter:{token:current!.session.token}});
  expect(sessions.cursor.firstBatch[0].userId.$oid).toBe(current!.user.id);
  expect(sessions.cursor.firstBatch[0].expiresAt.$date).toBeTypeOf('string');
  expect((await instance.auth.api.listSessions({headers})).map((s:any)=>s.token)).toContain(current!.session.token);
 });
 it('rolls back a failed signup callback without user or account residue',async()=>{
  const configuration=await mongoOptions();const instance=await getTestInstance({databaseHooks:{session:{create:{before:async()=>{throw new Error('callback failed')}}}}},{nativeMongo:configuration,disableTestUser:true});
  await expect(instance.auth.api.signUpEmail({body:{email:'rollback@example.com',name:'Rollback',password:'password123'}})).rejects.toThrow();
  for(const collection of ['user','account','session'])expect((await mongoCommand(configuration,{count:collection,query:{}})).n).toBe(0);
 });
 it('shares the database rate limiter between independent native clients',async()=>{
  const configuration=await mongoOptions();const options={rateLimit:{enabled:true,storage:'database' as const,max:1,window:60}};
  const instances=await Promise.all([0,1].map(()=>getTestInstance(options,{nativeMongo:configuration,disableTestUser:true})));
  const responses=await Promise.all(instances.map(i=>i.auth.handler(new Request('http://localhost:3000/api/auth/get-session'))));
  expect(responses.map(r=>r.status).sort()).toEqual([200,429]);
 });
});

describe('MongoDB schema and type contracts',()=>{
 it('stores UUID references as subtype 04 and preserves application-owned fields on updates',async()=>{
  const configuration={...await mongoOptions(),uuidIds:true,tables:{user:'auth_users'},fields:{user:{name:'displayName'}}};
  const instance=await getTestInstance({}, {nativeMongo:configuration});const {headers}=await instance.signInWithTestUser();
  const current=await instance.auth.api.getSession({headers});
  const before=(await mongoCommand(configuration,{find:'auth_users',filter:{}})).cursor.firstBatch[0];
  expect(before._id.$binary.subType).toBe('04');
  expect(Buffer.from(before._id.$binary.base64,'base64').toString('hex')).toBe(current!.user.id.replaceAll('-',''));
  await mongoCommand(configuration,{update:'auth_users',updates:[{q:{email:'test@test.com'},u:{$set:{domainState:'retained'}}}]});
  await instance.auth.api.updateUser({headers,body:{name:'Renamed'}});
  const after=(await mongoCommand(configuration,{find:'auth_users',filter:{}})).cursor.firstBatch[0];
  expect(after).toMatchObject({displayName:'Renamed',domainState:'retained'});
 });
 it('preserves custom 24-character string IDs and literal Extended JSON application objects',async()=>{
  const configuration=await mongoOptions();
  const instance=await getTestInstance({advanced:{database:{generateId:()=> '1234567890abcdef12345678'}},user:{additionalFields:{metadata:{type:'json'}}}}, {nativeMongo:configuration});
  const adapter=(await instance.auth.$context).internalAdapter;
  const metadata={$oid:'1234567890abcdef12345678',nested:{$date:'2020-01-01T00:00:00.000Z'}};
  await adapter.updateUser('1234567890abcdef12345678',{metadata});
  const raw=(await mongoCommand(configuration,{find:'user',filter:{}})).cursor.firstBatch[0];
  expect(raw._id).toBe('1234567890abcdef12345678');expect(raw.metadata).toEqual(metadata);
  expect((await adapter.findUserById(raw._id)).metadata).toEqual(metadata);
 });
 it('enforces mapped unique fields while allowing multiple absent values',async()=>{
  const configuration=await mongoOptions();
  const instance=await getTestInstance({user:{additionalFields:{username:{type:'string',unique:true,fieldName:'login'}}}}, {nativeMongo:configuration,disableTestUser:true});
  const adapter=(await instance.auth.$context).internalAdapter;
  await adapter.createUser({email:'a@example.com',name:'A'});await adapter.createUser({email:'b@example.com',name:'B'});
  await adapter.createUser({email:'c@example.com',name:'C',username:'unique'});
  await expect(adapter.createUser({email:'d@example.com',name:'D',username:'unique'})).rejects.toThrow();
  expect((await mongoCommand(configuration,{count:'user',query:{login:'unique'}})).n).toBe(1);
 });
 it('creates the Nabu index set and removes expired BSON session dates through MongoDB TTL',async()=>{
  const configuration=await mongoOptions(true);const instance=await getTestInstance({}, {nativeMongo:configuration});await instance.signInWithTestUser();
  expect((await mongoCommand({...configuration,database:'admin'},{getParameter:1,ttlMonitorEnabled:1})).ttlMonitorEnabled).toBe(true);
  const indexes=(await mongoCommand(configuration,{listIndexes:'session'})).cursor.firstBatch;
  expect(indexes).toEqual(expect.arrayContaining([expect.objectContaining({key:{token:1},unique:true}),expect.objectContaining({key:{expiresAt:1},expireAfterSeconds:0})]));
  expect((await mongoCommand(configuration,{listIndexes:'account'})).cursor.firstBatch).toEqual(expect.arrayContaining([expect.objectContaining({key:{providerId:1,accountId:1},unique:true})]));
  await mongoCommand(configuration,{update:'session',updates:[{q:{},u:[{$set:{expiresAt:{$toDate:0}}}],multi:true}]});
  await expect.poll(async()=>(await mongoCommand(configuration,{count:'session',query:{}})).n,{timeout:10000,interval:250}).toBe(0);
 });
 it('paginates past the first MongoDB cursor batch',async()=>{
  const configuration=await mongoOptions();const instance=await getTestInstance({}, {nativeMongo:configuration,disableTestUser:true});
  const adapter=(await instance.auth.$context).internalAdapter;
  for(let i=0;i<105;i++)await adapter.createVerificationValue({identifier:'cursor:'+i,value:String(i),expiresAt:new Date(Date.now()+60000)});
  // Listing through the native bridge must issue getMore, not truncate at 100.
  const context=await instance.auth.$context;
  const records=await context.adapter.findMany({model:'verification',limit:200});
  expect(records).toHaveLength(105);
 });
});

describe('Nabu existing database indexes',()=>{
 it('reuses the equivalent indexes created by Nabu under different names',async()=>{
  const configuration=await mongoOptions();
  for(const [collection,key,options] of [
   ['user',{email:1},{unique:true}],['session',{token:1},{unique:true}],
   ['session',{expiresAt:1},{expireAfterSeconds:0}],['account',{providerId:1,accountId:1},{unique:true}],
   ['verification',{identifier:1},{}],['rateLimit',{key:1},{unique:true}],
  ] as const){await mongoCommand(configuration,{createIndexes:collection,indexes:[{key,name:Object.keys(key).join('_')+'_1',...options}]})}
  const instance=await getTestInstance({}, {nativeMongo:configuration});const {headers}=await instance.signInWithTestUser();
  expect((await instance.auth.api.getSession({headers}))?.user.email).toBe('test@test.com');
  expect((await mongoCommand(configuration,{listIndexes:'user'})).cursor.firstBatch.filter((i:any)=>i.key.email)).toHaveLength(1);
 });
});
