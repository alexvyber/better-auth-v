import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {afterEach,expect,it} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from '../harness/postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from '../harness/mongo-fixture.js';

interface Counter {id:string;remaining:number;count:number;state:string;payload:unknown}
const cleanup:(()=>Promise<unknown>)[]=[];
afterEach(async()=>{for(const close of cleanup.splice(0).reverse())await close()});
async function fixture(backend:string){
 const config:Record<string,any>={disableTestUser:true};let factory=getTestInstance;
 if(backend==='postgres'){
  factory=postgresInstance;const storage=await postgresOptions();config.nativePostgres=storage;
  cleanup.push(()=>postgresSQL(storage,`DROP SCHEMA IF EXISTS "${storage.schema}" CASCADE`));
 }else if(backend==='mongo'){
  factory=mongoInstance;const storage=await mongoOptions();config.nativeMongo=storage;
  cleanup.push(()=>mongoCommand(storage,{dropDatabase:1}));
 }else{
  const root=await mkdtemp(join(tmpdir(),'better-auth-increment-'));config.nativeSqlite=join(root,'auth.sqlite');
  cleanup.push(()=>rm(root,{recursive:true,force:true}));
 }
 const options:Parameters<typeof getTestInstance>[0]={
  user:{additionalFields:{credits:{type:'number',defaultValue:0}}},
  plugins:[{id:'counter-models',schema:{counter:{modelName:'mapped_counters',fields:{
   remaining:{type:'number',required:true,defaultValue:2,fieldName:'remaining_uses'},
   count:{type:'number',required:true,defaultValue:0,fieldName:'use_count'},
   state:{type:'string',required:true,defaultValue:'open'},
   payload:{type:'json',required:false},
  }}}}],
 };
 const first=await factory(options,config);cleanup.push(()=>first.bridge.close());
 const second=await factory(options,config);cleanup.push(()=>second.bridge.close());
 const a=(await first.auth.$context).adapter;const b=(await second.auth.$context).adapter;
 const row=await a.create({model:'counter',data:{payload:{'$ne':null,createdAt:'literal'}}}) as Counter;
 return {a,b,row,storage:config.nativeMongo};
}

it('checks the MongoDB guard inside the conditional write after both callers read the old state',async()=>{
 const f=await fixture('mongo');f.a.options.adapterConfig.transaction=false;f.b.options.adapterConfig.transaction=false;
 const admin={...f.storage,database:'admin'};
 try{
  await mongoCommand(admin,{configureFailPoint:'failCommand',mode:{times:2},data:{failCommands:['findAndModify'],blockConnection:true,blockTimeMS:100,appName:'better-auth-v'}});
  const results=await Promise.all([f.a,f.b].map(adapter=>adapter.incrementOne<Counter>({model:'counter',where:[{field:'id',value:f.row.id},{field:'state',value:'open'}],increment:{},set:{state:'claimed'}})));
  expect(results.filter(Boolean)).toHaveLength(1);expect(results.filter(row=>row===null)).toHaveLength(1);
  expect(await f.a.findOne({model:'counter',where:[{field:'id',value:f.row.id}]})).toMatchObject({state:'claimed',count:0});
 }finally{await mongoCommand(admin,{configureFailPoint:'failCommand',mode:'off'})}
});

for(const backend of ['sqlite','postgres','mongo']){
 it(`selects exactly one guarded set winner across independent ${backend} connections`,async()=>{
  const f=await fixture(backend);
  const results=await Promise.all([f.a,f.b].map((adapter,index)=>adapter.transaction(async tx=>{
   const row=await tx.incrementOne<Counter>({model:'counter',where:[{field:'id',value:f.row.id},{field:'state',value:'open'}],increment:{},set:{state:'claimed',payload:{winner:index}}});
   if(row)await delay(60);return row;
  }))) as (Counter|null)[];
  const winners=results.filter((row):row is Counter=>row!==null);expect(winners).toHaveLength(1);
  expect(results.filter(row=>row===null)).toHaveLength(1);
  expect(await f.a.findOne({model:'counter',where:[{field:'id',value:f.row.id}]})).toMatchObject({state:'claimed',payload:winners[0].payload,count:0});
 });

 it(`applies signed deltas and comparison guards without lost updates on ${backend}`,async()=>{
  const f=await fixture(backend);
  const results=await Promise.all(Array.from({length:8},(_,index)=>(index%2?f.a:f.b).incrementOne<Counter>({
   model:'counter',where:[{field:'id',value:f.row.id},{field:'remaining',operator:'gt',value:0}],
   increment:{remaining:-1,count:1},set:{state:'used'},
  })));
  expect(results.filter(Boolean)).toHaveLength(2);
  expect(results.filter(Boolean).map(row=>row!.count).sort()).toEqual([1,2]);
  expect(await f.a.findOne({model:'counter',where:[{field:'id',value:f.row.id}]})).toMatchObject({remaining:0,count:2,state:'used',payload:{'$ne':null,createdAt:'literal'}});
 });

 it(`keeps atomic guards when transactions are disabled on ${backend}`,async()=>{
  const f=await fixture(backend);f.a.options.adapterConfig.transaction=false;f.b.options.adapterConfig.transaction=false;
  const results=await Promise.all(Array.from({length:8},(_,index)=>(index%2?f.a:f.b).incrementOne<Counter>({
   model:'counter',where:[{field:'id',value:f.row.id},{field:'count',operator:'lt',value:2,connector:'OR'},{field:'state',value:'open',connector:'OR'}],
   increment:{count:1},set:{state:'used'},
  })));
  expect(results.filter(Boolean)).toHaveLength(2);
  expect(await f.a.findOne({model:'counter',where:[{field:'id',value:f.row.id}]})).toMatchObject({count:2,state:'used'});
 });

 it(`validates mutations before empty lookups and rolls back atomic writes on ${backend}`,async()=>{
  const f=await fixture(backend);
  for(const mutation of [
   {increment:{state:1}}, {increment:{count:Infinity}}, {increment:[],set:{state:'bad'}},
   {increment:{},set:{id:'changed'}}, {increment:{},set:{state:[]}},
  ])await expect(f.a.incrementOne({model:'counter',where:[{field:'id',value:f.row.id}],...mutation})).rejects.toThrow();
  await expect(f.a.incrementOne({model:'counter',where:[{field:'state',value:'missing'}],increment:{typo:1}})).rejects.toThrow();
  await expect(f.a.incrementOne({model:'counter',where:[{field:'state',value:'missing'}],increment:{},set:{state:[]}})).rejects.toThrow();
  const failure=new Error('rollback the counter');
  await expect(f.a.transaction(async tx=>{
   expect(await tx.incrementOne({model:'counter',where:[{field:'id',value:f.row.id}],increment:{count:3},set:{payload:{'$eq':'literal'}}})).toMatchObject({count:3,payload:{'$eq':'literal'}});
   throw failure;
  })).rejects.toBe(failure);
  expect(await f.b.findOne({model:'counter',where:[{field:'id',value:f.row.id}]})).toMatchObject(f.row);
  expect(await f.a.incrementOne({model:'counter',where:[{field:'id',value:f.row.id}],increment:{count:0}})).toMatchObject(f.row);
  expect(await f.a.incrementOne({model:'counter',where:[{field:'id',value:f.row.id}],increment:{count:1},set:{count:'overridden'}})).toMatchObject({count:1});
 });

 it(`increments user additional fields atomically on ${backend}`,async()=>{
  const f=await fixture(backend);const user=await f.a.create({model:'user',data:{name:'Credits',email:'credits@atomic.example',credits:null}}) as {id:string;credits:null};
  expect(user.credits).toBeNull();
  await Promise.all(Array.from({length:8},(_,index)=>(index%2?f.a:f.b).incrementOne({model:'user',where:[{field:'id',value:user.id}],increment:{credits:1}})));
  expect(await f.a.findOne({model:'user',where:[{field:'id',value:user.id}]})).toMatchObject({credits:8});
 });
}
