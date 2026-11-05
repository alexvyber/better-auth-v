import {randomBytes,randomUUID} from 'node:crypto';
import {expect,it,vi} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';
import {getTestInstance as postgresInstance} from '../harness/postgres-fixture.js';
import {getTestInstance as mongoInstance} from '../harness/mongo-fixture.js';

for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
 it(`commits nested raw adapter writes, honors ID/default rules and bypasses application hooks on ${backend}`,async()=>{
  const before=vi.fn(async()=>{throw new Error('Application creation hook must not run for raw adapter writes')});
  const after=vi.fn(async()=>{});const fallback=vi.fn(()=> 'database-default');
  const ready=await factory({user:{additionalFields:{label:{type:'string',defaultValue:fallback}}},databaseHooks:{user:{create:{before,after}}}},{disableTestUser:true});
  const adapter=(await ready.auth.$context).adapter;
  const id=backend==='mongo'?randomBytes(12).toString('hex'):randomUUID();
  const value=await adapter.transaction(async tx=>{
   const created=await tx.create({model:'user',data:{id,name:'Raw created',email:'raw@example.com'},forceAllowId:true});
   expect(created).toMatchObject({id,label:'database-default'});
   await tx.transaction(async nested=>{
    const generated=await nested.create({model:'user',data:{id:'ignored-id',name:'Generated',email:'generated@example.com',label:'explicit'}});
    expect(generated.id).not.toBe('ignored-id');
    const filtered=await nested.findMany({model:'user',where:[{field:'email',value:'raw@example.com'}]});expect(filtered).toHaveLength(1);expect(filtered[0]).toMatchObject({id});
   });
   return {id,committed:true};
  });
  expect(value).toEqual({id,committed:true});expect(await adapter.findMany({model:'user'})).toHaveLength(2);
  expect(before).not.toHaveBeenCalled();expect(after).not.toHaveBeenCalled();expect(fallback).toHaveBeenCalledTimes(1);
 });

 it(`rolls back successful nested writes when the outer transaction rejects and preserves its error on ${backend}`,async()=>{
  const ready=await factory({}, {disableTestUser:true});const adapter=(await ready.auth.$context).adapter;
  const failure=new Error('outer transaction rejection');
  await expect(adapter.transaction(async tx=>{
   await tx.transaction(async nested=>{
    await nested.create({model:'user',data:{name:'Rollback',email:'rollback@adapter.example'}});
    expect(await nested.findMany({model:'user'})).toHaveLength(1);
   });
   throw failure;
  })).rejects.toBe(failure);
  expect(await adapter.findMany({model:'user'})).toEqual([]);
  // A failed operation must release the transaction and connection for later use.
  await adapter.transaction(async tx=>{await tx.create({model:'user',data:{name:'Recovered',email:'recovered@adapter.example'}})});
  expect(await adapter.findMany({model:'user'})).toHaveLength(1);
 });

 it(`opens independent atomic transactions in after-commit hooks on ${backend}`,async()=>{
  let adapter:Awaited<Awaited<ReturnType<typeof getTestInstance>>['auth']['$context']>['adapter'];
  const failure=new Error('after-commit rollback');
  const after=vi.fn(async()=>{
   await adapter.transaction(async tx=>{await tx.create({model:'user',data:{name:'Committed effect',email:'committed-effect@adapter.example'}})});
   await expect(adapter.transaction(async tx=>{
    await tx.create({model:'user',data:{name:'Rolled back effect',email:'failed-effect@adapter.example'}});
    throw failure;
   })).rejects.toBe(failure);
  });
  const ready=await factory({databaseHooks:{user:{create:{after}}}},{disableTestUser:true});
  const context=await ready.auth.$context;adapter=context.adapter;
  await adapter.transaction(async()=>{await context.internalAdapter.createUser({name:'Outer user',email:'outer@adapter.example'},{method:'test'})});
  const users=await adapter.findMany<{email:string}>({model:'user'});
  expect(users.map(user=>user.email).sort()).toEqual(['committed-effect@adapter.example','outer@adapter.example']);
  expect(after).toHaveBeenCalledTimes(1);
 });
}
