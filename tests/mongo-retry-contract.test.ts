import {expect,it,vi} from 'vitest';
import {getTestInstance,mongoOptions,mongoCommand} from './harness/mongo-fixture.js';
import {mongoErrorMetadata} from './harness/bridge.js';

async function fixture(){
 const storage=await mongoOptions();const after=vi.fn(async()=>{});
 const ready=await getTestInstance({databaseHooks:{user:{create:{after}}}},{nativeMongo:storage,disableTestUser:true});
 const context=await ready.auth.$context;
 const fault=async(commands:string[],code:number,labels:string[],times=1)=>mongoCommand({...storage,database:'admin'},{configureFailPoint:'failCommand',mode:{times},data:{failCommands:commands,errorCode:code,errorLabels:labels,appName:'better-auth-v'}});
 const clear=async()=>mongoCommand({...storage,database:'admin'},{configureFailPoint:'failCommand',mode:'off'});
 const stats=async()=>JSON.parse((await ready.bridge.send('mongo-transaction-stats')).value_json) as {commits:number;aborts:number;lastAbortCode:number;lastAbortRetryable:boolean};
 const inactive=async()=>(await mongoCommand({...storage,database:'admin'},{serverStatus:1})).transactions.currentInactive;
 return {ready,context,after,fault,clear,stats,inactive};
}

it('replays a transient body after rolling back partial writes and discards failed-attempt after hooks',async()=>{
 const f=await fixture();let armed=false;
 const body=vi.fn(async()=>{
  const first=await f.context.internalAdapter.createUser({email:'first@retry.example',name:'First'},{method:'test'});
  if(!armed){armed=true;await f.fault(['insert'],112,['TransientTransactionError'])}
  const second=await f.context.internalAdapter.createUser({email:'second@retry.example',name:'Second'},{method:'test'});
  return [first.id,second.id];
 });
 try{
  const ids=await f.context.adapter.transaction(body);
  expect(body).toHaveBeenCalledTimes(2);expect(f.after).toHaveBeenCalledTimes(2);
  const users=await f.context.adapter.findMany<{id:string}>({model:'user'});
  expect(users.map(user=>user.id).sort()).toEqual((ids as string[]).sort());
 }finally{await f.clear()}
});

it('retries unknown commit results without replaying a successful body',async()=>{
 const f=await fixture();const before=await f.stats();
 const body=vi.fn(async()=>f.context.internalAdapter.createUser({email:'unknown@retry.example',name:'Unknown commit'},{method:'test'}));
 try{
  await f.fault(['commitTransaction'],91,['UnknownTransactionCommitResult'],2);
  await f.context.adapter.transaction(body);const after=await f.stats();
  expect(after.commits-before.commits).toBe(3);expect(body).toHaveBeenCalledTimes(1);expect(f.after).toHaveBeenCalledTimes(1);
  expect(await f.context.adapter.findMany({model:'user'})).toHaveLength(1);
 }finally{await f.clear()}
});

it('replays the body after a transient commit failure and runs committed hooks once',async()=>{
 const f=await fixture();
 const body=vi.fn(async()=>f.context.internalAdapter.createUser({email:'commit@retry.example',name:'Transient commit'},{method:'test'}));
 try{
  await f.fault(['commitTransaction'],112,['TransientTransactionError']);
  await f.context.adapter.transaction(body);
  expect(body).toHaveBeenCalledTimes(2);expect(f.after).toHaveBeenCalledTimes(1);
  expect(await f.context.adapter.findMany({model:'user'})).toHaveLength(1);
 }finally{await f.clear()}
});

it('aborts a terminal failed commit on the server and preserves its error before recovery',async()=>{
 const f=await fixture();const before=await f.stats();
 try{
  await f.fault(['commitTransaction'],2,[]);
  let failure:unknown;
  try{await f.context.adapter.transaction(async()=>f.context.internalAdapter.createUser({email:'terminal@retry.example',name:'Terminal commit'},{method:'test'}))}catch(error){failure=error}
  expect(mongoErrorMetadata(failure)?.code).toBe(2);
  const stats=await f.stats();expect(stats.aborts-before.aborts).toBe(1);expect(stats.lastAbortCode).toBe(0);expect(f.after).not.toHaveBeenCalled();expect(await f.inactive()).toBe(0);
  expect(await f.context.adapter.findMany({model:'user'})).toEqual([]);
  await f.context.adapter.transaction(async tx=>{await tx.create({model:'user',data:{email:'recovered@retry.example',name:'Recovered'}})});
  expect(await f.context.adapter.findMany({model:'user'})).toHaveLength(1);
 }finally{await f.clear()}
});

it('retries a retryable raw abort once without replacing the terminal commit error',async()=>{
 const f=await fixture();const before=await f.stats();
 try{
  await f.fault(['commitTransaction','abortTransaction'],50,['RetryableWriteError'],3);
  let failure:unknown;
  try{await f.context.adapter.transaction(async tx=>{await tx.create({model:'user',data:{email:'abort@retry.example',name:'Abort retry'}})})}catch(error){failure=error}
  expect(mongoErrorMetadata(failure)?.code).toBe(50);
  const after=await f.stats();expect(after.commits-before.commits).toBe(2);expect(after.aborts-before.aborts,JSON.stringify(after)).toBe(2);
  expect(after.lastAbortCode).toBe(0);expect(await f.inactive()).toBe(0);
  expect(await f.context.adapter.findMany({model:'user'})).toEqual([]);
 }finally{await f.clear()}
});

it('keeps the primary commit failure when best-effort abort fails and recovers for later transactions',async()=>{
 const f=await fixture();
 try{
  await f.fault(['commitTransaction','abortTransaction'],2,[],2);
  let failure:unknown;
  try{await f.context.adapter.transaction(async tx=>{await tx.create({model:'user',data:{email:'cleanup@retry.example',name:'Cleanup failure'}})})}catch(error){failure=error}
  expect(mongoErrorMetadata(failure)?.code).toBe(2);expect((await f.stats()).lastAbortCode).toBe(2);expect(f.after).not.toHaveBeenCalled();
  await f.clear();
  await f.context.adapter.transaction(async tx=>{await tx.create({model:'user',data:{email:'after-cleanup@retry.example',name:'Recovered'}})});
  expect(await f.context.adapter.findMany({model:'user'})).toHaveLength(1);expect(await f.inactive()).toBe(0);
 }finally{await f.clear()}
});

it('does not replay ordinary callback errors and preserves the original JavaScript error identity',async()=>{
 const f=await fixture();const failure=new Error('ordinary callback rejection');
 const body=vi.fn(async()=>{await f.context.internalAdapter.createUser({email:'ordinary@retry.example',name:'Ordinary failure'},{method:'test'});throw failure});
 await expect(f.context.adapter.transaction(body)).rejects.toBe(failure);
 expect(body).toHaveBeenCalledTimes(1);expect(f.after).not.toHaveBeenCalled();expect(await f.context.adapter.findMany({model:'user'})).toEqual([]);
});

it('does not mask a final commit error with an earlier transient callback error',async()=>{
 const f=await fixture();let attempts=0;
 try{
  const body=vi.fn(async()=>{
   attempts++;
   if(attempts===1)await f.fault(['insert'],112,['TransientTransactionError']);
   else await f.fault(['commitTransaction'],2,[]);
   await f.context.internalAdapter.createUser({email:'latest@retry.example',name:'Latest error'},{method:'test'});
  });
  let failure:unknown;try{await f.context.adapter.transaction(body)}catch(error){failure=error}
  expect(body).toHaveBeenCalledTimes(2);expect(mongoErrorMetadata(failure)?.code).toBe(2);
  expect(f.after).not.toHaveBeenCalled();expect(await f.context.adapter.findMany({model:'user'})).toEqual([]);
 }finally{await f.clear()}
});
