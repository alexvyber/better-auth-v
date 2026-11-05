import {spawn,execFile, type ChildProcess} from 'node:child_process';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {afterAll} from 'vitest';
import {getTestInstance as nativeInstance} from './test-instance.js';
export interface NativeMongoOptions {
 uri:string;database:string;uuidIds?:boolean;stringIds?:boolean;
 tables?:Record<string,string>;fields?:Record<string,Record<string,string>>;
}
const commandBin=fileURLToPath(new URL('../../build/mongo-command',import.meta.url));
export async function mongoCommand(configuration: Pick<NativeMongoOptions,'uri'|'database'>,command:Record<string,unknown>):Promise<any> {
 return new Promise((resolve,reject)=>{
  const child=spawn(commandBin,[],{stdio:'pipe'});let output='';let errors='';
  child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>errors+=chunk);
  child.on('error',reject);child.stdin.on('error',reject);child.on('exit',code=>{if(code!==0)reject(new Error('Native MongoDB command failed: '+errors));else {try{resolve(JSON.parse(output))}catch(error){reject(error)}}});
  child.stdin.end(JSON.stringify({...configuration,command})+'\n');
 });
}
const clusters=new Map<boolean,Promise<{root:string;uri:string;process:ChildProcess}>>();
async function stop(child:ChildProcess){
 if(!child.pid||child.exitCode!==null||child.signalCode!==null)return;
 const exited=once(child,'exit');child.kill('SIGTERM');
 await Promise.race([exited,delay(10000,undefined,{ref:false}).then(()=>{child.kill('SIGKILL')})]);
 await exited;
}
async function start(ttl:boolean){
 const root=await mkdtemp(join(tmpdir(),'better-auth-v-mongo-'));
 const listener=createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');const port=(listener.address() as {port:number}).port;
 await new Promise<void>((resolve,reject)=>listener.close(error=>error?reject(error):resolve()));
 const binary=process.env.BETTER_AUTH_MONGO_BIN??fileURLToPath(new URL('../../build/deps/mongodb-macos-aarch64-8.0.6/bin/mongod',import.meta.url));
 const child=spawn(binary,['--dbpath',root,'--bind_ip','127.0.0.1','--port',String(port),'--replSet','rs0','--wiredTigerCacheSizeGB','0.25','--setParameter','ttlMonitorSleepSecs=1','--setParameter','ttlMonitorEnabled='+String(ttl),'--logpath',join(root,'server.log')],{stdio:'ignore'});
 let spawnError:Error|undefined;child.once('error',error=>{spawnError=error});
 const uri=`mongodb://127.0.0.1:${port}/?directConnection=true&serverSelectionTimeoutMS=500&connectTimeoutMS=500`;
 try{
  let ready=false;
  for(let i=0;i<60;i++){
   if(spawnError)throw spawnError;if(child.exitCode!==null)throw new Error('Temporary mongod exited: '+await readFile(join(root,'server.log'),'utf8'));
   try{await mongoCommand({uri,database:'admin'},{ping:1});ready=true;break}catch{await delay(100)}
  }
  if(!ready)throw new Error('Temporary MongoDB did not start');
  await mongoCommand({uri,database:'admin'},{replSetInitiate:{_id:'rs0',members:[{_id:0,host:`127.0.0.1:${port}`}]}});
  for(let i=0;i<100;i++) {const reply=await mongoCommand({uri,database:'admin'},{hello:1});if(reply.isWritablePrimary)return {root,uri,process:child};await delay(100)}
  throw new Error('Temporary MongoDB did not elect a primary');
 }catch(error){await stop(child);await rm(root,{recursive:true,force:true});throw error}
}
afterAll(async()=>{await Promise.all([...clusters.values()].map(async cluster=>{const running=await cluster.catch(()=>undefined);if(!running)return;try{await stop(running.process)}finally{await rm(running.root,{recursive:true,force:true})}}))});
// Fixed historical clocks in upstream auth tests must not race the real server's
// TTL clock. Indexes remain present; the real TTL contract opts into its own server.
export async function mongoOptions(ttl=false):Promise<NativeMongoOptions>{
 let cluster=clusters.get(ttl);if(!cluster){cluster=start(ttl);clusters.set(ttl,cluster)}
 const running=await cluster;return {uri:running.uri,database:'ba_'+randomUUID().replaceAll('-','')};
}
export const getTestInstance:typeof nativeInstance=async(options={} as any,config={} as any)=>{
 if(Object.hasOwn(options,'database'))throw new Error('MongoDB matrix cannot override an explicit upstream database');
 const mongo=(config as any).nativeMongo??await mongoOptions();const generate=(options as any).advanced?.database?.generateId;
 return nativeInstance(options,{...config,nativeMongo:{...mongo,uuidIds:mongo.uuidIds||generate==='uuid',stringIds:mongo.stringIds||typeof generate==='function',fields:{...mongo.fields,account:{...mongo.fields?.account,...(options as any).account?.fields}}}}) as any;
};
