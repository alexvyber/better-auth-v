import {randomBytes,randomUUID} from 'node:crypto';
import type {Auth} from 'better-auth';
import type {BetterAuthOptions} from '@better-auth/core';
import type {User,Session,Account,Verification} from '@better-auth/core/db';
import type {DBAdapter} from '@better-auth/core/db/adapter';
import {readFileSync} from 'node:fs';
import {deepmerge} from '@better-auth/core/db/adapter';
import {afterEach,beforeEach,describe,it} from 'vitest';
import {getTestInstance} from './test-instance.js';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from './postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from './mongo-fixture.js';

type Models={user:User;session:Session;account:Account;verification:Verification};
type Tuple<M extends keyof Models>=M extends 'user'?[User]:M extends 'verification'?[Verification]:M extends 'session'?[User,Session]:[User,Account];
type InsertRandom=<M extends keyof Models,C extends number=1>(model:M,count?:C)=>Promise<C extends 1?Tuple<M>:Tuple<M>[]>;
const selections=JSON.parse(readFileSync(new URL('../upstream/adapter-suites.imports.json',import.meta.url),'utf8')).files.find((entry:any)=>entry.path.endsWith('/basic.ts'))?.tests as {title:string;selected:boolean}[]|undefined;
type Instance=Awaited<ReturnType<typeof getTestInstance>>;
interface Helpers {
 adapter:DBAdapter;
 generate<M extends keyof Models>(model:M):Promise<Models[M]>;
 insertRandom:InsertRandom;
 sortModels(models:(Record<string,any>&{id:string})[],by?:'id'|'createdAt'):(Record<string,any>&{id:string})[];
 customIdGenerator:()=>string;
 transformGeneratedModel:<T>(data:T)=>T;
 transformIdOutput:(id:string)=>string;
 getAuth():Promise<Auth<{}>>;
 getBetterAuthOptions():BetterAuthOptions;
 modifyBetterAuthOptions(options:BetterAuthOptions,migrate:boolean):Promise<BetterAuthOptions>;
 tryCatch<T>(operation:Promise<T>):Promise<{data:T;error:null}|{data:null;error:unknown}>;
 hardCleanup():Promise<void>;
}
type TestContext={skip(note?:string):never};
type TestEntry=((context:TestContext)=>Promise<void>)|{migrateBetterAuth:BetterAuthOptions;test:(context:TestContext)=>Promise<void>};

// Register upstream's complete shared suites against actual native adapters.
// Each test has its own database; the only JS policy is fixture configuration.
export function createTestSuite(name:string,settings:{defaultBetterAuthOptions?:BetterAuthOptions;alwaysMigrate?:boolean;prefixTests?:string;customIdGenerator?:()=>any},build:(helpers:Helpers,debug?:{showDB?:()=>Promise<void>})=>Record<string,TestEntry>){
 for(const [backend,factory] of [['sqlite',getTestInstance],['postgres',postgresInstance],['mongo',mongoInstance]] as const){
  describe(`upstream shared adapter ${name} on ${backend}`,()=>{
   let options:BetterAuthOptions;
   let config:Record<string,any>;
   let ready:Promise<Instance>|undefined;
   let postgres:Awaited<ReturnType<typeof postgresOptions>>|undefined;
   let mongo:Awaited<ReturnType<typeof mongoOptions>>|undefined;
   const opened:Instance[]=[];
   const instance=()=>ready??=factory(options as any,config).then(value=>{opened.push(value);return value});
   beforeEach(async()=>{
    options=settings.defaultBetterAuthOptions??{};ready=undefined;postgres=undefined;mongo=undefined;
    config={disableTestUser:true};
    if(backend==='postgres'){postgres=await postgresOptions();config.nativePostgres=postgres}
    if(backend==='mongo'){mongo=await mongoOptions();config.nativeMongo=mongo}
   });
   afterEach(async()=>{
    await Promise.all(opened.splice(0).map(value=>value.bridge.close()));
    if(mongo)await mongoCommand(mongo,{dropDatabase:1});
    if(postgres)await postgresSQL(postgres,`DROP SCHEMA IF EXISTS "${postgres.schema}" CASCADE`);
   });
   const adapter=new Proxy({} as Helpers['adapter'],{get(_target,property){
    if(property==='options')return {adapterConfig:{transaction:true,adapterName:'native-'+backend}};
    return async(...args:unknown[])=>{
     const native=(await (await instance()).auth.$context).adapter;
     const operation=native[property as keyof typeof native];
     if(typeof operation!=='function')throw new Error('Unsupported native adapter operation: '+String(property));
     return (operation as (...args:unknown[])=>unknown).apply(native,args);
    };
   }});
   let generated=0;
   const id=()=>backend==='mongo'?randomBytes(12).toString('hex'):randomUUID();
   const generate:Helpers['generate']=async model=>{
    const key=id();const createdAt=new Date(Date.now()-(++generated)*86400000);const updatedAt=new Date();
    if(model==='user')return {id:key,name:'user-'+key,email:'user-'+key+'@email.com',emailVerified:true,image:null,createdAt,updatedAt} as any;
    if(model==='session')return {id:key,userId:id(),token:randomUUID(),createdAt,updatedAt,expiresAt:new Date(Date.now()+60000),ipAddress:'127.0.0.1',userAgent:'Some User Agent'} as any;
    if(model==='account')return {id:key,userId:id(),accountId:randomUUID(),providerId:'test',createdAt,updatedAt,accessToken:randomUUID(),refreshToken:randomUUID(),idToken:randomUUID(),accessTokenExpiresAt:new Date(),refreshTokenExpiresAt:new Date(),scope:'test',password:null} as any;
    return {id:key,identifier:'test:'+randomUUID(),value:randomUUID(),expiresAt:new Date(Date.now()+60000),createdAt,updatedAt} as any;
   };
   const insertRandom:InsertRandom=async(model,count=1 as any)=>{
    const rows:any[]=[];
    for(let i=0;i<count;i++){
     if(model==='user'||model==='verification'){rows.push([await adapter.create({model,data:await generate(model),forceAllowId:true})]);continue}
     const user=await adapter.create<User>({model:'user',data:await generate('user'),forceAllowId:true});
     const related=await adapter.create({model,data:{...await generate(model),userId:user.id},forceAllowId:true});rows.push([user,related]);
    }
    return (count===1?rows[0]:rows) as any;
   };
   const tests=build({
    adapter,generate,insertRandom,customIdGenerator:id,transformGeneratedModel:data=>data,transformIdOutput:value=>value,
    sortModels:(models,by='id')=>models.sort((a,b)=>by==='createdAt'?new Date(a.createdAt).getTime()-new Date(b.createdAt).getTime():a.id.localeCompare(b.id)),
    async getAuth(){return (await instance()).auth as unknown as Auth<{}>},
    getBetterAuthOptions(){return options},
    async modifyBetterAuthOptions(patch,_migrate){
     options=deepmerge(options,patch);ready=undefined;return options;
    },
    async tryCatch(operation){try{return {data:await operation,error:null}}catch(error){return {data:null,error}}},
    async hardCleanup(){
     if(postgres)await postgresSQL(postgres,`DELETE FROM "${postgres.schema}".auth_user`);
     else if(mongo)await mongoCommand(mongo,{delete:'user',deletes:[{q:{},limit:0}]});
     // SQLite uses a fresh in-memory database, discarded with the bridge.
     else if(ready)await (await ready).bridge.close();
    },
   });
   for(const [title,entry] of Object.entries(tests)){
    if(['normal','joins'].includes(name)&&!selections?.some(test=>test.title===title&&test.selected))continue;
    it(title,async()=>{
     if(typeof entry!=='function'){options=deepmerge(options,entry.migrateBetterAuth);ready=undefined}
     await (typeof entry==='function'?entry:entry.test)({skip(){throw new Error('A configured native adapter must execute this upstream test')}});
    });
   }
  });
 }
}
