import {randomBytes,randomUUID} from 'node:crypto';
import type {Auth} from 'better-auth';
import type {BetterAuthOptions} from '@better-auth/core';
import type {User} from '@better-auth/core/db';
import {deepmerge} from '@better-auth/core/db/adapter';
import {afterEach,beforeEach,describe,it} from 'vitest';
import {getTestInstance} from './test-instance.js';
import {getTestInstance as postgresInstance,postgresOptions,postgresSQL} from './postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from './mongo-fixture.js';

type Instance=Awaited<ReturnType<typeof getTestInstance>>;
interface Helpers {
 adapter:Awaited<Instance['auth']['$context']>['adapter'];
 generate(model:'user'):Promise<User>;
 getAuth():Promise<Auth<{}>>;
 getBetterAuthOptions():BetterAuthOptions;
 modifyBetterAuthOptions(options:BetterAuthOptions,migrate:boolean):Promise<void>;
 tryCatch<T>(operation:Promise<T>):Promise<{data:T;error:null}|{data:null;error:unknown}>;
 hardCleanup():Promise<void>;
}
type TestContext={skip(note?:string):never};

// Register upstream's complete shared suites against actual native adapters.
// Each test has its own database; the only JS policy is fixture configuration.
export function createTestSuite(name:string,settings:{defaultBetterAuthOptions?:BetterAuthOptions},build:(helpers:Helpers,debug?:{showDB?:()=>Promise<void>})=>Record<string,(context:TestContext)=>Promise<void>>){
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
   afterEach(async()=>{await Promise.all(opened.splice(0).map(value=>value.bridge.close()))});
   const adapter=new Proxy({} as Helpers['adapter'],{get(_target,property){
    if(property==='options')return {adapterConfig:{transaction:true,adapterName:'native-'+backend}};
    return async(...args:unknown[])=>{
     const native=(await (await instance()).auth.$context).adapter;
     const operation=native[property as keyof typeof native];
     if(typeof operation!=='function')throw new Error('Unsupported native adapter operation: '+String(property));
     return (operation as (...args:unknown[])=>unknown).apply(native,args);
    };
   }});
   const tests=build({
    adapter,
    async generate(model){
     if(model!=='user')throw new Error('Only shared user fixtures are configured');
     return {id:backend==='mongo'?randomBytes(12).toString('hex'):randomUUID(),name:'Adapter conformance user',email:randomUUID()+'@adapter.example',emailVerified:false,image:null,createdAt:new Date(),updatedAt:new Date()};
    },
    async getAuth(){return (await instance()).auth as unknown as Auth<{}>},
    getBetterAuthOptions(){return options},
    async modifyBetterAuthOptions(patch,_migrate){
     options=deepmerge(options,patch);ready=undefined;
    },
    async tryCatch(operation){try{return {data:await operation,error:null}}catch(error){return {data:null,error}}},
    async hardCleanup(){
     if(postgres)await postgresSQL(postgres,`DELETE FROM "${postgres.schema}".auth_user`);
     else if(mongo)await mongoCommand(mongo,{delete:'user',deletes:[{q:{},limit:0}]});
     // SQLite uses a fresh in-memory database, discarded with the bridge.
     else if(ready)await (await ready).bridge.close();
    },
   });
   for(const [title,test] of Object.entries(tests))it(title,async()=>test({skip(){throw new Error('A configured native adapter must execute this upstream test')}}));
  });
 }
}
