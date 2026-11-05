import type {BetterAuthOptions as CoreOptions} from '@better-auth/core';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {afterAll} from 'vitest';
import {DatabaseSync} from './native-auth.js';
import {getTestInstance} from './test-instance.js';
export {DatabaseSync};
export type BetterAuthOptions = Omit<CoreOptions, 'database'> & {database?: DatabaseSync};
const instances = new WeakMap<object, ReturnType<typeof getTestInstance>>();
const databases = new WeakMap<DatabaseSync,{path:string;migrated:boolean}>();
const roots = new Set<string>();
// Describe-scoped native bridges close before this file's outer teardown.
afterAll(()=>{for(const root of roots)rmSync(root,{recursive:true,force:true})});
function database(options:BetterAuthOptions){
 if(!(options.database instanceof DatabaseSync))throw new Error('Expected native SQLite descriptor');
 let state=databases.get(options.database);
 if(!state){const root=mkdtempSync(join(tmpdir(),'better-auth-v-verification-'));roots.add(root);state={path:join(root,'auth.sqlite'),migrated:false};databases.set(options.database,state)}
 return state;
}
function instance(options:BetterAuthOptions){
 const state=database(options);
 const {database:_database,...configuration}=options;
 const ready=getTestInstance(configuration,{disableTestUser:true,deferMigrations:true,nativeSqlite:state.path});
 instances.set(options,ready);return ready;
}
export async function getMigrations(options: BetterAuthOptions) {
 const state=database(options);const ready=instances.get(options)??instance(options);
 return {async runMigrations() {await (await ready).bridge.send('migrate');state.migrated=true}};
}
export async function init(options: BetterAuthOptions) {
 let ready=instances.get(options);
 if(!ready){
  if(!database(options).migrated)throw new Error('Native migrations must initialize the fixture first');
  // Same descriptor, separate V auth instance/configuration, shared actual SQL rows.
  ready=instance(options);
 }
 return (await ready).auth.$context;
}
