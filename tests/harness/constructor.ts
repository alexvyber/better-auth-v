import type {Auth,BetterAuthOptions} from 'better-auth';
import {getTestInstance} from './test-instance.js';
import {memoryAdapter} from './memory-adapter.js';

// Constructor shape for upstream fixtures. Calls lazily initialize the same V
// backend as getTestInstance; no TypeScript server authentication runs here.
export function betterAuth<const O extends BetterAuthOptions>(options:O):Auth<O>{
 let ready:Promise<Awaited<ReturnType<typeof getTestInstance>>>|undefined;
 function instance(){
  return ready??=getTestInstance({...options,
   database:Object.hasOwn(options,'database')?options.database:memoryAdapter({user:[],session:[],account:[],verification:[]}),
   emailAndPassword:options.emailAndPassword??{enabled:false},
  } as any,{disableTestUser:true}) as Promise<Awaited<ReturnType<typeof getTestInstance>>>;
 }
 const api=new Proxy({}, {get(_target,name){
  if(name==='then'||typeof name!=='string')return undefined;
  return async(...args:unknown[])=>{
   const auth=(await instance()).auth;
   const method=auth.api[name];
   if(!Object.hasOwn(auth.api,name)||typeof method!=='function')throw new Error('Unported native constructor API: '+name);
   return (method as (...args:unknown[])=>unknown)(...args);
  };
 }});
 return {options,api,handler:async(request:Request)=>(await instance()).auth.handler(request),get $context(){return instance().then(({auth})=>auth.$context)}} as unknown as Auth<O>;
}
