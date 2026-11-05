import {Bridge,transportJSON} from "./bridge.js";
import {nativeTransactionScope} from "./fixture-scopes.js";
import type {FixtureOptions,FixtureInternalAdapter,FixtureTransactionAdapter} from "./fixture-types.js";

export function createFixtureAdapters(bridge:Bridge,callbacks:Record<string,(payload:any)=>unknown>,hydrate:(value:any,modelHint?:string)=>any){
  const internalAdapter = {} as FixtureInternalAdapter;
  const internalNames = ['createVerificationValue', 'findVerificationValue', 'consumeVerificationValue', 'reserveVerificationValue', 'deleteVerificationByIdentifier', 'updateVerificationByIdentifier', 'createSession', 'findSession', 'listSessions', 'updateSession', 'deleteSession', 'deleteUserSessions', 'createUser', 'updateUser', 'findUserById', 'findUserByEmail', 'createAccount', 'findCredentialAccount', 'deleteAccount', 'updateAccount', 'findAccounts', 'updatePassword'];
  for (const name of internalNames) {
    internalAdapter[name] = async (...args: any[]) => {
      const reply = await bridge.send('internal', {method: name, arguments_json: transportJSON(args)});
      return hydrate(JSON.parse(reply.value_json));
    };
    callbacks['internal.' + name] = (args: any[]) => internalAdapter[name](...args);
  }
  const adapter: FixtureTransactionAdapter = {
    async nativeRunWithTransaction<T>(callback: () => Promise<T>): Promise<T> {
      if (bridge.inCallback ? bridge.inNativeTransaction : nativeTransactionScope.getStore()) return callback();
      const method = 'transaction.' + crypto.randomUUID();
      let result: T;
      let cause: unknown;
      let failed = false;
      bridge.setCallback(method, () => nativeTransactionScope.run(true, async () => {
        failed=false;cause=undefined;
        try { result = await callback(); return null; }
        catch (error) { failed = true; cause = error; throw error; }
      }));
      try { await bridge.send('transaction', {method}); }
      catch (error) { throw failed ? cause : error; }
      finally { bridge.removeCallback(method); }
      return result!;
    },
    async create<I,O>(query:{model:string;data:I;forceAllowId?:boolean}):Promise<O>{
      if(query.model==='jwks'){
       const reply=await bridge.send('internal',{method:'adapterCreateJWK',arguments_json:transportJSON([query.data])});return hydrate(JSON.parse(reply.value_json));
      }
      return adapterQuery('create',query);
    },
    async findMany<T>(query:FixtureOptions):Promise<T[]>{
      if(query.model==='jwks'){
       const reply=await bridge.send('internal',{method:'jwkLookup',arguments_json:transportJSON(['getAllKeys','',''])});return hydrate(JSON.parse(reply.value_json));
      }
      return adapterQuery('findMany',query);
    },
    async findOne<T>(query:FixtureOptions):Promise<T|null>{
      if(!query.join&&['organization','member','invitation','organizationRole'].includes(query.model)){
       const reply=await bridge.send('internal',{method:'adapterFindOne',arguments_json:transportJSON([query])});return hydrate(JSON.parse(reply.value_json));
      }
      return adapterQuery('findOne',query);
    },
    async update<T>(query:FixtureOptions):Promise<T|null>{
      if(['organization','member','invitation','organizationRole'].includes(query.model)&&query.where?.length===1&&query.where[0].field==='id'&&(!query.where[0].operator||query.where[0].operator==='eq')){
       const reply=await bridge.send('internal',{method:'adapterUpdateOrganizationModel',arguments_json:transportJSON([query.model,query.where[0].value,query.update])});return hydrate(JSON.parse(reply.value_json));
      }
      return adapterQuery('update',query);
    },
    async updateMany(query){return adapterQuery('updateMany',query)},
    async delete(query){await adapterQuery('delete',query)},
    async deleteMany(query){return adapterQuery('deleteMany',query)},
    async count(query){return adapterQuery('count',query)},
    async incrementOne<T>(query:FixtureOptions):Promise<T|null>{
     return adapter.nativeRunWithTransaction(()=>adapterQuery<T>('incrementOne',query));
    },
    options: {adapterConfig: {transaction: true}},
    async transaction(callback): Promise<unknown> { return adapter.nativeRunWithTransaction(()=>callback(adapter)); },
  };
  async function adapterQuery<T=any>(operation:string,query:FixtureOptions):Promise<T>{
    const reply=await bridge.send('internal',{method:'adapterQuery',arguments_json:transportJSON([operation,query])});
    return hydrate(JSON.parse(reply.value_json),query.model);
  }
  bridge.setTransactionsProvider(() => adapter.options.adapterConfig.transaction !== false);
  return {adapter,internalAdapter};
}
