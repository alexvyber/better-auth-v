import {getTestInstance as nativeInstance,postgresOptions} from './postgres-fixture.js';
export const getTestInstance: typeof nativeInstance = async (options = {} as any, config = {} as any) => {
 const configuration = await postgresOptions();
 return nativeInstance(options,{...config,nativePostgres:{...configuration,uuidIds:false}}) as any;
};
