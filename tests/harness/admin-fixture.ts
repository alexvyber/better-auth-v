import {getTestInstance as nativeInstance} from './test-instance.js';
// Match the upstream test-instance Google provider and implicit linking defaults.
// Native code performs all authentication, account policy and redirect decisions.
export function adminFixture(factory:typeof nativeInstance):typeof nativeInstance {
 return (async(options={} as any,config={} as any)=>factory({...options,
  socialProviders:(options as any).socialProviders??{google:{clientId:'test',clientSecret:'test'}},
  account:{...(options as any).account,accountLinking:{enabled:true,...(options as any).account?.accountLinking}},
 },config)) as typeof nativeInstance;
}
export const getTestInstance=adminFixture(nativeInstance);
