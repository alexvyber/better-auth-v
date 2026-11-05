import {getTestInstance as nativeInstance} from './test-instance.js';
// Upstream create-context defaults skipOriginCheck to true under isTest(). This
// fixture translates that effective test configuration; production V defaults
// remain strict and independent HTTP contracts exercise those defaults.
export function organizationFixture(factory:typeof nativeInstance):typeof nativeInstance {
 return (async(options={} as any,config={} as any)=>{
  const advanced=(options as any).advanced??{};
  return factory({...options,advanced:{...advanced,
   disableOriginCheck:advanced.disableOriginCheck??true,
   disableCSRFCheck:advanced.disableCSRFCheck??(advanced.disableOriginCheck===undefined?true:undefined),
  }},config);
 }) as typeof nativeInstance;
}
export const getTestInstance=organizationFixture(nativeInstance);
