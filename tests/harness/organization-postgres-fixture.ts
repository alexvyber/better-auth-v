import {getTestInstance as postgresInstance,postgresOptions} from './postgres-fixture.js';
import {organizationFixture} from './organization-fixture.js';
// Upstream's trusted beforeCreateInvitation hook supplies a non-UUID identifier.
// Keep UUID organization/user references and explicitly use a text invitation PK.
export const getTestInstance=organizationFixture((async(options={} as any,config={} as any)=>{
 const storage=config.nativePostgres??await postgresOptions();
 return postgresInstance(options,{...config,nativePostgres:{...storage,columnTypes:{...storage.columnTypes,invitation:{...storage.columnTypes?.invitation,id:'text'}}}});
}) as typeof postgresInstance);
