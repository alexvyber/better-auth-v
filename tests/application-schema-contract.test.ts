import {hashPassword} from 'better-auth/crypto';
import {serializeSignedCookie} from 'better-call';
import {createAuthClient} from 'better-auth/client';
import {emailOTPClient,oneTimeTokenClient,organizationClient,twoFactorClient} from 'better-auth/client/plugins';
import {describe,expect,it,vi} from 'vitest';
import {brandMapDatabase,brandMapOptions} from './harness/brand-map-fixture.js';
import {getTestInstance as postgresInstance,postgresSQL,type NativePostgresOptions} from './harness/postgres-fixture.js';
import {getTestInstance as mongoInstance,mongoOptions,mongoCommand} from './harness/mongo-fixture.js';
import {nativeHTTP} from './harness/http-fixture.js';

const secret='application-schema-interop-secret-at-least-32-characters';
const password='existing-application-password';
const owner='019a5100-0000-7000-8000-000000000001';
const recipient='019a5100-0000-7000-8000-000000000002';
const oldToken='existing-upstream-application-session-token';
const sqlString=(value:string)=>"'"+value.replaceAll("'","''")+"'";
const schemaSQL=(storage:NativePostgresOptions,sql:string)=>postgresSQL(storage,`SET search_path TO "${storage.schema}";`+sql);
async function fingerprint(storage:NativePostgresOptions){
 return schemaSQL(storage,`SELECT jsonb_build_object('columns',(SELECT jsonb_agg(to_jsonb(c) ORDER BY table_name,ordinal_position) FROM information_schema.columns c WHERE table_schema=current_schema()),'constraints',(SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace),'indexes',(SELECT jsonb_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE schemaname=current_schema()))::text`);
}
async function existingBrandMap(){
 const storage=await brandMapDatabase();
 const hash=await hashPassword(password);
 await schemaSQL(storage,`INSERT INTO auth_user(id,name,email,email_verified,username,role,curator_rank,curator_application,birth_date) VALUES
 ('${owner}','Existing owner','owner@app.example',true,'existing_owner','user',17,'{"review":{"approved":true}}','1990-01-02 03:04:05.123456+03'),
 ('${recipient}','Existing recipient','recipient@app.example',true,'existing_recipient','user',0,NULL,NULL);
 INSERT INTO auth_account(account_id,provider_id,user_id,password,updated_at) VALUES ('${owner}','credential','${owner}',${sqlString(hash)},now());
 INSERT INTO auth_session(user_id,token,created_at,updated_at,expires_at) VALUES ('${owner}','${oldToken}',now()-interval '2 days',now()-interval '2 days',now()+interval '28 days');`);
 return storage;
}
const cookie=async(token:string)=> (await serializeSignedCookie('better-auth.session_token',token,secret,{path:'/'})).split(';')[0];
const official=(origin:string,headers:Record<string,string>={})=>createAuthClient({baseURL:origin,basePath:'/auth',plugins:[organizationClient({dynamicAccessControl:{enabled:true}}),emailOTPClient(),twoFactorClient(),oneTimeTokenClient()],fetchOptions:{headers:{origin,...headers}}});

describe('Brand Map existing application schema over HTTP',()=>{
 it('reads upstream credentials/cookies, renews across instances and revokes after restart without schema changes',async()=>{
  const storage=await existingBrandMap();const before=await fingerprint(storage);const http=await nativeHTTP();
  const options={...brandMapOptions(),baseURL:http.origin,secret};
  const config={nativePostgres:storage,disableTestUser:true,realPasswords:true,deferMigrations:true};
  const first=await postgresInstance(options,config);http.install(first.auth);
  const client=official(http.origin,{cookie:await cookie(oldToken)});
  const current=await client.getSession();expect(current.error).toBeNull();expect(current.data?.user).toMatchObject({id:owner,email:'owner@app.example',username:'existing_owner',role:'user',curatorApplication:{review:{approved:true}}});
  expect((current.data?.user as any).birthDate).toEqual(new Date('1990-01-02T00:04:05.123Z'));
  expect(current.data?.session.token).toBe(oldToken);
  expect((await official(http.origin,{authorization:'bEaReR '+oldToken}).getSession()).data?.user.id).toBe(owner);
  expect((await official(http.origin,{cookie:(await cookie(oldToken)).replace(oldToken,'tampered-'+oldToken)}).getSession()).data).toBeNull();
  expect(await schemaSQL(storage,`SELECT updated_at>now()-interval '1 minute' FROM auth_session WHERE token='${oldToken}'`)).toBe('t');
  expect(await schemaSQL(storage,'SELECT count(*) FROM jwks')).toBe('1');
  const second=await postgresInstance(options,config);http.install(second.auth);
  expect((await client.getSession()).data?.user.id).toBe(owner);
  const login=await official(http.origin).signIn.email({email:'owner@app.example',password});expect(login.error).toBeNull();expect(login.data?.user.id).toBe(owner);
  await first.bridge.close();
  const restarted=await postgresInstance(options,config);http.install(restarted.auth);
  expect((await client.getSession()).data?.session.token).toBe(oldToken);
  expect((await client.signOut()).error).toBeNull();
  http.install(second.auth);expect((await client.getSession()).data).toBeNull();
  expect(await schemaSQL(storage,'SELECT curator_rank FROM auth_user WHERE id='+sqlString(owner))).toBe('17');
  expect(await fingerprint(storage)).toBe(before);
 });

 it('preserves domain data/protected fields and joins pre-existing organization members and dynamic roles',async()=>{
  const storage=await existingBrandMap();const http=await nativeHTTP();const updated=vi.fn(async()=>{});const invites=vi.fn(async()=>{});
  const ready=await postgresInstance({...brandMapOptions({updated,invite:invites}),baseURL:http.origin,secret},{nativePostgres:storage,disableTestUser:true,realPasswords:true,deferMigrations:true});http.install(ready.auth);
  const headers=new Headers({cookie:await cookie(oldToken)});const client=official(http.origin,{cookie:headers.get('cookie')!});
  const deniedUpdate=await client.updateUser({name:'Spoofed',customerStatus:'blocked',curatorApplication:{spoof:true}} as any);expect(deniedUpdate.error?.status).toBe(400);expect(updated).not.toHaveBeenCalled();
  const changed=await client.updateUser({name:'Renamed',firstName:'Existing'} as any);expect(changed.error).toBeNull();expect(updated).toHaveBeenCalledWith(owner);
  expect((await client.getSession()).data?.user).toMatchObject({name:'Renamed',firstName:'Existing',customerStatus:'active',curatorApplication:{review:{approved:true}}});
  expect(await schemaSQL(storage,'SELECT curator_rank FROM auth_user WHERE id='+sqlString(owner))).toBe('17');
  const created=await ready.auth.api.createOrganization({body:{userId:owner,name:'Existing schema organization',slug:'existing-schema-org'}});
  expect(created).toMatchObject({status:'pending_review',creator_id:owner});
  // Domain provisioning writes the same text permission column as Brand Map.
  await schemaSQL(storage,`INSERT INTO auth_organization_role(organization_id,role,permission) VALUES ('${created.id}','domain-reader','{"product":["read"]}');
   INSERT INTO auth_member(organization_id,user_id,role,created_at) VALUES ('${created.id}','${recipient}','domain-reader',now());`);
  expect((await client.organization.setActive({organizationId:created.id})).error).toBeNull();
  const full=await client.organization.getFullOrganization({query:{organizationId:created.id}});expect(full.error).toBeNull();expect(full.data?.members).toEqual(expect.arrayContaining([expect.objectContaining({userId:recipient,role:'domain-reader',user:expect.objectContaining({email:'recipient@app.example'})})]));
  const readerSession=await (await ready.auth.$context).internalAdapter.createSession(recipient);
  const reader=official(http.origin,{cookie:await cookie(readerSession.token)});
  expect((await reader.organization.hasPermission({organizationId:created.id,permissions:{product:['read']}} as any)).data?.success).toBe(true);
  // Brand Map grants accessControl, while upstream role CRUD requires ac.
  const denied=await client.organization.createRole({organizationId:created.id,role:'elevated',permission:{product:['read']}} as any);expect(denied.error?.status).toBe(403);
  const invited=await client.organization.inviteMember({organizationId:created.id,email:'new@app.example',role:'support'} as any);expect(invited.error).toBeNull();expect(invites).toHaveBeenCalledTimes(1);
  expect(await schemaSQL(storage,`SELECT count(*) FROM auth_invitation WHERE organization_id='${created.id}' AND email='new@app.example'`)).toBe('1');
  const fresh=await postgresInstance({...brandMapOptions(),baseURL:http.origin,secret},{nativePostgres:storage,disableTestUser:true,deferMigrations:true});http.install(fresh.auth);
  expect((await client.getSession()).data?.session).toHaveProperty('activeOrganizationId',created.id);
  expect((await reader.organization.hasPermission({organizationId:created.id,permissions:{product:['read']}} as any)).data?.success).toBe(true);
 });

 it('uses hashed OTP and single-use tokens against the application verification table',async()=>{
  const storage=await existingBrandMap();const http=await nativeHTTP();const delivered=vi.fn(async(_data:any)=>{});
  const ready=await postgresInstance({...brandMapOptions({otp:delivered}),baseURL:http.origin,secret},{nativePostgres:storage,disableTestUser:true,deferMigrations:true});http.install(ready.auth);
  const client=official(http.origin,{cookie:await cookie(oldToken)});
  expect((await client.emailOtp.sendVerificationOtp({email:'owner@app.example',type:'sign-in'})).error).toBeNull();
  const otp=delivered.mock.calls[0]?.[0] as unknown as {otp:string};expect(otp.otp).toMatch(/^\d{6}$/);
  const stored=await schemaSQL(storage,"SELECT value FROM auth_verification WHERE identifier LIKE '%owner@app.example%' LIMIT 1");expect(stored).not.toContain(otp.otp);
  expect((await official(http.origin).signIn.emailOtp({email:'owner@app.example',otp:otp.otp})).data?.user.id).toBe(owner);
  expect((await official(http.origin).signIn.emailOtp({email:'owner@app.example',otp:otp.otp})).error).not.toBeNull();
  const generated=await client.oneTimeToken.generate();expect(generated.error).toBeNull();const token=generated.data!.token;
  expect((await client.oneTimeToken.verify({token})).data?.user.id).toBe(owner);
  expect((await client.oneTimeToken.verify({token})).error).not.toBeNull();
 });
});

describe('Nabu existing application documents over HTTP',()=>{
 it('reads raw ObjectId/BSON rows and upstream cookies, renews, authenticates and revokes across instances',async()=>{
  const storage=await mongoOptions();const http=await nativeHTTP();const id='69a510000000000000000001';const now=Date.now();
  // Same index definitions as Nabu auth.ts, installed before V connects.
  for(const [collection,key,options] of [['user',{email:1},{unique:true}],['session',{token:1},{unique:true}],['session',{expiresAt:1},{expireAfterSeconds:0}],['account',{providerId:1,accountId:1},{unique:true}],['verification',{identifier:1},{}],['rateLimit',{key:1},{unique:true}]] as const)await mongoCommand(storage,{createIndexes:collection,indexes:[{key,name:Object.keys(key).join('_')+'_1',...options}]});
  const date=(milliseconds:number)=>({$toDate:new Date(milliseconds).toISOString()});
  const seed=async(collection:string,q:Record<string,string>,fields:Record<string,unknown>)=>mongoCommand(storage,{update:collection,updates:[{q,upsert:true,u:[{$set:fields}]}]});
  await seed('user',{email:'operator@nabu.example'},{_id:{$toObjectId:id},email:'operator@nabu.example',name:'Provisioned operator',emailVerified:true,createdAt:date(now-3*86400000),updatedAt:date(now-3*86400000),applicationOwned:{access:'retained'}});
  await seed('account',{providerId:'credential',accountId:id},{_id:{$toObjectId:'69a510000000000000000002'},userId:{$toObjectId:id},accountId:id,providerId:'credential',password:await hashPassword(password),createdAt:date(now),updatedAt:date(now)});
  await seed('session',{token:oldToken},{_id:{$toObjectId:'69a510000000000000000003'},userId:{$toObjectId:id},token:oldToken,createdAt:date(now-2*86400000),updatedAt:date(now-2*86400000),expiresAt:date(now+28*86400000)});
  const options={appName:'Nabu',baseURL:http.origin,secret,emailAndPassword:{enabled:true,disableSignUp:true,minPasswordLength:12},session:{expiresIn:30*86400,updateAge:86400},rateLimit:{enabled:true,storage:'database'}};
  const config={nativeMongo:storage,disableTestUser:true,realPasswords:true,deferMigrations:true};
  const first=await mongoInstance(options,config);http.install(first.auth);
  const client=createAuthClient({baseURL:http.origin,fetchOptions:{headers:{origin:http.origin,cookie:await cookie(oldToken)}}});
  const current=await client.getSession();expect(current.error).toBeNull();expect(current.data).not.toBeNull();expect(current.data?.user.id).toBe(id);
  const row=(await mongoCommand(storage,{find:'session',filter:{token:oldToken}})).cursor.firstBatch[0];expect(Date.parse(row.updatedAt.$date)).toBeGreaterThan(now-1000);expect(row.userId.$oid).toBe(id);
  const fresh=createAuthClient({baseURL:http.origin,fetchOptions:{headers:{origin:http.origin}}});
  expect((await fresh.signIn.email({email:'operator@nabu.example',password})).data?.user.id).toBe(id);
  expect((await fresh.signUp.email({email:'outsider@nabu.example',name:'Denied',password})).error?.status).toBe(400);
  const second=await mongoInstance(options,config);http.install(second.auth);await first.bridge.close();
  expect((await client.getSession()).data?.user.id).toBe(id);expect((await client.signOut()).error).toBeNull();
  const restarted=await mongoInstance(options,config);http.install(restarted.auth);expect((await client.getSession()).data).toBeNull();
  expect((await mongoCommand(storage,{find:'user',filter:{email:'operator@nabu.example'}})).cursor.firstBatch[0].applicationOwned).toEqual({access:'retained'});
  expect((await mongoCommand(storage,{listIndexes:'session'})).cursor.firstBatch.filter((index:any)=>index.key.token)).toHaveLength(1);
 });
});
