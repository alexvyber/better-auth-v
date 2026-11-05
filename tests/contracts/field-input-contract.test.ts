import {HttpResponse,http} from 'msw';
import {setupServer} from 'msw/node';
import {signJWT} from 'better-auth/crypto';
import {DEFAULT_SECRET} from '../harness/constants.js';
import type {DBPrimitive} from "@better-auth/core/db";
import {afterAll, beforeAll, describe, expect, it, vi} from 'vitest';
import * as z from 'zod';
import {getTestInstance} from '../harness/test-instance.js';
import {getTestInstance as postgresInstance, postgresOptions, postgresSQL} from '../harness/postgres-fixture.js';
import {memoryAdapter} from '../harness/memory-adapter.js';
const body = (email:string,username?:string) => ({email,name:'Field User',password:'password123',...(username === undefined ? {} : {username})});
const user = {additionalFields:{username:{type:'string',unique:true,required:false,validator:{input:z.string().regex(/^[a-z][a-z0-9_]{2,19}$/,'Invalid username')}},displayUsername:{type:'string',required:false,fieldName:'display_username',validator:{input:z.string().regex(/^[a-z][a-z0-9_]{2,19}$/,'Invalid display username')}}}} as const;

describe('Brand Map input validators', () => {
 it('rejects invalid profile fields before writes and applies validators on updates', async () => {
  const {auth,db} = await getTestInstance({user},{disableTestUser:true});
  await expect(auth.api.signUpEmail({body:body('bad@example.com','invalid!')})).rejects.toMatchObject({statusCode:400,body:{code:'VALIDATION_ERROR',message:'Invalid username'}});
  expect(await db.findMany({model:'user'})).toHaveLength(0);
  const registered = await auth.api.signUpEmail({body:{...body('valid@example.com','valid_name'),displayUsername:'valid_name'}});
  const login = await auth.api.signInEmail({body:{email:'valid@example.com',password:'password123'},returnHeaders:true});
  const headers = new Headers({cookie:login.headers.getSetCookie().map((value:string)=>value.split(';')[0]).join('; ')});
  await expect(auth.api.updateUser({headers,body:{displayUsername:'bad!'}})).rejects.toMatchObject({body:{code:'VALIDATION_ERROR',message:'Invalid display username'}});
  expect((await auth.api.getSession({headers}))?.user.username).toBe(registered.user.username);
 });
 it('runs the validator before a competing transform and retains transformed values', async () => {
  const transform = vi.fn((value:DBPrimitive)=>typeof value === 'string' ? value.toUpperCase() : value);
  const {auth} = await getTestInstance({user:{additionalFields:{username:{type:'string',required:false,validator:{input:z.string().transform(value=>value.toLowerCase())},transform:{input:transform}},label:{type:'string',required:false,transform:{input:(value:DBPrimitive)=>typeof value === 'string' ? value.trim() : value}}}}},{disableTestUser:true});
  const registered = await auth.api.signUpEmail({body:{...body('transform@example.com','UPPER'),label:'  Label  '}});
  expect(registered.user).toMatchObject({username:'upper',label:'Label'});
  expect(transform).not.toHaveBeenCalled();
 });
 it('rejects asynchronous Standard Schema validators without creating a user', async () => {
  const {auth,db} = await getTestInstance({user:{additionalFields:{username:{type:'string',required:false,validator:{input:{'~standard':{version:1,vendor:'test',validate:async (value:unknown)=>({value})}}}}}}},{disableTestUser:true});
  await expect(auth.api.signUpEmail({body:{...body('async@example.com'),username:'valid_name'}})).rejects.toMatchObject({statusCode:500,body:{code:'ASYNC_VALIDATION_NOT_SUPPORTED'}});
  expect(await db.findMany({model:'user'})).toHaveLength(0);
 });
});

for (const backend of ['sqlite','memory'] as const) describe(`${backend} unique user fields`,()=>{
 it('enforces uniqueness on insert/update while allowing absent optional values', async()=>{
  const options = {user,...(backend === 'memory' ? {database:memoryAdapter({user:[],session:[],account:[],verification:[]})} : {})};
  const {auth,db} = await getTestInstance(options,{disableTestUser:true});
  await auth.api.signUpEmail({body:body('first@example.com','unique_name')});
  await expect(auth.api.signUpEmail({body:body('second@example.com','unique_name')})).rejects.toMatchObject({statusCode:500});
  await auth.api.signUpEmail({body:body('absent1@example.com')});
  await auth.api.signUpEmail({body:body('absent2@example.com')});
  const login = await auth.api.signInEmail({body:{email:'absent1@example.com',password:'password123'},returnHeaders:true});
  const headers = new Headers({cookie:login.headers.getSetCookie().map((value:string)=>value.split(';')[0]).join('; ')});
  await expect(auth.api.updateUser({headers,body:{username:'unique_name'}})).rejects.toMatchObject({statusCode:500});
  expect((await db.findMany({model:'user'}))).toHaveLength(3);
 });
});

describe('PostgreSQL mapped unique fields',()=>{
 it('uses fieldName columns and enforces username uniqueness across separate native connections',async()=>{
  const configuration = await postgresOptions();
  const first = await postgresInstance({user},{nativePostgres:configuration,disableTestUser:true});
  const second = await postgresInstance({user},{nativePostgres:configuration,disableTestUser:true});
  const results = await Promise.allSettled([first,second].map((instance,index)=>instance.auth.api.signUpEmail({body:{...body(`concurrent${index}@example.com`,'shared_name'),displayUsername:'display_name'}})));
  expect(results.filter(result=>result.status === 'fulfilled')).toHaveLength(1);
  expect(results.filter(result=>result.status === 'rejected')).toHaveLength(1);
  expect(await postgresSQL(configuration,`SELECT display_username FROM "${configuration.schema}".auth_user LIMIT 1`)).toBe('display_name');
  expect(await postgresSQL(configuration,`SELECT count(*) FROM "${configuration.schema}".auth_user`)).toBe('1');
 });
});


describe('PostgreSQL best-effort linked profiles',()=>{
 it('keeps a new provider binding when a unique profile update is rejected',async()=>{
  const configuration = await postgresOptions();
  const instance = await postgresInstance({
   user,
   account:{accountLinking:{enabled:true,trustedProviders:['google'],updateUserInfoOnLink:true}},
   socialProviders:{google:{clientId:'test',clientSecret:'test',mapProfileToUser:()=>({username:'already_taken'})}},
  },{nativePostgres:configuration,disableTestUser:true});
  const adapter = (await instance.auth.$context).internalAdapter;
  const target = await adapter.createUser({email:'linked-profile@example.com',name:'Original',emailVerified:true,username:'original_name'});
  await adapter.createUser({email:'owner@example.com',name:'Owner',emailVerified:true,username:'already_taken'});
  const headers = new Headers();
  const started = await instance.auth.api.signInSocial({body:{provider:'google',callbackURL:'/done'},asResponse:true});
  instance.cookieSetter(headers)({response:started});
  const url = new URL((await started.json()).url);
  const callback = await instance.auth.handler(new Request('http://localhost:3000/api/auth/callback/google?state='+url.searchParams.get('state')+'&code=test-code',{headers}));
  expect(callback.status).toBe(302);
  expect(callback.headers.get('location')).toBe('/done');
  expect(await adapter.findAccounts(target.id)).toHaveLength(1);
  expect((await adapter.findUserById(target.id)).username).toBe('original_name');
  instance.cookieSetter(headers)({response:callback});
  expect((await instance.auth.api.getSession({headers}))?.user.name).toBe('Original');
 });
});

const provider = setupServer(http.post('https://oauth2.googleapis.com/token',async()=>HttpResponse.json({access_token:'test-token',id_token:await signJWT({sub:'linked-provider-user',email:'linked-profile@example.com',email_verified:true,name:'Provider Name'},DEFAULT_SECRET)})));
beforeAll(()=>provider.listen({onUnhandledRequest:'error'}));
afterAll(()=>provider.close());
