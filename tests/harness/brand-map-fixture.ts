import {readFileSync} from 'node:fs';
import type {DBFieldAttribute} from '@better-auth/core/db';
import {createAccessControl} from 'better-auth/plugins/access';
import {adminAc,userAc} from 'better-auth/plugins/admin/access';
import {openAPI} from 'better-auth/plugins';
import * as z from 'zod';
import {admin,anonymous,bearer,emailOTP,jwt,oneTimeToken,organization,twoFactor} from './plugins.js';
import {getTestInstance,postgresOptions,postgresSQL} from './postgres-fixture.js';

const snapshot=JSON.parse(readFileSync(new URL('../fixtures/brand-map-config.json',import.meta.url),'utf8')) as {
 fields:Record<string,string>;statements:Record<string,string[]>;roles:Record<string,Record<string,string[]>>;
};
export async function brandMapDatabase(){
 const storage=await postgresOptions();
 storage.fields=Object.fromEntries(Object.keys(storage.fields).map(model=>[model,{...snapshot.fields}]));
 storage.fields.jwks={...snapshot.fields};
 await postgresSQL(storage,`CREATE SCHEMA "${storage.schema}"; SET search_path TO "${storage.schema}";`+
  readFileSync(new URL('../fixtures/brand-map-schema.sql',import.meta.url),'utf8'));
 return storage;
}

// Same schema/plugin settings as create-auth.ts. Delivery and domain effects are
// injected callbacks; no application service, environment, or database is loaded.
export function brandMapOptions(effects:{updated?:(id:string)=>Promise<void>;invite?:(data:any)=>Promise<void>;otp?:(data:any)=>Promise<void>}={}){
 const ac=createAccessControl(snapshot.statements);
 const roles=Object.fromEntries(Object.entries(snapshot.roles).map(([name,permissions])=>[name,ac.newRole(permissions)]));
 const fields=snapshot.fields;
 const extra:Record<string,DBFieldAttribute>={};
 for(const [name,fieldName] of Object.entries({bio:'bio',city:'city',cover:'cover',curatorStatus:'curator_status',curatorStatusChangedBy:'curator_status_changed_by',curatorStatusReason:'curator_status_reason',customerStatus:'customer_status',customerType:'customer_type',gender:'gender',patronymic:'patronymic'}))extra[name]={type:'string',required:false,input:false,fieldName};
 for(const [name,fieldName] of Object.entries({curatorApplication:'curator_application',metadata:'metadata',socialLinks:'social_links'}))extra[name]={type:'json',required:false,input:false,fieldName};
 for(const [name,fieldName] of Object.entries({curatorStatusChangedAt:'curator_status_changed_at',lastLoginAt:'last_login_at'}))extra[name]={type:'date',required:false,input:false,fieldName};
 for(const [name,fieldName] of Object.entries({firstName:'first_name',lastName:'last_name',imageMiniature:'image_miniature'}))extra[name]={type:'string',required:false,fieldName};
 // Standard Schema equivalent of the application's Valibot username regex.
 extra.username={type:'string',required:false,unique:true,validator:{input:z.string().regex(/^[A-Za-z0-9_.]{4,64}$/)}};
 extra.displayUsername={type:'string',required:false,fieldName:'display_username',validator:{input:z.string().regex(/^[A-Za-z0-9_.]{4,64}$/)}};
 extra.birthDate={type:'date',required:false,fieldName:'birth_date'};
 extra.twoFactorEnabled={type:'boolean',required:false,input:false,defaultValue:false,fieldName:'two_factor_enabled'};
 return {
  appName:'brand-map',basePath:'/auth',
  user:{modelName:'auth_user',fields,additionalFields:extra},
  session:{modelName:'auth_session',fields,expiresIn:30*86400,updateAge:86400,storeSessionInDatabase:true},
  account:{modelName:'auth_account',fields},verification:{modelName:'auth_verification',fields},
  databaseHooks:{user:{update:{after:async(user:{id:string})=>{await effects.updated?.(user.id)}}}},
  plugins:[openAPI(),bearer(),jwt({jwt:{definePayload:({user})=>({id:user.id,email:user.email,isAnonymous:(user as any).isAnonymous??false,role:(user as any).role,twoFactorEnabled:(user as any).twoFactorEnabled})},schema:{jwks:{fields}}}),
   organization({ac,roles,allowUserToCreateOrganization:false,invitationExpiresIn:48*3600,dynamicAccessControl:{enabled:true},schema:{
    organization:{modelName:'auth_organization',fields,additionalFields:{status:{type:'string',required:false,input:false,defaultValue:'pending_review'},status_reason:{type:'string',required:false,input:false},creator_id:{type:'string',required:false,input:false},reviewed_at:{type:'date',required:false,input:false},reviewed_by:{type:'string',required:false,input:false}}},
    member:{modelName:'auth_member',fields},invitation:{modelName:'auth_invitation',fields},organizationRole:{modelName:'auth_organization_role',fields},
   },organizationHooks:{beforeCreateOrganization:async({organization,user})=>({data:{...organization,creator_id:user.id}})},sendInvitationEmail:async data=>{await effects.invite?.(data)}}),
   anonymous({schema:{user:{fields}}}),
   emailOTP({storeOTP:'hashed',allowedAttempts:5,resendStrategy:'rotate',changeEmail:{enabled:true},sendVerificationOnSignUp:false,async sendVerificationOTP(data){await effects.otp?.(data)}}),
   oneTimeToken(),twoFactor({schema:{twoFactor:{modelName:'auth_two_factor',fields},user:{fields}},otpOptions:{storeOTP:'hashed',async sendOTP(){}}}),
   admin({adminRoles:['platform-admin'],defaultRole:'user',roles:{curator:userAc,'platform-admin':adminAc,user:userAc},schema:{user:{fields},session:{fields}}}),
  ],
 } satisfies Parameters<typeof getTestInstance>[0];
}
