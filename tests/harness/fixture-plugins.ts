import type {BetterAuthOptions} from '@better-auth/core';
import type {FixtureOptions,ServerOptions} from './fixture-types.js';
import {assertKeys} from './fixture-validation.js';
import {schemaPluginOptions} from './plugins.js';
import {endpointSchema} from './endpoint-schema.js';
import {nativeEndpoint,freshSessionMiddleware,nativeOriginSelector} from './endpoint.js';
import {transportJSON} from './bridge.js';

export function parseFixturePlugins(options:ServerOptions,config:FixtureOptions,getContext:()=>FixtureOptions,hydrate:(value:any,modelHint?:string)=>any){
  let magicLinkOptions: FixtureOptions | undefined;
  let twoFactorOptions: FixtureOptions | undefined;
  let anonymousOptions: FixtureOptions | undefined;
  let otpOptions: FixtureOptions | undefined;
  let ottOptions: FixtureOptions | undefined;
  let jwtOptions: FixtureOptions | undefined;
  let adminOptions: FixtureOptions | undefined;
  let organizationOptions: FixtureOptions | undefined;
  let openAPIOptions:FixtureOptions|undefined;
  const genericProviders: FixtureOptions[] = [];
  const logoutProviders: FixtureOptions[] = [];
  const requestHooks: Array<(request: Request, context: FixtureOptions) => unknown> = [];
  const skippedOriginPaths: string[] = [];
  const initializers: Array<(context: FixtureOptions) => unknown> = [];
  const originSources: NonNullable<BetterAuthOptions['trustedOrigins']>[] = [];
  if (options.trustedOrigins) originSources.push(options.trustedOrigins);
  const endpointPlugins: FixtureOptions[] = [];
  const endpointCallbacks: Record<string, (payload: any) => Promise<unknown>> = {};
  const adapterModels:Record<string,{modelName?:string;fields:Record<string,FixtureOptions>}>={};
  for (const plugin of options.plugins ?? []) {
    // Shared DB suites consume schemas independently of plugin HTTP behavior.
    if(config.adapterSchemaOnly&&plugin.schema){
     for(const [model,definition] of Object.entries(plugin.schema) as [string,any][]){
      if(['user','session','account','verification','jwks','rateLimit','twoFactor','organization','member','invitation','organizationRole'].includes(model))continue;
      if(adapterModels[model])throw new Error('Duplicate adapter model: '+model);
      adapterModels[model]={modelName:definition.modelName,fields:definition.fields??{}};
     }
     continue;
    }
    if (plugin.id === 'magic-link') {
      magicLinkOptions = schemaPluginOptions(plugin);
      if (!magicLinkOptions) throw new Error('Magic link requires a native fixture descriptor');
      assertKeys(magicLinkOptions, ['sendMagicLink'], 'magicLink');
      continue;
    }
    if (plugin.id === 'two-factor') {
      twoFactorOptions = schemaPluginOptions(plugin);
      if (!twoFactorOptions) throw new Error('Two factor requires a native fixture descriptor');
      assertKeys(twoFactorOptions, ['twoFactorTable', 'issuer', 'totpOptions', 'otpOptions', 'backupCodeOptions', 'skipVerificationOnEnable', 'allowPasswordless', 'twoFactorCookieMaxAge', 'trustDeviceMaxAge', 'accountLockout', 'schema'], 'twoFactor');
      continue;
    }
    if (plugin.id === 'anonymous') {
      anonymousOptions = schemaPluginOptions(plugin);
      if (!anonymousOptions) throw new Error('Anonymous requires a native fixture descriptor');
      assertKeys(anonymousOptions, ['emailDomainName', 'disableDeleteAnonymousUser', 'generateName', 'generateRandomEmail', 'onLinkAccount', 'schema'], 'anonymous');
      continue;
    }
    if(plugin.id==='open-api'){openAPIOptions=plugin.options??{};assertKeys(openAPIOptions,['path','disableDefaultReference','theme','nonce'],'openAPI');continue;}
    if (plugin.id === 'bearer') { continue; }
    if (plugin.id === 'email-otp') {
      otpOptions = schemaPluginOptions(plugin);
      if (!otpOptions) throw new Error('Email OTP requires a native fixture descriptor');
      assertKeys(otpOptions, ['sendVerificationOTP', 'generateOTP', 'otpLength', 'expiresIn', 'allowedAttempts', 'storeOTP', 'sendVerificationOnSignUp', 'disableSignUp', 'resendStrategy', 'changeEmail', 'overrideDefaultEmailVerification', 'rateLimit'], 'emailOTP');
      continue;
    }
    if (plugin.id === 'one-time-token') {
      ottOptions = schemaPluginOptions(plugin);
      if (!ottOptions) throw new Error('One-time-token requires a native fixture descriptor');
      assertKeys(ottOptions, ['expiresIn', 'disableClientRequest', 'disableSetSessionCookie', 'setOttHeaderOnNewSession', 'storeToken', 'generateToken'], 'oneTimeToken');
      continue;
    }
    if (plugin.id === 'generic-oauth') {
      const input = schemaPluginOptions(plugin);
      if (!input) throw new Error('Generic OAuth needs its native fixture descriptor');
      assertKeys(input, ['config'], 'genericOAuth');
      for (const provider of input.config) {
        assertKeys(provider, ['providerId', 'name', 'clientId', 'clientSecret', 'discoveryUrl', 'discoveryHeaders', 'authorizationUrl', 'tokenUrl', 'userInfoUrl', 'endSessionEndpoint', 'disableProviderLogout', 'postLogoutRedirectURI', 'redirectURI', 'pkce', 'requireIdTokenVerification', 'disableIdTokenNonceBinding', 'disableSignUp', 'disableImplicitSignUp', 'authentication', 'tokenEndpointAuth', 'authorizationUrlParams', 'tokenUrlParams', 'authorizationHeaders', 'scopes', 'prompt', 'accessType', 'responseType', 'responseMode', 'mapProfileToUser', 'getToken'], 'genericOAuth.config');
        if (provider.discoveryUrl || provider.authorizationUrl) genericProviders.push(provider);
        logoutProviders.push({providerId: provider.providerId, clientId: provider.clientId, endSessionEndpoint: provider.endSessionEndpoint ?? '', disableProviderLogout: provider.disableProviderLogout ?? false, postLogoutRedirectURI: provider.postLogoutRedirectURI ?? ''});
      }
      continue;
    }
    if (plugin.id === 'admin' || plugin.id === 'organization') {
      const input = schemaPluginOptions(plugin);
      if (!input) throw new Error(`Native schema plugin ${plugin.id} requires its fixture descriptor`);
      if (plugin.id === 'admin') {
        assertKeys(input, ['defaultRole','adminRoles','adminUserIds','roles','ac','defaultBanReason','defaultBanExpiresIn','bannedUserMessage','schema','allowImpersonatingAdmins','impersonationSessionDuration'], 'admin');
        assertKeys(input.dynamicAccessControl??{},['enabled','maximumRolesPerOrganization'],'organization.dynamicAccessControl');
        if(typeof input.dynamicAccessControl?.maximumRolesPerOrganization==='function')throw new Error('Dynamic role limit callbacks remain unported');
        assertKeys(input.schema??{},['user','session'],'admin.schema');
        for(const value of Object.values(input.schema??{}) as any[]){assertKeys(value,['fields','modelName'],'admin.schema.model');for(const name of Object.values(value.fields??{})){if(typeof name!=='string')throw new Error('Admin schema field aliases must be strings');}}
        for(const role of Object.values(input.roles ?? {}) as any[]) {if(!role?.statements)throw new Error('Native admin roles require explicit permission statements');}
        adminOptions = input;
      } else {
        assertKeys(input, ['teams','allowUserToCreateOrganization','organizationLimit','membershipLimit','creatorRole','disableOrganizationDeletion','roles','ac','schema','organizationHooks','sendInvitationEmail','invitationExpiresIn','invitationLimit','cancelPendingInvitationsOnReInvite','requireEmailVerificationOnInvitation','dynamicAccessControl'], 'organization');
        if(typeof input.organizationLimit==='function'||typeof input.membershipLimit==='function')throw new Error('Dynamic organization limits remain unported');
        assertKeys(input.dynamicAccessControl??{},['enabled','maximumRolesPerOrganization'],'organization.dynamicAccessControl');
        if(typeof input.dynamicAccessControl?.maximumRolesPerOrganization==='function')throw new Error('Dynamic role limit callbacks remain unported');
        assertKeys(input.schema??{},['organization','member','invitation','session','organizationRole'],'organization.schema');
        for(const model of Object.values(input.schema??{}) as any[]){assertKeys(model,['modelName','fields','additionalFields'],'organization.schema.model');}
        assertKeys(input.organizationHooks??{},['beforeCreateOrganization','afterCreateOrganization','beforeAddMember','afterAddMember','beforeUpdateOrganization','afterUpdateOrganization','beforeDeleteOrganization','afterDeleteOrganization','beforeCreateInvitation','afterCreateInvitation','beforeAcceptInvitation','afterAcceptInvitation','beforeRejectInvitation','afterRejectInvitation','beforeCancelInvitation','afterCancelInvitation','beforeUpdateMemberRole','afterUpdateMemberRole','beforeRemoveMember','afterRemoveMember'],'organization.hooks');
        for(const role of Object.values(input.roles??{}) as any[]){if(!role?.statements)throw new Error('Native organization roles require explicit permission statements');}
        if(input.teams?.enabled&&Object.keys(input).some(key=>key!=='teams'))throw new Error('Organization teams currently supply schema only');
        assertKeys(input.teams ?? {}, ['enabled'], 'organization.teams');
        organizationOptions = input;
      }
      continue;
    }
    if (plugin.id !== 'jwt') {
      if (plugin.onRequest) requestHooks.push(plugin.onRequest.bind(plugin) as (request: Request, context: FixtureOptions) => unknown);
      if (plugin.init) initializers.push(plugin.init.bind(plugin) as (context: FixtureOptions) => unknown);
      assertKeys(plugin, ['id', 'endpoints', 'init', 'onRequest','schema'], `plugin.${plugin.id}`);
      for(const [model,definition] of Object.entries(plugin.schema??{}) as [string,any][]){
       assertKeys(definition,['modelName','fields'],`plugin.${plugin.id}.schema.${model}`);
       if(['user','session','account','verification','jwks','rateLimit','twoFactor','organization','member','invitation','organizationRole'].includes(model))throw new Error('Generic plugin core-model extensions require their native plugin');
       if(adapterModels[model])throw new Error('Duplicate adapter model: '+model);
       for(const field of Object.values(definition.fields??{}) as FixtureOptions[]){
        assertKeys(field,['type','required','input','returned','defaultValue','fieldName','unique','references','validator','transform'],'adapter field');
        assertKeys(field.references??{},['field','model'],'adapter reference');
       }
       adapterModels[model]={modelName:definition.modelName,fields:definition.fields??{}};
      }
      const routes: FixtureOptions[] = [];
      for (const [name, endpoint] of Object.entries(plugin.endpoints ?? {})) {
        const descriptor = nativeEndpoint(endpoint);
        if (!descriptor) throw new Error(`Plugin endpoint ${plugin.id}.${name} needs a native fixture descriptor`);
        assertKeys(descriptor.options, ['method', 'use', 'query','body','metadata'], `plugin.${plugin.id}.${name}`);
        assertKeys(descriptor.options.metadata??{},['openapi','scope'],'endpoint.metadata');
        const use = descriptor.options.use ?? [];
        if (use.some(middleware => middleware !== freshSessionMiddleware && !nativeOriginSelector(middleware))) throw new Error('Unsupported native middleware descriptor');
        const method = descriptor.options.method ?? 'GET';
        if (typeof method !== 'string') throw new Error('Endpoint method arrays are not bridged yet');
        routes.push({name,body_schema:descriptor.options.metadata?.openapi?.requestBody?undefined:endpointSchema(descriptor.options.body),query_schema:descriptor.options.metadata?.openapi?.parameters?undefined:endpointSchema(descriptor.options.query),openapi_metadata:descriptor.options.metadata?.openapi?transportJSON(descriptor.options.metadata.openapi):undefined,hide_from_docs:descriptor.options.metadata?.scope==='server', path: descriptor.path, method, fresh_session: use.includes(freshSessionMiddleware)});
        endpointCallbacks[`plugin.${plugin.id}.${name}`] = async payload => {
          const request = new Request(payload.request.url, {method: payload.request.method, headers: payload.request.headers, body: payload.request.method === 'POST' ? payload.request.body : undefined});
          const responseHeaders = new Headers();
          const endpointContext = {
            request, headers: request.headers, query: descriptor.options.query ? descriptor.options.query.parse(Object.fromEntries(new URL(request.url).searchParams)) : Object.fromEntries(new URL(request.url).searchParams),
            body: payload.request.body ? JSON.parse(payload.request.body) : undefined,
            context: {...getContext(), session: hydrate(payload.session)},
            setHeader: (name: string, value: string) => responseHeaders.set(name, value),
            json: (body: unknown) => body,
          };
          for (const middleware of use) {
            const select = nativeOriginSelector(middleware);
            if (select) {
              const selected = await select(endpointContext);
              await getContext().nativeValidateRedirect(Array.isArray(selected) ? selected : [selected ?? null]);
            }
          }
          const result = await descriptor.handler(endpointContext);
          if (result instanceof Response) {
            result.headers.forEach((value, name) => { if (name !== 'set-cookie') responseHeaders.set(name, value); });
            for (const cookie of result.headers.getSetCookie()) responseHeaders.append('set-cookie', cookie);
          } else responseHeaders.set('content-type', 'application/json');
          return {
            status: result instanceof Response ? result.status : 200,
            body: result instanceof Response ? await result.text() : JSON.stringify(result ?? null),
            headers: [...responseHeaders].map(([name, value]) => ({name, value})),
          };
        };
      }
      endpointPlugins.push({name: plugin.id, routes});
      continue;
    }
    if (jwtOptions) throw new Error('Duplicate JWT plugin');
    jwtOptions = (plugin as {options?: FixtureOptions}).options ?? {};
    assertKeys(jwtOptions, ['sessionCookieCache', 'jwks', 'jwt', 'disableSettingJwtHeader', 'adapter', 'schema'], 'jwt');
    assertKeys(jwtOptions.schema??{}, ['jwks'], 'jwt.schema');
    if(jwtOptions.schema?.jwks)assertKeys(jwtOptions.schema.jwks,['fields','modelName'],'jwt.schema.jwks');
    if (jwtOptions.adapter) {
      assertKeys(jwtOptions.adapter, ['getJwks', 'createJwk'], 'jwt.adapter');
      for (const method of ['getJwks', 'createJwk']) if (jwtOptions.adapter[method] !== undefined && typeof jwtOptions.adapter[method] !== 'function') throw new Error(`Invalid custom JWK callback: ${method}`);
    }
    assertKeys(jwtOptions.jwks ?? {}, ['rotationInterval', 'gracePeriod', 'disablePrivateKeyEncryption', 'jwksPath', 'keyPairConfig', 'remoteUrl', 'keyPairConfigs'], 'jwt.jwks');
    assertKeys(jwtOptions.jwks?.keyPairConfig ?? {}, ['alg', 'crv', 'modulusLength'], 'jwt.jwks.keyPairConfig');
    assertKeys(jwtOptions.jwt ?? {}, ['issuer', 'audience', 'sign', 'expirationTime', 'definePayload', 'getSubject'], 'jwt.jwt');
  }
  return {magicLinkOptions,twoFactorOptions,anonymousOptions,otpOptions,ottOptions,jwtOptions,adminOptions,organizationOptions,openAPIOptions,genericProviders,logoutProviders,requestHooks,skippedOriginPaths,initializers,originSources,endpointPlugins,endpointCallbacks,adapterModels};
}
