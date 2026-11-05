import type {UserWithRole} from 'better-auth/plugins/admin';
import type {DBFieldAttribute} from "@better-auth/core/db";
import {nativeRedisConfiguration} from './redis-storage.js';
import { APIError } from "@better-auth/core/error";
import type { BetterAuthClientOptions, BetterAuthOptions } from "@better-auth/core";
import type { Account, Auth } from "better-auth";
import type { JSONWebKeySet } from 'jose';
import { AsyncLocalStorage } from "node:async_hooks";
import { createAuthClient } from "better-auth/client";
import { parseSetCookieHeader } from "better-auth/cookies";
import { afterAll } from "vitest";
import { Bridge, recordMetadata, transportJSON } from "./bridge.js";
import { isNativeMemoryAdapter } from "./memory-adapter.js";
import {endpointSchema} from './endpoint-schema.js';
import { nativeEndpoint, freshSessionMiddleware, nativeOriginSelector } from './endpoint.js';
import { encodeJWTOptions } from './jwt-options.js';
import { schemaPluginOptions } from './plugins.js';

// Upstream fixtures are intentionally dynamically shaped. This boundary accepts
// their objects; unsupported server configuration fails rather than being ignored.
type FixtureOptions = Record<string, any>;
interface FixtureUserOptions extends FixtureOptions {
  deleteUser?: NonNullable<BetterAuthOptions['user']>['deleteUser'];
  changeEmail?: NonNullable<BetterAuthOptions['user']>['changeEmail'];
  additionalFields?: Record<string,DBFieldAttribute>;
  validateUserInfo?: NonNullable<BetterAuthOptions['user']>['validateUserInfo'];
}
interface FixtureLoggerOptions extends FixtureOptions {
  log?: NonNullable<BetterAuthOptions['logger']>['log'];
}
interface ServerOptions {
 verification?: BetterAuthOptions["verification"];
	socialProviders?: BetterAuthOptions['socialProviders'];
  plugins?: BetterAuthOptions['plugins'];
  database?: BetterAuthOptions["database"];
  baseURL?: BetterAuthOptions['baseURL'];
  basePath?: string;
  appName?: string;
  secret?: string;
  secrets?: BetterAuthOptions['secrets'];
  trustedOrigins?: BetterAuthOptions['trustedOrigins'];
  emailAndPassword?: Partial<NonNullable<BetterAuthOptions['emailAndPassword']>> & FixtureOptions;
  emailVerification?: NonNullable<BetterAuthOptions['emailVerification']> & FixtureOptions;
  session?: NonNullable<BetterAuthOptions["session"]> & FixtureOptions;
  advanced?: FixtureOptions;
  rateLimit?: FixtureOptions;
  logger?: FixtureLoggerOptions;
  secondaryStorage?: NonNullable<BetterAuthOptions["secondaryStorage"]> & Record<string, any>;
  account?: FixtureOptions;
  user?: FixtureUserOptions;
  databaseHooks?: BetterAuthOptions["databaseHooks"];
}
type FixtureResponseAPI = <const A extends FixtureOptions = FixtureOptions>(args?: A) => Promise<A extends {asResponse: true} ? Response : any>;
type FixtureEnableTwoFactorAPI = <const A extends FixtureOptions = FixtureOptions>(args?: A) => Promise<A extends {asResponse: true} ? Response : {method: 'totp' | 'otp'; backupCodes: string[]; totpURI: string}>;
type OrganizationAPI<O,K extends string> = O extends BetterAuthOptions ? K extends keyof Auth<O>['api'] ? Auth<O>['api'][K] : (args?:FixtureOptions)=>Promise<any> : (args?:FixtureOptions)=>Promise<any>;
type SignUpAPI<O> = O extends BetterAuthOptions ? (Auth<O>["api"] extends {signUpEmail: infer F} ? F : Auth<{}>["api"]["signUpEmail"]) : Auth<{}>["api"]["signUpEmail"];
type SessionAPI<O> = O extends BetterAuthOptions ? (Auth<O>["api"] extends {getSession: infer F} ? F : Auth<{}>["api"]["getSession"]) : Auth<{}>["api"]["getSession"];
interface FixtureSession extends FixtureOptions {
  id: string;
  userId: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}
interface FixtureInternalAdapter extends Record<string, (...args: any[]) => Promise<any>> {
  findAccounts(userId: string): Promise<Account[]>;
  listSessions(userId: string): Promise<FixtureSession[]>;
  createSession(userId: string, dontRememberMe?: boolean): Promise<FixtureSession>;
  findSession(token: string): Promise<{session: FixtureSession; user: FixtureOptions} | null>;
}
interface FixtureTransactionAdapter {
  findOne<T = any>(query: FixtureOptions): Promise<T | null>;
 update<T = any>(query: FixtureOptions): Promise<T | null>;
  create<I=Record<string,unknown>, O=I & {id:string}>(query: {model: string; data: I}): Promise<O>;
  findMany<T>(query: {model: string;where?:FixtureOptions[]}): Promise<T[]>;
  nativeRunWithTransaction<T>(callback: () => Promise<T>): Promise<T>;
  options: {adapterConfig: {transaction: boolean}};
  transaction(callback: (transaction: FixtureTransactionAdapter) => Promise<unknown>): Promise<unknown>;
}
const instances = new Set<Bridge>();
const nativeTransactionScope = new AsyncLocalStorage<boolean>();
const currentUserHeaders = new AsyncLocalStorage<Headers>();
const currentOperation = new AsyncLocalStorage<{ transactionError?: unknown; storeFailure?: unknown; request?: Request }>();
afterAll(async () => {
  await Promise.all([...instances].map((instance) => instance.close()));
  instances.clear();
});

const routes: Record<string, [string, string]> = {
 generateOpenAPISchema:['GET','/open-api/generate-schema'],openAPIReference:['GET','/reference'],
 createOrganization:['POST','/organization/create'],updateOrganization:['POST','/organization/update'],deleteOrganization:['POST','/organization/delete'],
 checkOrganizationSlug:['POST','/organization/check-slug'],setActiveOrganization:['POST','/organization/set-active'],
 listOrganizations:['GET','/organization/list'],getFullOrganization:['GET','/organization/get-full-organization'],getOrganization:['GET','/organization/get-organization'],
 getActiveMember:['GET','/organization/get-active-member'],listMembers:['GET','/organization/list-members'],addMember:['POST','/internal/organization/add-member'],
 createInvitation:['POST','/organization/invite-member'],acceptInvitation:['POST','/organization/accept-invitation'],rejectInvitation:['POST','/organization/reject-invitation'],cancelInvitation:['POST','/organization/cancel-invitation'],getInvitation:['GET','/organization/get-invitation'],listInvitations:['GET','/organization/list-invitations'],listUserInvitations:['GET','/organization/list-user-invitations'],
 hasPermission:['POST','/organization/has-permission'],updateMemberRole:['POST','/organization/update-member-role'],createOrgRole:['POST','/organization/create-role'],updateOrgRole:['POST','/organization/update-role'],deleteOrgRole:['POST','/organization/delete-role'],getOrgRole:['GET','/organization/get-role'],listOrgRoles:['GET','/organization/list-roles'],
 removeMember:['POST','/organization/remove-member'],leaveOrganization:['POST','/organization/leave'],getActiveMemberRole:['GET','/organization/get-active-member-role'],

 impersonateUser:['POST','/admin/impersonate-user'],stopImpersonating:['POST','/admin/stop-impersonating'],
 getUser:['GET','/admin/get-user'],createUser:['POST','/admin/create-user'],
 listUsers:['GET','/admin/list-users'],setRole:['POST','/admin/set-role'],
 banUser:['POST','/admin/ban-user'],unbanUser:['POST','/admin/unban-user'],
 adminUpdateUser:['POST','/admin/update-user'],setUserPassword:['POST','/admin/set-user-password'],
 removeUser:['POST','/admin/remove-user'],listUserSessions:['POST','/admin/list-user-sessions'],
 revokeUserSession:['POST','/admin/revoke-user-session'],revokeUserSessions:['POST','/admin/revoke-user-sessions'],
 userHasPermission:['POST','/admin/has-permission'],

 signInMagicLink: ['POST', '/sign-in/magic-link'],
 magicLinkVerify: ['GET', '/magic-link/verify'],
 sendTwoFactorOTP: ['POST', '/two-factor/send-otp'],
 verifyTwoFactorOTP: ['POST', '/two-factor/verify-otp'],
 enableTwoFactor: ['POST', '/two-factor/enable'],
 disableTwoFactor: ['POST', '/two-factor/disable'],
 getTOTPURI: ['POST', '/two-factor/get-totp-uri'],
 verifyTOTP: ['POST', '/two-factor/verify-totp'],
 generateTOTP: ['POST', '/internal/two-factor/generate-totp'],
 generateBackupCodes: ['POST', '/two-factor/generate-backup-codes'],
 verifyBackupCode: ['POST', '/two-factor/verify-backup-code'],
 viewBackupCodes: ['POST', '/internal/two-factor/view-backup-codes'],
 signInAnonymous: ['POST', '/sign-in/anonymous'],
 deleteAnonymousUser: ['POST', '/delete-anonymous-user'],
 sendVerificationOTP: ['POST', '/email-otp/send-verification-otp'],
 checkVerificationOTP: ['POST', '/email-otp/check-verification-otp'],
 verifyEmailOTP: ['POST', '/email-otp/verify-email'],
 signInEmailOTP: ['POST', '/sign-in/email-otp'],
 requestPasswordResetEmailOTP: ['POST', '/email-otp/request-password-reset'],
 forgetPasswordEmailOTP: ['POST', '/forget-password/email-otp'],
 resetPasswordEmailOTP: ['POST', '/email-otp/reset-password'],
 requestEmailChangeEmailOTP: ['POST', '/email-otp/request-email-change'],
 changeEmailEmailOTP: ['POST', '/email-otp/change-email'],
 generateOneTimeToken: ['GET', '/one-time-token/generate'],
 verifyOneTimeToken: ['POST', '/one-time-token/verify'],
  signInSocial: ["POST", "/sign-in/social"],
  signUpEmail: ["POST", "/sign-up/email"],
  signInEmail: ["POST", "/sign-in/email"],
  getSession: ["GET", "/get-session"],
  signOut: ["POST", "/sign-out"],
  listSessions: ["GET", "/list-sessions"],
  revokeSession: ["POST", "/revoke-session"],
  revokeSessions: ["POST", "/revoke-sessions"],
  revokeOtherSessions: ["POST", "/revoke-other-sessions"],
  updateUser: ["POST", "/update-user"],
  updateSession: ["POST", "/update-session"],
  changePassword: ["POST", "/change-password"],
  changeEmail: ["POST", "/change-email"],
  deleteUser: ["POST", "/delete-user"],
  requestPasswordReset: ["POST", "/request-password-reset"],
  resetPassword: ["POST", "/reset-password"],
  verifyPassword: ["POST", "/verify-password"],
  sendVerificationEmail: ["POST", "/send-verification-email"],
  verifyEmail: ["GET", "/verify-email"],
};

const statuses: Record<number, string> = {
  400: "BAD_REQUEST",
  401: "UNAUTHORIZED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  405: "METHOD_NOT_ALLOWED",
  413: "PAYLOAD_TOO_LARGE",
  415: "UNSUPPORTED_MEDIA_TYPE",
  422: "UNPROCESSABLE_ENTITY",
  429: "TOO_MANY_REQUESTS",
  500: "INTERNAL_SERVER_ERROR",
};

function assertKeys(value: FixtureOptions, allowed: string[], label: string) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key))
      throw new Error(`Unsupported V fixture option: ${label}.${key}`);
  }
}


export async function getTestInstance<const O extends ServerOptions = {}, C extends FixtureOptions = {}>(
  options: O & ServerOptions = {} as O & ServerOptions,
  config: C = {} as C,
) {
  assertKeys(
    options,
    [
      "verification",
      "appName",
      "baseURL",
      "plugins",
      "database",
      "basePath",
      "secret",
      "secrets",
      "trustedOrigins",
      "emailAndPassword",
      "emailVerification",
      "session",
      "advanced",
      "rateLimit",
      "user",
      "logger",
      "secondaryStorage",
      "databaseHooks",
      "account",
      "socialProviders",
    ],
    "options",
  );
  assertKeys(
    config,
    [
      "deferMigrations",
      "nativePostgres", "nativeSqlite",
      "nativeMongo",
      "disableTestUser",
      "testUser",
      "port",
      "testWith",
      "realPasswords",
      "failDelivery",
      "magicLink",
      "clientOptions",
    ],
    "config",
  );
  if (config.testWith && config.testWith !== "sqlite")
    throw new Error("Only SQLite fixtures are implemented");
  if (options.database !== undefined && !isNativeMemoryAdapter(options.database))
    throw new Error("Only the native memory-adapter fixture is supported as an explicit database");
  if (options.verification) {
    assertKeys(options.verification, ['storeInDatabase', 'disableCleanup', 'storeIdentifier'], 'verification');
    const storage = options.verification.storeIdentifier;
    const modes = typeof storage === 'object' && storage && 'default' in storage ? [storage.default, ...Object.values(storage.overrides ?? {})] : [storage];
    if (modes.some(mode => mode !== undefined && mode !== 'plain' && mode !== 'hashed' && !(typeof mode === 'object' && mode && typeof (mode as FixtureOptions).hash === 'function'))) throw new Error('Invalid verification identifier hashing');
  }
  const nativeRedis = nativeRedisConfiguration(options.secondaryStorage);
  assertKeys(options.rateLimit ?? {}, ['enabled', 'max', 'window', 'storage', 'customRules'], 'rateLimit');
  const ep = options.emailAndPassword ?? {};
  const ev = options.emailVerification ?? {};
  const session = options.session ?? {};
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
  for (const plugin of options.plugins ?? []) {
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
      assertKeys(plugin, ['id', 'endpoints', 'init', 'onRequest'], `plugin.${plugin.id}`);
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
            context: {...context, session: hydrate(payload.session)},
            setHeader: (name: string, value: string) => responseHeaders.set(name, value),
            json: (body: unknown) => body,
          };
          for (const middleware of use) {
            const select = nativeOriginSelector(middleware);
            if (select) {
              const selected = await select(endpointContext);
              await context.nativeValidateRedirect(Array.isArray(selected) ? selected : [selected ?? null]);
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
    assertKeys(jwtOptions, ['sessionCookieCache', 'jwks', 'jwt', 'disableSettingJwtHeader', 'adapter'], 'jwt');
    if (jwtOptions.adapter) {
      assertKeys(jwtOptions.adapter, ['getJwks', 'createJwk'], 'jwt.adapter');
      for (const method of ['getJwks', 'createJwk']) if (jwtOptions.adapter[method] !== undefined && typeof jwtOptions.adapter[method] !== 'function') throw new Error(`Invalid custom JWK callback: ${method}`);
    }
    assertKeys(jwtOptions.jwks ?? {}, ['rotationInterval', 'gracePeriod', 'disablePrivateKeyEncryption', 'jwksPath', 'keyPairConfig', 'remoteUrl', 'keyPairConfigs'], 'jwt.jwks');
    assertKeys(jwtOptions.jwks?.keyPairConfig ?? {}, ['alg', 'crv', 'modulusLength'], 'jwt.jwks.keyPairConfig');
    assertKeys(jwtOptions.jwt ?? {}, ['issuer', 'audience', 'sign', 'expirationTime', 'definePayload', 'getSubject'], 'jwt.jwt');
  }
  const stateless = Object.hasOwn(options, 'database') && options.database === undefined && !options.secondaryStorage;
  const cacheOptions = session.cookieCache ?? {};
  assertKeys(cacheOptions, ['enabled', 'strategy', 'maxAge', 'refreshCache', 'version'], 'session.cookieCache');
  const advanced = options.advanced ?? {};
  assertKeys(
    ep,
    [
      "enabled",
      "disableSignUp",
      "requireEmailVerification",
      "autoSignIn",
      "minPasswordLength",
      "maxPasswordLength",
      "sendResetPassword",
      "onPasswordReset",
      "resetPasswordTokenExpiresIn",
      "revokeSessionsOnPasswordReset",
      "password",
      "onExistingUserSignUp",
      "customSyntheticUser",
    ],
    "emailAndPassword",
  );
  assertKeys(
    ev,
    ["sendOnSignUp", "sendOnSignIn", "sendVerificationEmail", "expiresIn", "autoSignInAfterVerification", "beforeEmailVerification", "afterEmailVerification"],
    "emailVerification",
  );
  assertKeys(
    session,
    [
      "expiresIn",
      "updateAge",
      "freshAge",
      "deferSessionRefresh",
      "disableSessionRefresh",
      "storeSessionInDatabase",
      "preserveSessionInDatabase",
      "additionalFields",
      "cookieCache",
    ],
    "session",
  );
  assertKeys(
    advanced,
    ["database", "generateId", "disableCSRFCheck", "disableOriginCheck", "trustedProxyHeaders", "cookies", "cookiePrefix", "useSecureCookies", "crossSubDomainCookies", "defaultCookieAttributes"],
    "advanced",
  );
  assertKeys(advanced.database ?? {}, ['generateId'], 'advanced.database');
  const configuredId = advanced.generateId ?? advanced.database?.generateId;
  if (configuredId !== undefined && configuredId !== 'uuid' && typeof configuredId !== 'function') throw new Error('Persisted serial/database-generated IDs remain unported');
  assertKeys(advanced.crossSubDomainCookies ?? {}, ['enabled', 'domain'], 'advanced.crossSubDomainCookies');
  const cookieNames: Record<string, string> = {};
  const cookieAttributes: Record<string, Record<string, unknown>> = {};
  for (const [kind, cookie] of Object.entries(advanced.cookies ?? {}) as [string, FixtureOptions][]) {
    assertKeys(cookie, ['name', 'attributes'], 'advanced.cookies.' + kind);
    cookieNames[kind] = cookie.name ?? '';
    cookieAttributes[kind] = cookie.attributes ?? {};
  }
  assertKeys(
    options.user ?? {},
    ["additionalFields", "validateUserInfo", "changeEmail", "deleteUser"],
    "user",
  );
  assertKeys(options.user?.deleteUser ?? {}, ['enabled', 'sendDeleteAccountVerification', 'deleteTokenExpiresIn', 'beforeDelete', 'afterDelete'], 'user.deleteUser');
  assertKeys(options.user?.changeEmail ?? {}, ['enabled', 'sendChangeEmailConfirmation', 'updateEmailWithoutVerification'], 'user.changeEmail');
  assertKeys(options.logger ?? {}, ["level", "log", "disabled"], "logger");
  assertKeys(
    ep.password ?? {},
    ["hash", "verify"],
    "emailAndPassword.password",
  );
  assertKeys(config.clientOptions ?? {}, ["plugins"], "clientOptions");
  for (const schema of [
    options.user?.additionalFields ?? {},
    session.additionalFields ?? {},
    ...Object.values(organizationOptions?.schema??{}).map((model:any)=>model.additionalFields??{}),
  ]) {
    for (const field of Object.values(schema) as FixtureOptions[]) {
      assertKeys(
        field,
        ["type", "required", "input", "returned", "defaultValue", "fieldName", "unique", "validator", "transform"],
        "additionalField",
      );
      assertKeys(field.validator ?? {}, ['input'], 'additionalField.validator');
      assertKeys(field.transform ?? {}, ['input'], 'additionalField.transform');
      if (field.validator?.input && typeof field.validator.input['~standard']?.validate !== 'function') throw new Error('Field validator requires Standard Schema');

    }
  }

  assertKeys(options.account ?? {}, ['fields', 'storeAccountCookie', 'encryptOAuthTokens', 'accountLinking'], 'account');
  if (options.account?.accountLinking) {
    assertKeys(options.account.accountLinking, ['enabled', 'trustedProviders', 'allowDifferentEmails', 'updateUserInfoOnLink', 'requireLocalEmailVerified', 'disableImplicitLinking'], 'account.accountLinking');
    if (options.account.accountLinking.allowDifferentEmails) throw new Error('Different-email account linking remains unported');
    if (options.account.accountLinking.trustedProviders && !Array.isArray(options.account.accountLinking.trustedProviders)) throw new Error('Dynamic trusted providers remain unported');
  }

  assertKeys(options.socialProviders ?? {}, ['google'], 'socialProviders');
  const google = options.socialProviders?.google;
  if (typeof google === 'function') throw new Error('Unported provider option callback');
  if (google) {
    assertKeys(google, ['clientId', 'clientSecret', 'enabled', 'scope', 'disableDefaultScope', 'accessType', 'display', 'hd', 'prompt', 'includeGrantedScopes', 'redirectURI', 'authorizationEndpoint', 'disableIdTokenSignIn', 'mapProfileToUser'], 'socialProviders.google');
  }
  assertKeys(options.account?.fields ?? {}, ['id', 'userId', 'providerId', 'accountId'], 'account.fields');
  if (options.baseURL !== undefined && typeof options.baseURL !== 'string') throw new Error('Live dynamic baseURL configuration remains unported');
  const baseURL = typeof options.baseURL === 'string' ? options.baseURL : `http://localhost:${config.port ?? 3000}`;
  const basePath = options.basePath ?? "/api/auth";
  const bridge = new Bridge([], !!config.nativeMongo);
  instances.add(bridge);
  let jwtCallSequence = 0;
  const callbacks: Record<string, (payload: any) => unknown> = {...endpointCallbacks};
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
      if (nativeTransactionScope.getStore()) return callback();
      const method = 'transaction.' + crypto.randomUUID();
      let result: T;
      let cause: unknown;
      let failed = false;
      bridge.setCallback(method, () => nativeTransactionScope.run(true, async () => {
        try { result = await callback(); return null; }
        catch (error) { failed = true; cause = error; throw error; }
      }));
      try { await bridge.send('transaction', {method}); }
      catch (error) { throw failed ? cause : error; }
      finally { bridge.removeCallback(method); }
      return result!;
    },
    async create<I, O>(query: {model: string; data: I}): Promise<O> {
      if (query.model === 'user') {
       const reply = await bridge.send('internal', {method:'createUser',arguments_json:transportJSON([query.data])});
       return hydrate(JSON.parse(reply.value_json));
      }
      if (query.model !== 'jwks') throw new Error('Unsupported adapter create model');
      const reply = await bridge.send('internal', {method: 'adapterCreateJWK', arguments_json: transportJSON([query.data])});
      return hydrate(JSON.parse(reply.value_json));
    },
    async findMany<T>(query: {model: string}): Promise<T[]> {
      if (['account','verification'].includes(query.model)) {
       const reply = await bridge.send('inspect', {model:query.model,where_json:transportJSON((query as FixtureOptions).where ?? [])});
       return hydrate(JSON.parse(reply.records_json));
      }
      if (query.model !== 'jwks') throw new Error('Unsupported adapter findMany model');
      const reply = await bridge.send('internal', {method: 'jwkLookup', arguments_json: transportJSON(['getAllKeys', '', ''])});
      return hydrate(JSON.parse(reply.value_json));
    },
    async update(query) {
     assertKeys(query, ['model','where','update'], 'adapter.update');
     if(['organization','member','invitation','organizationRole'].includes(query.model)&&query.where?.length===1&&query.where[0].field==='id'&&(!query.where[0].operator||query.where[0].operator==='eq')){const reply=await bridge.send('internal',{method:'adapterUpdateOrganizationModel',arguments_json:transportJSON([query.model,query.where[0].value,query.update])});return hydrate(JSON.parse(reply.value_json));}
     if (query.model !== 'user' || query.where?.length !== 1 || !['id','email'].includes(query.where[0].field) || (query.where[0].operator && query.where[0].operator !== 'eq')) throw new Error('Native adapter.update requires user id/email equality');
     const reply = await bridge.send('internal',{method:'adapterUpdateUser',arguments_json:transportJSON([query.where[0].field,query.where[0].value,query.update])});
     return hydrate(JSON.parse(reply.value_json));
    },
    async findOne(query) {
      const reply = await bridge.send('internal', {method: 'adapterFindOne', arguments_json: transportJSON([query])});
      return hydrate(JSON.parse(reply.value_json));
    },
    options: {adapterConfig: {transaction: true}},
    async transaction(callback): Promise<unknown> { return callback(adapter); },
  };
  bridge.setTransactionsProvider(() => adapter.options.adapterConfig.transaction !== false);
  const password = {
    hash: ep.password?.hash ?? (async (value: string) => {
      if (bridge.inCallback) return undefined;
      return JSON.parse((await bridge.send('configured-password-hash', {password: value})).value_json) as string;
    }),
    verify: ep.password?.verify ?? (async (input: {password: string; hash: string}) => {
      if (bridge.inCallback) return undefined;
      return JSON.parse((await bridge.send('configured-password-verify', input)).value_json) as boolean;
    }),
  };
  const context = {
    adapter, internalAdapter, options, password,
    socialProviders: [] as {id: string; requiresIdTokenNonce?: boolean}[],
    secret: options.secrets?.[0]?.value ?? options.secret ?? 'better-auth-secret-that-is-long-enough-for-validation-test',
    session: null as unknown,
    authCookies: {} as {sessionToken: {name: string}; sessionData: {name: string}; accountData: {name: string}; dontRememberToken: {name: string}},
    secretConfig: '' as string | import('@better-auth/core').SecretConfig,
    async nativeValidateRedirect(values: unknown[]) {
      try { await bridge.send('internal', {method: 'validateRedirect', arguments_json: transportJSON([values])}); }
      catch (error) {
        const native = error as Error & {statusCode: number; body: {code: string; message: string}};
        throw APIError.fromStatus((statuses[native.statusCode] ?? 'INTERNAL_SERVER_ERROR') as any, native.body);
      }
    },
    async isTrustedOrigin(url: string, settings?: {allowRelativePaths: boolean}) {
      const reply = await bridge.send('internal', {method: 'isTrustedOrigin', arguments_json: transportJSON([url, settings?.allowRelativePaths ?? false])});
      return JSON.parse(reply.value_json) as boolean;
    },
    async nativeSignJWT(payload: unknown, signing: unknown, replacement?: {options?: FixtureOptions}) {
      const reply = replacement ? await nativeJWTCall('signJWTWith', [payload, signing], replacement.options) : await bridge.send('internal', {method: 'signJWTWith', arguments_json: transportJSON([payload, signing])});
      recordLogs(reply.logs ?? []);
      return JSON.parse(reply.value_json) as string;
    },
    async nativeVerifyJWT(token: string, options?: FixtureOptions) {
      const reply = await nativeJWTCall('verifyJWTWithOptions', [token], options);
      recordLogs(reply.logs ?? []);
      return JSON.parse(reply.value_json);
    },
    async nativeJwkLookup(method: string, value: string, algorithm: string, replacement?: {options?: FixtureOptions}) {
      const reply = replacement ? await nativeJWTCall('jwkLookupWithOptions', [method, value], replacement.options) : await bridge.send('internal', {method: 'jwkLookup', arguments_json: transportJSON([method, value, algorithm])});
      const result = hydrate(JSON.parse(reply.value_json));
      return result === null ? undefined : result;
    },
    async nativeVerifyCookieJWT(token: string) {
      const reply = await bridge.send('internal', {method: 'verifyCookieJWT', arguments_json: transportJSON([token])});
      return JSON.parse(reply.value_json);
    },
    async nativeSession(endpoint: {headers?: Headers; query?: FixtureOptions; responseHeaders?: Headers}, authoritative: boolean) {
      const reply = await bridge.send('internal', {method: 'sessionFromContext', arguments_json: transportJSON([Object.fromEntries(endpoint.headers ?? new Headers()), endpoint.query ?? {}, authoritative])});
      const response = JSON.parse(reply.value_json);
      endpoint.responseHeaders ??= new Headers();
      for (const {name, value} of response.headers) endpoint.responseHeaders.append(name, value);
      return hydrate(JSON.parse(response.body));
    },
  };
  async function nativeJWTCall(method: string, args: unknown[], options?: FixtureOptions) {
    const encoded = encodeJWTOptions(options);
    const prefix = `jwt.call.${++jwtCallSequence}`;
    const methods: string[] = [];
    const install = (suffix: string, callback: (input: any) => unknown) => {
      methods.push(prefix + '.' + suffix);
      bridge.setCallback(prefix + '.' + suffix, callback);
    };
    if (options?.jwt?.sign) install('sign', ({payload, header, config}) => options.jwt.sign(payload, Object.keys(header).length ? header : undefined, {signingKeyId: config.signingKeyId ?? undefined, signingAlgorithm: config.signingAlgorithm ?? undefined}));
    if (options?.adapter?.getJwks) install('getJwks', () => options.adapter.getJwks({context}));
    if (options?.adapter?.createJwk) install('createJwk', data => options.adapter.createJwk(hydrate(data), {context}));
    try {
      return await bridge.send('internal', {method, arguments_json: transportJSON(args), jwt_options_json: encoded.options_json, jwt_expiration_json: encoded.expiration_json, jwt_callback_prefix: prefix, jwt_callback_methods: methods});
    } finally { for (const method of methods) bridge.removeCallback(method); }
  }
  for (const initialize of initializers) {
    const result = await initialize(context) as FixtureOptions | undefined;
    if (!result) continue;
    assertKeys(result, ['options', 'context'], 'plugin.init');
    assertKeys(result.context ?? {}, ['skipOriginCheck'], 'plugin.init.context');
    if (result.context?.skipOriginCheck !== undefined) {
      if (!Array.isArray(result.context.skipOriginCheck) || result.context.skipOriginCheck.some((path: unknown) => typeof path !== 'string')) throw new Error('Only native skipOriginCheck path arrays are supported in plugin init');
      skippedOriginPaths.push(...result.context.skipOriginCheck);
    }
    assertKeys(result.options ?? {}, ['trustedOrigins'], 'plugin.init.options');
    if (result.options?.trustedOrigins) originSources.push(result.options.trustedOrigins);
  }
  if (originSources.length) callbacks.trustedOrigins = async () => {
    const result: unknown[] = [];
    for (const source of originSources) result.push(...(typeof source === 'function' ? await source(callbackRequest()) : source));
    return result;
  };
  callbacks['internal.adapter.findOne'] = async ([query]: FixtureOptions[]) => {
    try { return await adapter.findOne(query); }
    catch (error) { const state = currentOperation.getStore(); if (state) state.storeFailure = error; throw error; }
  };
  for (const name of ['definePayload', 'getSubject']) {
    const callback = jwtOptions?.jwt?.[name];
    if (callback !== undefined && typeof callback !== 'function') throw new Error('Invalid JWT callback: ' + name);
    if (callback) callbacks['jwt.' + name] = current => callback(hydrate(current));
  }
  if (jwtOptions?.jwt?.sign) callbacks['jwt.sign'] = ({payload, header, config}) => jwtOptions!.jwt.sign(payload, Object.keys(header).length ? header : undefined, {signingKeyId: config.signingKeyId ?? undefined, signingAlgorithm: config.signingAlgorithm ?? undefined});
  if (jwtOptions?.adapter) {
    const store = jwtOptions.adapter;
    if (store.getJwks) callbacks['jwt.getJwks'] = () => store.getJwks({context});
    if (store.createJwk) callbacks['jwt.createJwk'] = data => store.createJwk(hydrate(data), {context});
  }
  if (typeof session.cookieCache?.version === 'function') {
    callbacks['cache.version'] = (payload) => (session.cookieCache!.version as Function)(hydrate(payload.session), hydrate(payload.user));
  }
  if (google?.mapProfileToUser) callbacks['google.map'] = profile => google.mapProfileToUser!(profile);
  if ((google && google.enabled !== false) || genericProviders.length) callbacks['oauth.fetch'] = async request => {
    const response = await fetch(request.url, {method: request.method, headers: request.headers, body: request.method === 'GET' ? undefined : request.body, redirect: 'manual'});
    return {status: response.status, body: await response.text(), headers: [...response.headers].map(([name, value]) => ({name, value}))};
  };
  callbacks['transaction.beforeCommit'] = async () => {
    try { await context.adapter.transaction(async () => undefined); }
    catch (error) { const state = currentOperation.getStore(); if (state) state.transactionError = error; throw error; }
  };
  if (options.secondaryStorage && !nativeRedis) {
    const store = options.secondaryStorage;
    for (const name of ['get', 'set', 'delete', 'getAndDelete', 'increment']) {
      if (typeof options.secondaryStorage[name] !== 'function') throw new Error(`Secondary storage requires ${name}`);
      callbacks['secondary.' + name] = (payload) => {
        if (name === 'set') return store.set(payload.key, payload.value, payload.ttl || undefined);
        if (name === 'increment') return store.increment(payload.key, payload.ttl || undefined);
        return store[name](payload.key);
      };
    }
  }
  for (const [model, operations] of Object.entries(options.databaseHooks ?? {}) as [string, FixtureOptions][]) {
    assertKeys({[model]: operations}, ['user', 'account', 'session', 'verification'], 'databaseHooks');
    assertKeys(operations, ['create', 'update', 'delete'], 'databaseHooks.' + model);
    for (const [operation, phases] of Object.entries(operations) as [string, FixtureOptions][]) {
      assertKeys(phases, ['before', 'after'], `databaseHooks.${model}.${operation}`);
      for (const [phase, callback] of Object.entries(phases)) {
        if (typeof callback !== 'function') throw new Error('Database hook must be a callback');
        callbacks[`db.${model}.${operation}.${phase}`] = (data) => callback(hydrate(data), undefined);
      }
    }
  }

  if (ep.password) {
    if (
      typeof ep.password.hash !== "function" ||
      typeof ep.password.verify !== "function"
    )
      throw new Error(
        "Custom password configuration requires hash and verify callbacks",
      );

  }
  if (magicLinkOptions) callbacks['email.magic-link'] = data => magicLinkOptions.sendMagicLink({email:data.user.email, url:data.url,token:data.token}, callbackRequest());
  callbacks['password.hash'] = value => context.password.hash(value);
  callbacks['password.verify'] = input => context.password.verify(input);
  if (typeof ep.onPasswordReset === 'function') callbacks['password.reset'] = input => ep.onPasswordReset!(hydrate(input), callbackRequest());
  if (typeof ep.sendResetPassword === "function")
    callbacks["email.reset-password"] = (payload) =>
      ep.sendResetPassword!({user: hydrate(payload.user), url: payload.url, token: payload.token}, callbackRequest());
  if (typeof ev.beforeEmailVerification === 'function') callbacks['email.verify.before'] = user => ev.beforeEmailVerification!(hydrate(user), callbackRequest());
  if (typeof ev.afterEmailVerification === 'function') callbacks['email.verify.after'] = user => ev.afterEmailVerification!(hydrate(user), callbackRequest());
  const deleteUser = options.user?.deleteUser;
  if (deleteUser?.sendDeleteAccountVerification) callbacks['email.delete-account'] = data => deleteUser.sendDeleteAccountVerification!({user: hydrate(data.user), token: data.token, url: data.url}, callbackRequest());
  if (deleteUser?.beforeDelete) callbacks['user.delete.before'] = user => deleteUser.beforeDelete!(hydrate(user), callbackRequest());
  if (deleteUser?.afterDelete) callbacks['user.delete.after'] = user => deleteUser.afterDelete!(hydrate(user), callbackRequest());
  const changeEmail = options.user?.changeEmail;
  if (typeof changeEmail?.sendChangeEmailConfirmation === 'function') callbacks['email.change-confirmation'] = message => changeEmail.sendChangeEmailConfirmation!({user: hydrate(message.user), newEmail: message.newEmail, url: message.url, token: message.token}, callbackRequest());
  if (typeof ev.sendVerificationEmail === "function")
    callbacks["email.verify-email"] = (payload) =>
      ev.sendVerificationEmail!({user: hydrate(payload.user), url: payload.url, token: payload.token}, callbackRequest());
  const validateUserInfo = options.user?.validateUserInfo;
  if (typeof validateUserInfo === "function")
    callbacks["user.validate"] = (payload) =>
      validateUserInfo(hydrate(payload), {context, request: callbackRequest(), headers: callbackRequest()?.headers} as unknown as Parameters<NonNullable<typeof validateUserInfo>>[1]);
  if (typeof ep.onExistingUserSignUp === "function")
    callbacks["user.existing"] = (payload) =>
      ep.onExistingUserSignUp!(hydrate(payload), undefined);
  if (typeof ep.customSyntheticUser === 'function') {
    callbacks['user.synthetic'] = payload => {
      const {id: _id, ...coreFields} = hydrate(payload.coreFields);
      return ep.customSyntheticUser!({coreFields, additionalFields: hydrate(payload.additionalFields), id: payload.id});
    };
  }
  if (typeof configuredId === 'function') callbacks['id.generate'] = input => configuredId(input);
  const identifierPolicy = options.verification?.storeIdentifier;
  const identifierMode = (policy: any) => typeof policy === 'object' && policy && 'hash' in policy ? 'custom' : policy;
  const defaultIdentifierPolicy = typeof identifierPolicy === 'object' && identifierPolicy && 'default' in identifierPolicy ? identifierPolicy.default : identifierPolicy;
  const identifierOverrides = typeof identifierPolicy === 'object' && identifierPolicy && 'default' in identifierPolicy ? identifierPolicy.overrides ?? {} : {};
  const customIdentifierHash = [defaultIdentifierPolicy, ...Object.values(identifierOverrides)].some(value => identifierMode(value) === 'custom');
  if (customIdentifierHash) callbacks['verification.hash'] = identifier => {
    let policy: any = defaultIdentifierPolicy;
    for (const [prefix, override] of Object.entries(identifierOverrides)) if (identifier.startsWith(prefix)) { policy = override; break; }
    if (!policy || typeof policy.hash !== 'function') throw new Error('No custom hash for identifier');
    return policy.hash(identifier);
  };
  const genericCallbacks: Record<string, string[]> = {};
  for (const provider of genericProviders) {
    const methods: string[] = [];
    if (provider.getToken) { methods.push('token'); callbacks['generic.token.' + provider.providerId] = async data => {
      const tokens = await provider.getToken(data);
      return {access_token: tokens.accessToken ?? null, refresh_token: tokens.refreshToken ?? null, id_token: tokens.idToken ?? '', access_token_expires_at: tokens.accessTokenExpiresAt?.toISOString(), refresh_token_expires_at: tokens.refreshTokenExpiresAt?.toISOString(), scope: tokens.scopes?.join(',') ?? null};
    }; }
    if (provider.mapProfileToUser) { methods.push('map'); callbacks['generic.map.' + provider.providerId] = profile => provider.mapProfileToUser(profile); }
    genericCallbacks[provider.providerId] = methods;
  }
  const fieldSchemas:Record<string,Record<string,FixtureOptions>>={user:{...options.user?.additionalFields},session:{...session.additionalFields},...Object.fromEntries(Object.entries(organizationOptions?.schema??{}).filter(([model])=>model!=='session').map(([model,schema])=>[model,{...(schema as any).additionalFields}]))};
  for(const plugin of options.plugins??[]){for(const [model,definition] of Object.entries(plugin.schema??{}) as [string,any][]){const fields=fieldSchemas[model]??={};for(const [name,field] of Object.entries(definition.fields??{})){fields[name]??=field as FixtureOptions}}}
  function hydrate(value:any):any {
   if(value instanceof Date)return value;
   if(Array.isArray(value))return value.map(hydrate);
   if(!value||typeof value!=='object')return value;
   const model='email' in value&&'name' in value&&'emailVerified' in value?'user':'userId' in value&&'token' in value&&'expiresAt' in value?'session':'organizationId' in value?('inviterId' in value?'invitation':'userId' in value?'member':'permission' in value?'organizationRole':''):'slug' in value&&'name' in value?'organization':'';
   const schema=fieldSchemas[model]??{};
   const result=Object.fromEntries(Object.entries(value).filter(([name])=>name!=='$vSession').map(([name,item])=>{
    if(schema[name]?.type==='json'||model==='organization'&&name==='metadata')return [name,item];
    if(typeof item==='string'&&(schema[name]?.type==='date'||['createdAt','updatedAt','expiresAt','accessTokenExpiresAt','refreshTokenExpiresAt'].includes(name)))return [name,new Date(item)];
    return [name,hydrate(item)];
   }));
   if(value.$vSession)Object.defineProperty(result,recordMetadata,{value:value.$vSession});
   return result;
  }
  const fieldCallbackNames: string[] = [];
  const fieldValue = (value: unknown) => ({value: value ?? null, undefinedValue: value === undefined});
  for (const [model, fields] of Object.entries({user:options.user?.additionalFields ?? {},session:session.additionalFields ?? {},...Object.fromEntries(Object.entries(organizationOptions?.schema??{}).filter(([model])=>model!=='session').map(([model,schema])=>[model,(schema as any).additionalFields??{}]))})) {
   for (const [name, field] of Object.entries(fields) as Array<[string,FixtureOptions]>) {
    if(typeof field.defaultValue==='function'){
     const method='field.'+model+'.'+name+'.default';fieldCallbackNames.push(method);
     callbacks[method]=()=>{const value=field.defaultValue();if(value instanceof Promise){void value.catch(()=>undefined);return {...fieldValue(undefined),asynchronous:true}}return fieldValue(value)};
    }
    if (field.validator?.input) {
     const method = 'field.'+model+'.'+name+'.validate'; fieldCallbackNames.push(method);
     callbacks[method] = value => {
      const result = field.validator.input['~standard'].validate(value);
      if (result instanceof Promise) {void result.catch(()=>undefined);return {...fieldValue(undefined),asynchronous:true};}
      return {...fieldValue(result.value),invalid:!!result.issues,message:result.issues?.[0]?.message ?? ''};
     };
    }
    if (field.transform?.input) {
     const method = 'field.'+model+'.'+name+'.transform'; fieldCallbackNames.push(method);
     callbacks[method] = async value => fieldValue(await field.transform.input(value));
    }
   }
  }
  const encodeFields = (fields: FixtureOptions) => JSON.stringify(Object.fromEntries(Object.entries(fields).map(([name,field]:[string,FixtureOptions])=>{
   const {validator:_validator,transform:_transform,...metadata} = field;return [name,metadata];
  })));
  const otpCallbackNames: string[] = [];
  const otpContext = (payload: FixtureOptions) => {
    const request = payload.request ? new Request(payload.request.url, {method: payload.request.method, headers: payload.request.headers, body: payload.request.method === 'POST' ? payload.request.body : undefined}) : undefined;
    return {context: {...context, session: hydrate(payload.session)}, headers: new Headers(payload.headers), request};
  };
  const twoFactorCallbackNames: string[] = [];
  for (const [name, callback] of Object.entries({
   send: twoFactorOptions?.otpOptions?.sendOTP,
   hash: twoFactorOptions?.otpOptions?.storeOTP?.hash,
   encrypt: twoFactorOptions?.otpOptions?.storeOTP?.encrypt,
   decrypt: twoFactorOptions?.otpOptions?.storeOTP?.decrypt,
   backupGenerate: twoFactorOptions?.backupCodeOptions?.customBackupCodesGenerate,
   backupEncrypt: twoFactorOptions?.backupCodeOptions?.storeBackupCodes?.encrypt,
   backupDecrypt: twoFactorOptions?.backupCodeOptions?.storeBackupCodes?.decrypt,
  })) {
   if (typeof callback !== 'function') continue;
   twoFactorCallbackNames.push(name);
   callbacks['twoFactor.'+name] = payload => callback(hydrate(payload.data), otpContext(payload));
  }
  for(const [name,hook] of Object.entries(organizationOptions?.organizationHooks??{}) as [string,any][]){callbacks['organization.'+name]=payload=>hook(hydrate(payload.data));}
  if(typeof organizationOptions?.invitationLimit==='function')callbacks['organization.invitationLimit']=payload=>organizationOptions!.invitationLimit(hydrate(payload.data));
  if(organizationOptions?.sendInvitationEmail)callbacks['organization.sendInvitationEmail']=payload=>organizationOptions!.sendInvitationEmail(hydrate(payload.data),payload.request?new Request(payload.request.url,{method:payload.request.method,headers:payload.request.headers}):undefined);
  if(typeof organizationOptions?.allowUserToCreateOrganization==='function')callbacks['organization.allowCreate']=payload=>organizationOptions!.allowUserToCreateOrganization(hydrate(payload.data));
  const anonymousCallbackNames: string[] = [];
  if (anonymousOptions?.generateName) { anonymousCallbackNames.push('name'); callbacks['anonymous.name'] = payload => anonymousOptions.generateName(otpContext(payload)); }
  if (anonymousOptions?.generateRandomEmail) { anonymousCallbackNames.push('email'); callbacks['anonymous.email'] = () => anonymousOptions.generateRandomEmail(); }
  if (anonymousOptions?.onLinkAccount) { anonymousCallbackNames.push('link'); callbacks['anonymous.link'] = payload => anonymousOptions.onLinkAccount({...hydrate(payload.data), ctx: otpContext(payload)}); }
  for (const [key, callback] of Object.entries({generate: otpOptions?.generateOTP, send: otpOptions?.sendVerificationOTP, hash: typeof otpOptions?.storeOTP === 'object' ? otpOptions.storeOTP.hash : undefined, encrypt: typeof otpOptions?.storeOTP === 'object' ? otpOptions.storeOTP.encrypt : undefined, decrypt: typeof otpOptions?.storeOTP === 'object' ? otpOptions.storeOTP.decrypt : undefined})) {
    if (typeof callback !== 'function') continue;
    otpCallbackNames.push(key);
    callbacks['otp.' + key] = payload => callback(payload.data, otpContext(payload));
  }
  if (ottOptions?.generateToken) callbacks['ott.generate'] = payload => ottOptions.generateToken(hydrate(payload), {context, headers: currentOperation.getStore()?.request?.headers, request: currentOperation.getStore()?.request});
  if (typeof ottOptions?.storeToken === 'object') callbacks['ott.hash'] = token => ottOptions.storeToken.hash(token);
  for (const [method, callback] of Object.entries(callbacks))
    bridge.setCallback(method, callback);
  if(typeof adminOptions?.bannedUserMessage==='function') callbacks['admin.bannedMessage']=payload=>adminOptions!.bannedUserMessage(hydrate(payload.data));
  for(const [method,callback] of Object.entries(callbacks)) bridge.setCallback(method,callback);
  const mappedPluginSchema=(configuration:any)=>{
   if(!configuration)return configuration;
   const result={...configuration,tables:{...configuration.tables},fields:{...configuration.fields}};
   for(const [model,definition] of [...Object.entries(adminOptions?.schema??{}),...Object.entries(organizationOptions?.schema??{})] as [string,any][]){
    if(definition.modelName)result.tables[model]=definition.modelName;
    result.fields[model]={...result.fields[model],...definition.fields};
   }
   return result;
  };
  await bridge.send("init", {
    options: {
      id_strategy: configuredId === 'uuid' || config.nativePostgres?.uuidIds || config.nativeMongo?.uuidIds ? 'uuid' : 'random',
      custom_id_generator: typeof configuredId === 'function',
      generic_oauth: genericProviders.map(({getToken: _getToken, mapProfileToUser: _mapProfile, ...provider}) => provider),
      generic_callbacks: genericCallbacks,
      account_linking_enabled: options.account?.accountLinking?.enabled ?? false,
      update_user_info_on_link: options.account?.accountLinking?.updateUserInfoOnLink ?? false,
      require_local_email_verified: options.account?.accountLinking?.requireLocalEmailVerified ?? true,
      disable_implicit_linking: options.account?.accountLinking?.disableImplicitLinking ?? false,
      trusted_linking_providers: options.account?.accountLinking?.trustedProviders ?? [],
      disable_email_sign_up: ep.disableSignUp ?? false,
      app_name: options.appName,
      two_factor_callbacks: twoFactorCallbackNames,
      two_factor: twoFactorOptions ? {...twoFactorOptions,
       otpOptions: {...twoFactorOptions.otpOptions, hasSender: !!twoFactorOptions.otpOptions?.sendOTP, storeOTP: typeof twoFactorOptions.otpOptions?.storeOTP === 'object' ? ('hash' in twoFactorOptions.otpOptions.storeOTP ? 'custom-hash' : 'custom-encryption') : twoFactorOptions.otpOptions?.storeOTP}, backupCodeOptions: {...twoFactorOptions.backupCodeOptions, storeBackupCodes: typeof twoFactorOptions.backupCodeOptions?.storeBackupCodes === 'object' ? 'custom' : twoFactorOptions.backupCodeOptions?.storeBackupCodes}} : undefined,
      anonymous: anonymousOptions,
      anonymous_callbacks: anonymousCallbackNames,
      email_otp: otpOptions ? {...otpOptions, storeOTP: typeof otpOptions.storeOTP === 'object' ? (otpOptions.storeOTP.hash ? 'custom-hash' : 'custom-encryption') : otpOptions.storeOTP} : null,
      email_otp_callbacks: otpCallbackNames,
      verification_hash_callback: customIdentifierHash,
      verification_options: options.verification ? {
       ...options.verification,
       storeIdentifier: identifierMode(defaultIdentifierPolicy),
       overrides: Object.fromEntries(Object.entries(identifierOverrides).map(([prefix, policy]) => [prefix, identifierMode(policy)])),
      } : {},
      one_time_token: ottOptions ? {...ottOptions, storeToken: typeof ottOptions.storeToken === 'object' ? 'custom-hasher' : ottOptions.storeToken} : null,
      ott_generate_callback: !!ottOptions?.generateToken,
      ott_hash_callback: typeof ottOptions?.storeToken === 'object',
      admin_schema: !!adminOptions,
      admin: adminOptions ? {...adminOptions,ac:undefined,schema:undefined,
       userFieldNames:adminOptions.schema?.user?.fields,sessionFieldNames:adminOptions.schema?.session?.fields,
       adminRoles: typeof adminOptions.adminRoles==='string' ? adminOptions.adminRoles.split(',') : adminOptions.adminRoles,
       roles:adminOptions.roles ? Object.fromEntries(Object.entries(adminOptions.roles).map(([name,role])=>[name,(role as any).statements])) : undefined,
       bannedUserMessage:typeof adminOptions.bannedUserMessage==='string'?adminOptions.bannedUserMessage:undefined,
      } : undefined,
      admin_banned_callback: typeof adminOptions?.bannedUserMessage==='function',
      admin_default_role: adminOptions?.defaultRole ?? 'user',
      open_api:openAPIOptions,
      organization_schema: !!organizationOptions,
      organization:organizationOptions&&!organizationOptions.teams?.enabled?{
       allowUserToCreateOrganization:typeof organizationOptions.allowUserToCreateOrganization==='boolean'?organizationOptions.allowUserToCreateOrganization:undefined,
       invitationExpiresIn:organizationOptions.invitationExpiresIn,invitationLimit:typeof organizationOptions.invitationLimit==='number'?organizationOptions.invitationLimit:undefined,cancelPendingInvitationsOnReInvite:organizationOptions.cancelPendingInvitationsOnReInvite,requireEmailVerificationOnInvitation:organizationOptions.requireEmailVerificationOnInvitation,
       organizationLimit:organizationOptions.organizationLimit,membershipLimit:organizationOptions.membershipLimit,creatorRole:organizationOptions.creatorRole,disableOrganizationDeletion:organizationOptions.disableOrganizationDeletion,
       dynamicAccessControl:organizationOptions.dynamicAccessControl,acStatements:organizationOptions.ac?.statements,
       roles:organizationOptions.roles?Object.fromEntries(Object.entries(organizationOptions.roles).map(([name,role])=>[name,(role as any).statements])):undefined,
      }:undefined,
      organization_hooks:Object.keys(organizationOptions?.organizationHooks??{}),
      organization_invitation_limit:typeof organizationOptions?.invitationLimit==='function',
      organization_invitation_email:!!organizationOptions?.sendInvitationEmail,
      organization_creation_callback:typeof organizationOptions?.allowUserToCreateOrganization==='function',
      organization_fields_json:Object.fromEntries(Object.entries(organizationOptions?.schema??{}).filter(([model])=>model!=='session').map(([model,schema])=>[model,encodeFields((schema as any).additionalFields??{})])),
      organization_teams: organizationOptions?.teams?.enabled ?? false,
      logout_providers: logoutProviders,
      endpoint_plugins: endpointPlugins,
      jwt_expiration_json: jwtOptions?.jwt?.expirationTime === undefined ? '' : JSON.stringify(jwtOptions.jwt.expirationTime instanceof Date ? Math.floor(jwtOptions.jwt.expirationTime.getTime() / 1000) : jwtOptions.jwt.expirationTime),
      defer_migrations: config.deferMigrations ?? false,
      jwt_plugin: !!jwtOptions,
      custom_jwk_store: !!jwtOptions?.adapter,
      jwt_options: jwtOptions && {
        algorithm: jwtOptions.jwks?.keyPairConfig?.alg ?? '',
        remote_url: jwtOptions.jwks?.remoteUrl ?? '',
        key_pair_configs: (jwtOptions.jwks?.keyPairConfigs ?? []).map((key: FixtureOptions) => { assertKeys(key, ['alg', 'crv', 'modulusLength'], 'jwt.jwks.keyPairConfigs'); return {algorithm: key.alg, curve: key.crv ?? '', modulus_length: key.modulusLength ?? 2048}; }),
        curve: jwtOptions.jwks?.keyPairConfig?.crv ?? '',
        modulus_length: jwtOptions.jwks?.keyPairConfig?.modulusLength ?? 2048,
        session_cookie_cache: jwtOptions.sessionCookieCache ?? false,
        rotation_interval: jwtOptions.jwks?.rotationInterval ?? 0,
        grace_period: jwtOptions.jwks?.gracePeriod ?? 2592000,
        disable_private_key_encryption: jwtOptions.jwks?.disablePrivateKeyEncryption ?? false,
        jwks_path: jwtOptions.jwks?.jwksPath ?? '/jwks',
        disable_setting_jwt_header: jwtOptions.disableSettingJwtHeader ?? false,
        issuer: jwtOptions.jwt?.issuer ?? null,
        audience: typeof jwtOptions.jwt?.audience === 'string' ? jwtOptions.jwt.audience : null,
        audiences: Array.isArray(jwtOptions.jwt?.audience) ? jwtOptions.jwt.audience : null,
      },
      storage: config.nativeMongo ? 'mongo' : config.nativePostgres ? 'postgres' : stateless || isNativeMemoryAdapter(options.database) ? 'memory' : 'sqlite',
	  sqlite_path: config.nativeSqlite ?? ':memory:',
      postgres: mappedPluginSchema(config.nativePostgres),
      mongo: mappedPluginSchema(config.nativeMongo),
      stateless_sessions: stateless,
      secondary_storage: !!options.secondaryStorage,
      redis_tcp: nativeRedis?.tcp,
      redis_key_prefix: nativeRedis?.keyPrefix,
      cookie_cache: {
        enabled: cacheOptions.enabled,
        strategy: cacheOptions.strategy,
        max_age: cacheOptions.maxAge,
        refresh_cache: typeof cacheOptions.refreshCache === 'object' ? true : cacheOptions.refreshCache,
        update_age: typeof cacheOptions.refreshCache === 'object' ? cacheOptions.refreshCache.updateAge : undefined,
        version: typeof session.cookieCache?.version === 'string' ? session.cookieCache.version : '1',
      },
      store_session_in_database: session.storeSessionInDatabase ?? false,
      preserve_session_in_database: session.preserveSessionInDatabase ?? false,
      disable_csrf_check: advanced.disableCSRFCheck ?? null,
      disable_origin_check: advanced.disableOriginCheck === true,
      skip_origin_check_paths: [...skippedOriginPaths, ...(Array.isArray(advanced.disableOriginCheck) ? advanced.disableOriginCheck : [])],
      cookie_names: cookieNames,
      google_profile_callback: !!google?.mapProfileToUser,
      google_provider: google && google.enabled !== false ? {...google, clientId: Array.isArray(google.clientId) ? '' : google.clientId, clientIds: Array.isArray(google.clientId) ? google.clientId : undefined} : null,
      store_account_cookie: options.account?.storeAccountCookie ?? false,
      encrypt_oauth_tokens: options.account?.encryptOAuthTokens ?? false,
      account_cookie_bind_user: !(Object.hasOwn(options, 'database') && options.database === undefined),
      default_cookie_attributes_json: JSON.stringify(advanced.defaultCookieAttributes ?? {}),
      cookie_attributes_json: JSON.stringify(cookieAttributes),
      cookie_prefix: advanced.cookiePrefix ?? 'better-auth',
      secure_cookies: advanced.useSecureCookies ?? null,
      cross_subdomain_cookies: advanced.crossSubDomainCookies?.enabled ?? false,
      cookie_domain: advanced.crossSubDomainCookies?.domain ?? '',
      base_url: Object.hasOwn(options, 'baseURL') && options.baseURL === undefined ? '' : baseURL,
      base_path: basePath,
      secrets_json: options.secrets === undefined ? '' : JSON.stringify(options.secrets),
      secret:
        options.secret ??
        (options.secrets ? '' : "better-auth-secret-that-is-long-enough-for-validation-test"),
      trusted_origins: Array.isArray(options.trustedOrigins) ? options.trustedOrigins : [],
      email_and_password: ep.enabled ?? true,
      verification_delivery_enabled: typeof ev.sendVerificationEmail === 'function',
      auto_sign_in_after_verification: ev.autoSignInAfterVerification ?? false,
      delete_user_enabled: deleteUser?.enabled ?? false,
      delete_token_expires_in: deleteUser?.deleteTokenExpiresIn ?? 86400,
      change_email_enabled: options.user?.changeEmail?.enabled ?? false,
      update_email_without_verification: options.user?.changeEmail?.updateEmailWithoutVerification ?? false,
      require_email_verification: ep.requireEmailVerification ?? false,
      auto_sign_in: ep.autoSignIn ?? true,
      min_password_length: ep.minPasswordLength ?? 8,
      max_password_length: ep.maxPasswordLength ?? 128,
      send_verification_on_sign_up: ev.sendOnSignUp,
      send_verification_on_sign_in: ev.sendOnSignIn ?? false,
      session_expires_in: session.expiresIn ?? 604800,
      session_update_age: session.updateAge ?? 86400,
      session_fresh_age: session.freshAge ?? 86400,
      defer_session_refresh: session.deferSessionRefresh ?? false,
      disable_session_refresh: session.disableSessionRefresh ?? false,
      verification_expires_in: ev.expiresIn ?? 3600,
      rate_limit_max: options.rateLimit?.enabled
        ? (options.rateLimit.max ?? 100)
        : 0,
      rate_limit_window: options.rateLimit?.window ?? 60,
      rate_limit_storage: options.rateLimit?.storage ?? 'memory',
      rate_limit_rules: Object.fromEntries(Object.entries(options.rateLimit?.customRules ?? {}).map(([path, rule]) => {if (typeof rule === 'function') throw new Error('Dynamic rate limit rules remain unported'); return [path, rule === false ? {disabled: true} : rule];})),
      trust_proxy_origin_headers: advanced.trustedProxyHeaders ?? false,
      real_passwords: config.realPasswords ?? false,
      fail_delivery: config.failDelivery ?? false,
      magic_link: !!magicLinkOptions || (config.magicLink ?? false),
      remote_passwords: true,
      password_reset_expires_in: ep.resetPasswordTokenExpiresIn ?? 3600,
      revoke_sessions_on_password_reset: ep.revokeSessionsOnPasswordReset ?? false,
      callback_methods: Object.keys(callbacks),
      account_fields_json: JSON.stringify(options.account?.fields ?? {}),
      field_callbacks: fieldCallbackNames,
      user_fields_json: encodeFields(options.user?.additionalFields ?? {}),
      session_fields_json: encodeFields(session.additionalFields ?? {}),
    },
  });

  function recordLogs(events: {level: string; message: string}[]) {
    const levels = ["debug", "info", "warn", "error"];
    for (const event of events) if (event.level === 'warn' && event.message.startsWith('[Deprecation]')) console.warn(event.message);
    if (
      !options.logger?.disabled &&
      typeof options.logger?.log === "function"
    ) {
      for (const event of events) {
        if (
          levels.indexOf(event.level) >=
          levels.indexOf(options.logger.level ?? "info")
        )
          options.logger.log(event.level as 'debug' | 'info' | 'warn' | 'error', event.message);
      }
    }
  }
  function callbackRequest() { return safeCloneRequest(currentOperation.getStore()?.request); }
  const emails: any[] = [];
  const cookieInfo = await bridge.send('internal', {method: 'cookieInfo'});
  context.authCookies = JSON.parse(cookieInfo.value_json);
  context.socialProviders = JSON.parse((await bridge.send('internal', {method: 'listOAuthProviders', arguments_json: '[]'})).value_json);
  for (const provider of context.socialProviders) {
    let required = provider.requiresIdTokenNonce;
    Object.defineProperty(provider, 'requiresIdTokenNonce', {get: () => required, set: value => {
      required = value;
      void bridge.send('internal', {method: 'setOAuthNonceRequirement', arguments_json: transportJSON([provider.id, value])});
    }});
  }

  const secretInfo = JSON.parse((await bridge.send('internal', {method: 'secretConfig'})).value_json);
  context.secretConfig = typeof secretInfo === 'string' ? secretInfo : {...secretInfo, keys: new Map(Object.entries(secretInfo.keys).map(([version, value]) => [Number(version), value as string]))};
  async function dispatch(request: Request, direct = false) {
    return currentOperation.run({request: direct ? undefined : safeCloneRequest(request)}, async () => {
    let result;
    if (!direct && requestHooks.length) {
      const prepared = await bridge.prepareRequest(request);
      let effective = request;
      let response: Response | undefined;
      for (const hook of requestHooks) {
        const returned = await hook(effective, context) as {request?: Request; response?: Response} | undefined;
        if (!returned) continue;
        assertKeys(returned, ['request', 'response'], 'plugin.onRequest');
        if (returned.request) effective = returned.request;
        if (returned.response) { response = returned.response; break; }
      }
      const state = currentOperation.getStore();
      if (state) state.request = safeCloneRequest(effective);
      result = await bridge.completeRequest(prepared, effective === request ? undefined : effective, response);
    } else result = await bridge.request(request, direct).catch(error => {
      const transactionError = currentOperation.getStore()?.transactionError;
      if (direct && transactionError) throw transactionError;
      throw error;
    });
    const transactionError = currentOperation.getStore()?.transactionError;
    if (direct && result.response.status === 500 && transactionError) throw transactionError;
    const storeFailure = currentOperation.getStore()?.storeFailure;
    if (direct && result.response.status === 500 && storeFailure !== undefined) {
      const body = await result.response.clone().json();
      if (body.code === 'FAILED_TO_GET_SESSION') throw APIError.from('INTERNAL_SERVER_ERROR', {code: body.code, message: body.message}, {cause: storeFailure});
    }
    for (const email of result.emails) {
      emails.push(email);
    }
    recordLogs(result.logs ?? []);
    return result.response;
    });
  }

  const api: Record<string, (args?: FixtureOptions) => Promise<any>> = {};
  const instanceRoutes = {...routes};
  if(openAPIOptions)instanceRoutes.openAPIReference=['GET',openAPIOptions.path??'/reference'];
  if (jwtOptions) {
    instanceRoutes.getJwks = ['GET', jwtOptions.jwks?.jwksPath ?? '/jwks'];
    instanceRoutes.getToken = ['GET', '/token'];
  }
  for (const [name, [method, path]] of Object.entries(instanceRoutes)) {
    api[name] = async (args = {}) => {
      const requestMethod = String(args.method ?? method).toUpperCase();
      const url = new URL(baseURL + basePath + path);
      for (const [key, value] of Object.entries(args.query ?? {}))
        url.searchParams.set(key, String(value));
      const headers = new Headers(args.headers);
      headers.set("content-type", "application/json");
      if (nativeTransactionScope.getStore() && (name !== 'getToken' || requestMethod !== 'GET')) throw new Error('Unported native transaction API: ' + name);
      const response = nativeTransactionScope.getStore()
        ? new Response((await bridge.send('internal', {method: 'getTokenFromContext', arguments_json: transportJSON([Object.fromEntries(headers)])})).value_json, {headers: {'content-type': 'application/json'}})
        : await dispatch(
        new Request(url, {
          method: requestMethod,
          headers,
          body:
            requestMethod === "POST"
              ? JSON.stringify(args.body ?? {})
              : undefined,
        }),
        true,
      );
      if (args.asResponse) return response;
      const body = await response.json();
      if (!response.ok) {
        throw APIError.fromStatus(
          (statuses[response.status] ?? "INTERNAL_SERVER_ERROR") as any,
          body,
        );
      }
      const result = hydrate(body);
      if (args.returnHeaders)
        return { response: result, headers: response.headers };
      return result;
    };
  }
  if (jwtOptions) for (const name of ['signJWT', 'verifyJWT']) {
    api[name] = async (args = {}) => {
      assertKeys(args.body ?? {}, name === 'signJWT' ? ['payload', 'overrideOptions'] : ['token', 'issuer'], name);
      const values = name === 'signJWT' ? [args.body?.payload] : [args.body?.token, args.body?.issuer ?? ''];
      const overridden = name === 'signJWT' && args.body?.overrideOptions !== undefined;
      const reply = overridden ? await nativeJWTCall('signJWTWith', [args.body.payload, {}], {...jwtOptions, ...args.body.overrideOptions}) : await bridge.send('internal', {method: name, arguments_json: transportJSON(values)});
      recordLogs(reply.logs ?? []);
      const value = overridden ? {token: JSON.parse(reply.value_json)} : JSON.parse(reply.value_json);
      if (args.asResponse) return new Response(JSON.stringify(value), {headers: {'content-type': 'application/json'}});
      return args.returnHeaders ? {response: hydrate(value), headers: new Headers()} : hydrate(value);
    };
  }
  if (otpOptions) for (const name of ['createVerificationOTP', 'getVerificationOTP']) api[name] = async (args: FixtureOptions = {}) => {
    try {
      const reply = await bridge.send('internal', {method: name, arguments_json: transportJSON([args.body ?? args.query ?? {}])});
      return hydrate(JSON.parse(reply.value_json));
    } catch (error) {
      const native = error as Error & {statusCode: number; body: {code: string; message: string}};
      throw APIError.fromStatus((statuses[native.statusCode] ?? 'INTERNAL_SERVER_ERROR') as any, native.body);
    }
  };
  api.setPassword = async (args = {}) => {
    const headers = new Headers(args.headers ?? currentUserHeaders.getStore());
    try {
      const reply = await bridge.send('internal', {method: 'setPassword', arguments_json: transportJSON([args.body?.newPassword ?? '', Object.fromEntries(headers)])});
      return JSON.parse(reply.value_json);
    } catch (error) {
      const native = error as Error & {statusCode: number; body: {code: string; message: string}};
      throw APIError.fromStatus((statuses[native.statusCode] ?? 'INTERNAL_SERVER_ERROR') as any, native.body);
    }
  };
  const auth = {
    $context: Promise.resolve(context),
    api: api as typeof api & { addMember:OrganizationAPI<O,'addMember'>; updateOrgRole:OrganizationAPI<O,'updateOrgRole'>;listMembers:OrganizationAPI<O,'listMembers'>; listOrgRoles:OrganizationAPI<O,'listOrgRoles'>;getOrgRole:OrganizationAPI<O,'getOrgRole'>; getFullOrganization(args?:FixtureOptions):Promise<({[key:string]:any;members:{[key:string]:any;user:{[key:string]:any;email:string}}[]})|null>; listUsers(args?:FixtureOptions):Promise<{users:UserWithRole[];total:number;limit?:number;offset?:number}>; signInEmail: FixtureResponseAPI; verifyTOTP: FixtureResponseAPI; verifyTwoFactorOTP: FixtureResponseAPI; enableTwoFactor: FixtureEnableTwoFactorAPI; signUpEmail: SignUpAPI<O>; getSession: SessionAPI<O>; getJwks(args?: FixtureOptions): Promise<JSONWebKeySet>; generateBackupCodes(args?: FixtureOptions): Promise<{status: boolean; backupCodes: string[]}>; viewBackupCodes(args?: FixtureOptions): Promise<{status: boolean; backupCodes: string[]}> },
    handler: (request: Request) => dispatch(request),
    options:{...options,emailAndPassword:{...ep,enabled:ep.enabled??true}} as O & {emailAndPassword:{enabled:boolean}},
  };
  const clientOptions = {
    baseURL: baseURL + basePath,
    fetchOptions: {
      customFetchImpl: async (
        input: string | URL | Request,
        init?: RequestInit,
      ) => {
        const request = new Request(input, init);
        currentUserHeaders.getStore()?.forEach((value, key) => {
          if (!request.headers.has(key)) request.headers.set(key, value);
        });
        // Browser fetch supplies this header; Node's fetch does not.
        if (
          !["GET", "HEAD"].includes(request.method) &&
          !request.headers.has("origin")
        )
          request.headers.set("origin", new URL(baseURL).origin);
        return dispatch(request);
      },
    },
  };
  Object.assign(clientOptions, { plugins: config.clientOptions?.plugins ?? [] });
  const clientPlugins = (config.clientOptions?.plugins ?? []) as C extends {clientOptions: {plugins: infer P extends NonNullable<BetterAuthClientOptions['plugins']>}} ? P : [];
  const client = createAuthClient({...clientOptions, plugins: clientPlugins});
  const cookieSetter =
    (headers: Headers) =>
    ({ response }: { response: Response }) => {
      const setCookie = response.headers.get('set-cookie');
      if (!setCookie) return;
      const cookies = parseSetCookieHeader(setCookie);
      const existing = new Map((headers.get("cookie") ?? "").split(";").filter(Boolean).map(item => {
        const separator = item.indexOf("=");
        return [item.slice(0, separator).trim(), item.slice(separator + 1)] as const;
      }));
      for (const [key, value] of cookies) {
        if (value["max-age"] === 0) existing.delete(key);
        else existing.set(key, value.value);
      }
      headers.set(
        "cookie",
        [...existing].map(([key, value]) => `${key}=${value}`).join("; "),
      );
    };
  const testUser = {
    email: "test@test.com",
    password: "test123456",
    name: "test user",
    ...config.testUser,
  };
  if (!config.disableTestUser) await api.signUpEmail({ body: testUser });

  async function signInWithTestUser(): Promise<{
    user: FixtureOptions; session: FixtureSession; headers: Headers;
    runWithUser<T>(callback: (headers: Headers) => T): T;
  }> {
    const response = await api.signInEmail({
      body: testUser,
      asResponse: true,
    });
    const headers = new Headers();
    cookieSetter(headers)({ response });
    const result = await api.getSession({ headers });
    return {
      ...result,
      headers,
      runWithUser: <T>(callback: (headers: Headers) => T) =>
        currentUserHeaders.run(headers, () => callback(headers)),
    };
  }
  async function signInWithUser(email: string, password: string) {
    const response = await api.signInEmail({body: {email, password}, asResponse: true});
    const headers = new Headers();
    cookieSetter(headers)({response});
    const result = await api.getSession({headers});
    return {...result, res:hydrate(await response.json()), headers, runWithUser: <T>(callback: (headers: Headers) => T) => currentUserHeaders.run(headers, () => callback(headers))};
  }
  const db = {
    async create<T = Record<string, unknown>>(args: FixtureOptions): Promise<T> {
      assertKeys(args, ['model', 'data'], 'db.create');
      if(['organization','member','invitation','organizationRole'].includes(args.model)){const reply=await bridge.send('internal',{method:'adapterCreateOrganizationModel',arguments_json:transportJSON([args.model,args.data])});return hydrate(JSON.parse(reply.value_json));}
      if (args.model !== 'twoFactor') throw new Error('Native fixture create requires twoFactor model');
      const reply = await bridge.send('internal', {method:'adapterCreateTwoFactor',arguments_json:transportJSON([args.data])});
      return hydrate(JSON.parse(reply.value_json));
    },
    async deleteMany(args: FixtureOptions): Promise<number> {
      assertKeys(args, ['model', 'where'], 'db.deleteMany');
      if (args.model !== 'session' || args.where?.length !== 1 || args.where[0].field !== 'userId' || (args.where[0].operator && args.where[0].operator !== 'eq')) throw new Error('V db.deleteMany requires a session userId equality filter');
      const reply = await bridge.send('internal', {method: 'adapterDeleteSessions', arguments_json: transportJSON([args.where[0].value])});
      return JSON.parse(reply.value_json);
    },
    async delete(args: FixtureOptions) {
      assertKeys(args, ['model', 'where'], 'db.delete');
      if(['organization','member','invitation','organizationRole'].includes(args.model)){await bridge.send('internal',{method:'adapterDeleteOrganizationModel',arguments_json:transportJSON([args.model,args.where])});return;}
      if (args.model === 'account' && args.where?.length === 1 && args.where[0].field === 'id' && (!args.where[0].operator || args.where[0].operator === 'eq')) {
       await bridge.send('internal',{method:'deleteAccount',arguments_json:transportJSON([args.where[0].value])}); return;
      }
      if (args.model !== 'session' || args.where?.length !== 1 || args.where[0].field !== 'token' || (args.where[0].operator && args.where[0].operator !== 'eq')) throw new Error('V db.delete requires a session token equality filter');
      await bridge.send('internal', {method: 'adapterDeleteSession', arguments_json: transportJSON([args.where[0].value])});
    },
    async update<T = Record<string, unknown>>(args: FixtureOptions): Promise<T | null> {
      assertKeys(args, ["model", "where", "update"], "db.update");
      if (args.model === 'verification' && args.where?.length === 1 && ['id','identifier'].includes(args.where[0].field) && (!args.where[0].operator || args.where[0].operator === 'eq')) {
       const reply = await bridge.send('internal',{method:'adapterUpdateVerification',arguments_json:transportJSON([args.where[0].field,args.where[0].value,args.update])});
       return hydrate(JSON.parse(reply.value_json));
      }
      if (args.model === 'twoFactor' && args.where?.length === 1 && ['id','userId'].includes(args.where[0].field) && (!args.where[0].operator || args.where[0].operator === 'eq')) {
       const reply = await bridge.send('internal',{method:'adapterUpdateTwoFactor',arguments_json:transportJSON([args.where[0].field,args.where[0].value,args.update])});
       return hydrate(JSON.parse(reply.value_json));
      }
      if (args.model === 'user' && args.where?.length === 1 && ['email', 'id'].includes(args.where[0].field) && (!args.where[0].operator || args.where[0].operator === 'eq')) {
        const reply = await bridge.send('internal', {method: 'adapterUpdateUser', arguments_json: transportJSON([args.where[0].field, args.where[0].value, args.update])});
        return hydrate(JSON.parse(reply.value_json));
      }
      if (args.model !== "session" || args.where?.length !== 1 || args.where[0].field !== "id" || (args.where[0].operator && args.where[0].operator !== "eq"))
        throw new Error("V fixture db.update currently requires a session id equality filter");
      const reply = await bridge.send("internal", {method: "adapterUpdateSession", arguments_json: transportJSON([args.where[0].value, args.update])});
      return hydrate(JSON.parse(reply.value_json));
    },
    async findOne<T = Record<string, unknown>>(args: FixtureOptions): Promise<T | null> {
      assertKeys(args, ['model', 'where'], 'db.findOne');
      const reply = await bridge.send('inspect', {model: args.model, where_json: transportJSON(args.where ?? [])});
      return hydrate(JSON.parse(reply.records_json))[0] ?? null;
    },
    async findMany<T = Record<string, unknown>>(
      args: FixtureOptions,
    ): Promise<T[]> {
      assertKeys(args, ["model", "where"], "db.findMany");
      const reply = await bridge.send("inspect", { model: args.model, where_json: transportJSON(args.where ?? []) });
      return hydrate(JSON.parse(reply.records_json)) as T[];
    },
  };
  return {
    auth,
    customFetchImpl: clientOptions.fetchOptions.customFetchImpl,
    client,
    testUser,
    cookieSetter,
    sessionSetter: (headers: Headers) => ({response}: {response: Response}) => {
      const setCookie = response.headers.get('set-cookie');
      if (!setCookie) return;
      const token = parseSetCookieHeader(setCookie).get('better-auth.session_token')?.value;
      headers.set('cookie', `better-auth.session_token=${token}`);
    },
    signInWithTestUser,
    signInWithUser,
    runWithUser: async <T>(email: string, password: string, callback: (headers: Headers) => T) => {
      const {headers} = await signInWithUser(email, password);
      return currentUserHeaders.run(headers, () => callback(headers));
    },
    bridge,
    emails,
    db,
  };
}

function safeCloneRequest(request?: Request): Request | undefined {
  if (!request) return undefined;
  try { return request.clone(); }
  catch { return new Request(request.url, {method: request.method, headers: request.headers}); }
}
