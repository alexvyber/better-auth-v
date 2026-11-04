import { APIError } from "@better-auth/core/error";
import type { BetterAuthClientOptions, BetterAuthOptions } from "@better-auth/core";
import type { Auth } from "better-auth";
import type { JSONWebKeySet } from 'jose';
import { AsyncLocalStorage } from "node:async_hooks";
import { createAuthClient } from "better-auth/client";
import { parseSetCookieHeader } from "better-auth/cookies";
import { afterAll } from "vitest";
import { Bridge, recordMetadata, transportJSON } from "./bridge.js";
import { isNativeMemoryAdapter } from "./memory-adapter.js";
import { nativeEndpoint, freshSessionMiddleware } from './endpoint.js';
import { schemaPluginOptions } from './plugins.js';

// Upstream fixtures are intentionally dynamically shaped. This boundary accepts
// their objects; unsupported server configuration fails rather than being ignored.
type FixtureOptions = Record<string, any>;
interface FixtureUserOptions extends FixtureOptions {
  additionalFields?: FixtureOptions;
  validateUserInfo?: (context: {
    user: Record<string, unknown>;
    source: { action: string; method: string };
  }) => unknown;
}
interface ServerOptions {
  plugins?: BetterAuthOptions['plugins'];
  database?: BetterAuthOptions["database"];
  baseURL?: string;
  basePath?: string;
  secret?: string;
  trustedOrigins?: string[];
  emailAndPassword?: Partial<NonNullable<BetterAuthOptions['emailAndPassword']>> & FixtureOptions;
  emailVerification?: FixtureOptions;
  session?: NonNullable<BetterAuthOptions["session"]> & FixtureOptions;
  advanced?: FixtureOptions;
  rateLimit?: FixtureOptions;
  logger?: FixtureOptions;
  secondaryStorage?: NonNullable<BetterAuthOptions["secondaryStorage"]> & Record<string, any>;
  account?: FixtureOptions;
  user?: FixtureUserOptions;
  databaseHooks?: BetterAuthOptions["databaseHooks"];
}
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
  listSessions(userId: string): Promise<FixtureSession[]>;
  createSession(userId: string, dontRememberMe?: boolean): Promise<FixtureSession>;
  findSession(token: string): Promise<{session: FixtureSession; user: FixtureOptions} | null>;
}
interface FixtureTransactionAdapter {
  findOne(query: FixtureOptions): Promise<any>;
  options: {adapterConfig: {transaction: boolean}};
  transaction(callback: (transaction: FixtureTransactionAdapter) => Promise<unknown>): Promise<unknown>;
}
const instances = new Set<Bridge>();
const currentUserHeaders = new AsyncLocalStorage<Headers>();
const currentOperation = new AsyncLocalStorage<{ transactionError?: unknown; storeFailure?: unknown }>();
afterAll(async () => {
  await Promise.all([...instances].map((instance) => instance.close()));
  instances.clear();
});

const routes: Record<string, [string, string]> = {
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
  deleteUser: ["POST", "/delete-user"],
  requestPasswordReset: ["POST", "/request-password-reset"],
  resetPassword: ["POST", "/reset-password"],
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

function hydrate(value: any): any {
  if (Array.isArray(value)) return value.map(hydrate);
  if (value && typeof value === "object") {
    const result = Object.fromEntries(
      Object.entries(value).filter(([key]) => key !== "$vSession").map(([key, item]) => [
        key,
        ["createdAt", "updatedAt", "expiresAt"].includes(key) &&
        typeof item === "string"
          ? new Date(item)
          : hydrate(item),
      ]),
    );
    if (value.$vSession) Object.defineProperty(result, recordMetadata, { value: value.$vSession });
    return result;
  }
  return value;
}

export async function getTestInstance<const O extends ServerOptions = {}>(
  options: O & ServerOptions = {} as O & ServerOptions,
  config: FixtureOptions = {},
) {
  assertKeys(
    options,
    [
      "baseURL",
      "plugins",
      "database",
      "basePath",
      "secret",
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
    ],
    "options",
  );
  assertKeys(
    config,
    [
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
  const ep = options.emailAndPassword ?? {};
  const ev = options.emailVerification ?? {};
  const session = options.session ?? {};
  let jwtOptions: FixtureOptions | undefined;
  let adminOptions: FixtureOptions | undefined;
  let organizationOptions: FixtureOptions | undefined;
  const endpointPlugins: FixtureOptions[] = [];
  const endpointCallbacks: Record<string, (payload: any) => Promise<unknown>> = {};
  for (const plugin of options.plugins ?? []) {
    if (plugin.id === 'admin' || plugin.id === 'organization') {
      const input = schemaPluginOptions(plugin);
      if (!input) throw new Error(`Native schema plugin ${plugin.id} requires its fixture descriptor`);
      if (plugin.id === 'admin') {
        assertKeys(input, ['defaultRole'], 'admin');
        adminOptions = input;
      } else {
        assertKeys(input, ['teams'], 'organization');
        assertKeys(input.teams ?? {}, ['enabled'], 'organization.teams');
        organizationOptions = input;
      }
      continue;
    }
    if (plugin.id !== 'jwt') {
      assertKeys(plugin, ['id', 'endpoints'], `plugin.${plugin.id}`);
      const routes: FixtureOptions[] = [];
      for (const [name, endpoint] of Object.entries(plugin.endpoints ?? {})) {
        const descriptor = nativeEndpoint(endpoint);
        if (!descriptor) throw new Error(`Plugin endpoint ${plugin.id}.${name} needs a native fixture descriptor`);
        assertKeys(descriptor.options, ['method', 'use'], `plugin.${plugin.id}.${name}`);
        const use = descriptor.options.use ?? [];
        if (use.some(middleware => middleware !== freshSessionMiddleware)) throw new Error('Unsupported native middleware descriptor');
        const method = descriptor.options.method ?? 'GET';
        if (typeof method !== 'string') throw new Error('Endpoint method arrays are not bridged yet');
        routes.push({name, path: descriptor.path, method, fresh_session: use.includes(freshSessionMiddleware)});
        endpointCallbacks[`plugin.${plugin.id}.${name}`] = async payload => {
          const request = new Request(payload.request.url, {method: payload.request.method, headers: payload.request.headers, body: payload.request.method === 'POST' ? payload.request.body : undefined});
          const responseHeaders = new Headers();
          const result = await descriptor.handler({
            request, headers: request.headers, query: Object.fromEntries(new URL(request.url).searchParams),
            body: payload.request.body ? JSON.parse(payload.request.body) : undefined,
            context: {session: hydrate(payload.session)},
            setHeader: (name: string, value: string) => responseHeaders.set(name, value),
            json: (body: unknown) => body,
          });
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
    assertKeys(jwtOptions.jwks ?? {}, ['rotationInterval', 'gracePeriod', 'disablePrivateKeyEncryption', 'jwksPath', 'keyPairConfig', 'remoteUrl'], 'jwt.jwks');
    assertKeys(jwtOptions.jwks?.keyPairConfig ?? {}, ['alg', 'crv', 'modulusLength'], 'jwt.jwks.keyPairConfig');
    assertKeys(jwtOptions.jwt ?? {}, ['issuer', 'audience', 'sign'], 'jwt.jwt');
  }
  const stateless = Object.hasOwn(options, 'database') && options.database === undefined && !options.secondaryStorage;
  const cacheOptions = session.cookieCache ?? {};
  assertKeys(cacheOptions, ['enabled', 'strategy', 'maxAge', 'refreshCache', 'version'], 'session.cookieCache');
  const advanced = options.advanced ?? {};
  assertKeys(
    ep,
    [
      "enabled",
      "requireEmailVerification",
      "autoSignIn",
      "minPasswordLength",
      "maxPasswordLength",
      "sendResetPassword",
      "password",
      "onExistingUserSignUp",
      "customSyntheticUser",
    ],
    "emailAndPassword",
  );
  assertKeys(
    ev,
    ["sendOnSignUp", "sendOnSignIn", "sendVerificationEmail", "expiresIn"],
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
    ["disableCSRFCheck", "disableOriginCheck", "trustedProxyHeaders"],
    "advanced",
  );
  assertKeys(
    options.user ?? {},
    ["additionalFields", "validateUserInfo"],
    "user",
  );
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
  ]) {
    for (const field of Object.values(schema) as FixtureOptions[]) {
      assertKeys(
        field,
        ["type", "required", "input", "returned", "defaultValue"],
        "additionalField",
      );
      if (typeof field.defaultValue === "function")
        throw new Error("Functional field defaults are not bridged yet");
    }
  }
  if (advanced.disableCSRFCheck || advanced.disableOriginCheck)
    throw new Error("Disabling security checks is unsupported");

  assertKeys(options.account ?? {}, ['fields'], 'account');
  assertKeys(options.account?.fields ?? {}, ['id', 'userId', 'providerId', 'accountId'], 'account.fields');
  const baseURL = options.baseURL ?? `http://localhost:${config.port ?? 3000}`;
  const basePath = options.basePath ?? "/api/auth";
  const bridge = new Bridge();
  instances.add(bridge);
  const callbacks: Record<string, (payload: any) => unknown> = {...endpointCallbacks};
  const internalAdapter = {} as FixtureInternalAdapter;
  const internalNames = ['createSession', 'findSession', 'listSessions', 'updateSession', 'deleteSession', 'deleteUserSessions', 'createUser', 'updateUser', 'findUserById', 'findUserByEmail', 'createAccount', 'findCredentialAccount', 'deleteAccount'];
  for (const name of internalNames) {
    internalAdapter[name] = async (...args: any[]) => {
      const reply = await bridge.send('internal', {method: name, arguments_json: transportJSON(args)});
      return hydrate(JSON.parse(reply.value_json));
    };
    callbacks['internal.' + name] = (args: any[]) => internalAdapter[name](...args);
  }
  const adapter: FixtureTransactionAdapter = {
    async findOne(query) {
      const reply = await bridge.send('internal', {method: 'adapterFindOne', arguments_json: transportJSON([query])});
      return hydrate(JSON.parse(reply.value_json));
    },
    options: {adapterConfig: {transaction: true}},
    async transaction(callback): Promise<unknown> { return callback(adapter); },
  };
  const context = {
    adapter, internalAdapter, options,
    secret: options.secret ?? 'better-auth-secret-that-is-long-enough-for-validation-test',
    session: null as unknown,
    authCookies: {} as {sessionToken: {name: string}; sessionData: {name: string}},
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
  callbacks['internal.adapter.findOne'] = async ([query]: FixtureOptions[]) => {
    try { return await adapter.findOne(query); }
    catch (error) { const state = currentOperation.getStore(); if (state) state.storeFailure = error; throw error; }
  };
  if (jwtOptions?.jwt?.sign) callbacks['jwt.sign'] = payload => jwtOptions!.jwt.sign(payload);
  if (jwtOptions?.adapter) {
    const store = jwtOptions.adapter;
    if (store.getJwks) callbacks['jwt.getJwks'] = () => store.getJwks({context});
    if (store.createJwk) callbacks['jwt.createJwk'] = data => store.createJwk(hydrate(data), {context});
  }
  if (typeof session.cookieCache?.version === 'function') {
    callbacks['cache.version'] = (payload) => (session.cookieCache!.version as Function)(hydrate(payload.session), hydrate(payload.user));
  }
  callbacks['transaction.beforeCommit'] = async () => {
    try { await context.adapter.transaction(async () => undefined); }
    catch (error) { const state = currentOperation.getStore(); if (state) state.transactionError = error; throw error; }
  };
  if (options.secondaryStorage) {
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
    callbacks["password.hash"] = ep.password.hash;
    callbacks["password.verify"] = ep.password.verify;
  }
  if (typeof ep.sendResetPassword === "function")
    callbacks["email.reset-password"] = (payload) =>
      ep.sendResetPassword!(hydrate(payload), undefined);
  if (typeof ev.sendVerificationEmail === "function")
    callbacks["email.verify-email"] = (payload) =>
      ev.sendVerificationEmail(hydrate(payload), undefined);
  const validateUserInfo = options.user?.validateUserInfo;
  if (typeof validateUserInfo === "function")
    callbacks["user.validate"] = (payload) =>
      validateUserInfo(hydrate(payload));
  if (typeof ep.onExistingUserSignUp === "function")
    callbacks["user.existing"] = (payload) =>
      ep.onExistingUserSignUp!(hydrate(payload), undefined);
  if (typeof ep.customSyntheticUser === 'function') {
    callbacks['user.synthetic'] = payload => {
      const {id: _id, ...coreFields} = hydrate(payload.coreFields);
      return ep.customSyntheticUser!({coreFields, additionalFields: hydrate(payload.additionalFields), id: payload.id});
    };
  }
  for (const [method, callback] of Object.entries(callbacks))
    bridge.setCallback(method, callback);
  await bridge.send("init", {
    options: {
      admin_schema: !!adminOptions,
      admin_default_role: adminOptions?.defaultRole ?? 'user',
      organization_schema: !!organizationOptions,
      organization_teams: organizationOptions?.teams?.enabled ?? false,
      endpoint_plugins: endpointPlugins,
      jwt_plugin: !!jwtOptions,
      custom_jwk_store: !!jwtOptions?.adapter,
      jwt_options: jwtOptions && {
        algorithm: jwtOptions.jwks?.keyPairConfig?.alg ?? '',
        remote_url: jwtOptions.jwks?.remoteUrl ?? '',
        curve: jwtOptions.jwks?.keyPairConfig?.crv ?? '',
        modulus_length: jwtOptions.jwks?.keyPairConfig?.modulusLength ?? 2048,
        session_cookie_cache: jwtOptions.sessionCookieCache ?? false,
        rotation_interval: jwtOptions.jwks?.rotationInterval ?? 0,
        grace_period: jwtOptions.jwks?.gracePeriod ?? 2592000,
        disable_private_key_encryption: jwtOptions.jwks?.disablePrivateKeyEncryption ?? false,
        jwks_path: jwtOptions.jwks?.jwksPath ?? '/jwks',
        disable_setting_jwt_header: jwtOptions.disableSettingJwtHeader ?? false,
        issuer: jwtOptions.jwt?.issuer ?? '',
        audience: typeof jwtOptions.jwt?.audience === 'string' ? jwtOptions.jwt.audience : '',
        audiences: Array.isArray(jwtOptions.jwt?.audience) ? jwtOptions.jwt.audience : [],
      },
      storage: stateless || isNativeMemoryAdapter(options.database) ? 'memory' : 'sqlite',
      stateless_sessions: stateless,
      secondary_storage: !!options.secondaryStorage,
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
      base_url: baseURL,
      base_path: basePath,
      secret:
        options.secret ??
        "better-auth-secret-that-is-long-enough-for-validation-test",
      trusted_origins: options.trustedOrigins ?? [],
      email_and_password: ep.enabled ?? true,
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
      trust_proxy_origin_headers: advanced.trustedProxyHeaders ?? false,
      real_passwords: config.realPasswords ?? false,
      fail_delivery: config.failDelivery ?? false,
      magic_link: config.magicLink ?? false,
      remote_passwords: !!ep.password,
      callback_methods: Object.keys(callbacks),
      account_fields_json: JSON.stringify(options.account?.fields ?? {}),
      user_fields_json: JSON.stringify(options.user?.additionalFields ?? {}),
      session_fields_json: JSON.stringify(session.additionalFields ?? {}),
    },
  });

  const emails: any[] = [];
  const cookieInfo = await bridge.send('internal', {method: 'cookieInfo'});
  context.authCookies = JSON.parse(cookieInfo.value_json);
  async function dispatch(request: Request, direct = false) {
    return currentOperation.run({}, async () => {
    const result = await bridge.request(request, direct);
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
    const levels = ["debug", "info", "warn", "error"];
    if (
      !options.logger?.disabled &&
      typeof options.logger?.log === "function"
    ) {
      for (const event of result.logs ?? []) {
        if (
          levels.indexOf(event.level) >=
          levels.indexOf(options.logger.level ?? "info")
        )
          options.logger.log(event.level, event.message);
      }
    }
    return result.response;
    });
  }

  const api: Record<string, (args?: FixtureOptions) => Promise<any>> = {};
  const instanceRoutes = {...routes};
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
      const response = await dispatch(
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
      assertKeys(args.body ?? {}, name === 'signJWT' ? ['payload'] : ['token', 'issuer'], name);
      const values = name === 'signJWT' ? [args.body?.payload] : [args.body?.token, args.body?.issuer ?? ''];
      const reply = await bridge.send('internal', {method: name, arguments_json: transportJSON(values)});
      const value = JSON.parse(reply.value_json);
      if (args.asResponse) return new Response(reply.value_json, {headers: {'content-type': 'application/json'}});
      return args.returnHeaders ? {response: hydrate(value), headers: new Headers()} : hydrate(value);
    };
  }
  const auth = {
    $context: Promise.resolve(context),
    api: api as typeof api & { signUpEmail: SignUpAPI<O>; getSession: SessionAPI<O>; getJwks(args?: FixtureOptions): Promise<JSONWebKeySet> },
    handler: (request: Request) => dispatch(request),
    options,
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
  const client = createAuthClient(clientOptions);
  const cookieSetter =
    (headers: Headers) =>
    ({ response }: { response: Response }) => {
      const cookies = parseSetCookieHeader(
        response.headers.get("set-cookie") ?? "",
      );
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

  async function signInWithTestUser() {
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
  const db = {
    async update(args: FixtureOptions) {
      assertKeys(args, ["model", "where", "update"], "db.update");
      if (args.model !== "session" || args.where?.length !== 1 || args.where[0].field !== "id" || (args.where[0].operator && args.where[0].operator !== "eq"))
        throw new Error("V fixture db.update currently requires a session id equality filter");
      const reply = await bridge.send("internal", {method: "adapterUpdateSession", arguments_json: transportJSON([args.where[0].value, args.update])});
      return hydrate(JSON.parse(reply.value_json));
    },
    async findMany<T = Record<string, unknown>>(
      args: FixtureOptions,
    ): Promise<T[]> {
      assertKeys(args, ["model"], "db.findMany");
      const reply = await bridge.send("inspect", { model: args.model });
      return hydrate(JSON.parse(reply.records_json)) as T[];
    },
  };
  return {
    auth,
    client,
    testUser,
    cookieSetter,
    sessionSetter: cookieSetter,
    signInWithTestUser,
    bridge,
    emails,
    db,
  };
}
