import type {DBFieldAttribute} from "@better-auth/core/db";
import type {BetterAuthOptions} from "@better-auth/core";
import type {Account,Auth} from "better-auth";

// Upstream fixtures are intentionally dynamically shaped. This boundary accepts
// their objects; unsupported server configuration fails rather than being ignored.
export type FixtureOptions = Record<string, any>;
export interface FixtureUserOptions extends FixtureOptions {
  fields?: NonNullable<BetterAuthOptions['user']>['fields'];
  modelName?: string;
  deleteUser?: NonNullable<BetterAuthOptions['user']>['deleteUser'];
  changeEmail?: NonNullable<BetterAuthOptions['user']>['changeEmail'];
  additionalFields?: Record<string,DBFieldAttribute>;
  validateUserInfo?: NonNullable<BetterAuthOptions['user']>['validateUserInfo'];
}
export interface FixtureLoggerOptions extends FixtureOptions {
  log?: NonNullable<BetterAuthOptions['logger']>['log'];
}
export interface ServerOptions {
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
export type FixtureResponseAPI = <const A extends FixtureOptions = FixtureOptions>(args?: A) => Promise<A extends {asResponse: true} ? Response : any>;
export type FixtureEnableTwoFactorAPI = <const A extends FixtureOptions = FixtureOptions>(args?: A) => Promise<A extends {asResponse: true} ? Response : {method: 'totp' | 'otp'; backupCodes: string[]; totpURI: string}>;
export type OrganizationAPI<O,K extends string> = O extends BetterAuthOptions ? K extends keyof Auth<O>['api'] ? Auth<O>['api'][K] : (args?:FixtureOptions)=>Promise<any> : (args?:FixtureOptions)=>Promise<any>;
export type SignUpAPI<O> = O extends BetterAuthOptions ? (Auth<O>["api"] extends {signUpEmail: infer F} ? F : Auth<{}>["api"]["signUpEmail"]) : Auth<{}>["api"]["signUpEmail"];
export type SessionAPI<O> = O extends BetterAuthOptions ? (Auth<O>["api"] extends {getSession: infer F} ? F : Auth<{}>["api"]["getSession"]) : Auth<{}>["api"]["getSession"];
export interface FixtureSession extends FixtureOptions {
  id: string;
  userId: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}
export interface FixtureInternalAdapter extends Record<string, (...args: any[]) => Promise<any>> {
  findAccounts(userId: string): Promise<Account[]>;
  listSessions(userId: string): Promise<FixtureSession[]>;
  createSession(userId: string, dontRememberMe?: boolean): Promise<FixtureSession>;
  findSession(token: string): Promise<{session: FixtureSession; user: FixtureOptions} | null>;
}
export interface FixtureTransactionAdapter {
  findOne<T = any>(query: FixtureOptions): Promise<T | null>;
 update<T = any>(query: FixtureOptions): Promise<T | null>;
  create<I=Record<string,unknown>, O=I & {id:string}>(query: {model: string; data: I;forceAllowId?:boolean}): Promise<O>;
  findMany<T>(query: FixtureOptions): Promise<T[]>;
  updateMany(query: FixtureOptions): Promise<number>;
  delete(query: FixtureOptions): Promise<void>;
  deleteMany(query: FixtureOptions): Promise<number>;
  count(query: FixtureOptions): Promise<number>;
  incrementOne<T=any>(query: FixtureOptions): Promise<T|null>;
  nativeRunWithTransaction<T>(callback: () => Promise<T>): Promise<T>;
  options: {adapterConfig: {transaction: boolean;adapterName?:string}};
  transaction(callback: (transaction: FixtureTransactionAdapter) => Promise<unknown>): Promise<unknown>;
}
