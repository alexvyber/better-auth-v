import {execFile} from 'node:child_process';
import {existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {afterAll} from 'vitest';
import {getTestInstance as nativeInstance} from './test-instance.js';
const run = promisify(execFile);
const bundledBin = fileURLToPath(new URL('../../build/deps/pgsql/bin/', import.meta.url));
const pgBin = process.env.BETTER_AUTH_PG_BIN ?? (existsSync(join(bundledBin, 'postgres')) ? bundledBin : '');
const pgTool = (name: string) => pgBin ? join(pgBin, name) : name;
export interface NativePostgresOptions {
 connectionString: string; schema: string; uuidIds: boolean;
 tables: Record<string, string>; fields: Record<string, Record<string, string>>;
 columnTypes?: Record<string, Record<string, string>>;
}
let cluster: Promise<{root: string; connection: string}> | undefined;
async function start() {
 const root = await mkdtemp(join(tmpdir(), 'better-auth-v-pg-'));
 const listener = createServer(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
 const port = (listener.address() as {port: number}).port;
 await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
 try {
  await run(pgTool('initdb'), ['-D', root, '-A', 'trust', '-U', 'better_auth_test', '--no-locale', '-E', 'UTF8']);
  await run(pgTool('pg_ctl'), ['-D', root, '-l', join(root, 'server.log'), '-o', `-h 127.0.0.1 -p ${port} -k ${root}`, '-w', 'start']);
  return {root, connection: `host=127.0.0.1 port=${port} dbname=postgres user=better_auth_test sslmode=disable connect_timeout=2`};
 } catch (error) {await run(pgTool('pg_ctl'), ['-D', root, '-m', 'immediate', '-w', 'stop']).catch(() => undefined); await rm(root, {recursive: true, force: true}); throw error;}
}
afterAll(async () => {
 if (!cluster) return;
 const running = await cluster.catch(() => undefined);
 if (!running) return;
 try {await run(pgTool('pg_ctl'), ['-D', running.root, '-m', 'immediate', '-w', 'stop']);}
 finally {await rm(running.root, {recursive: true, force: true});}
});
const snake = (value: string) => value.replace(/[A-Z]/g, letter => '_' + letter.toLowerCase());
const columns: Record<string, string[]> = {
 user: ['id','name','email','emailVerified','image','createdAt','updatedAt','twoFactorEnabled'],
 twoFactor: ['id','userId','secret','backupCodes','verified','failedVerificationCount','lockedUntil'],
 session: ['id','userId','token','expiresAt','createdAt','updatedAt','ipAddress','userAgent'],
 account: ['id','userId','accountId','providerId','password','accessToken','refreshToken','idToken','accessTokenExpiresAt','refreshTokenExpiresAt','scope','createdAt','updatedAt'],
 verification: ['id','identifier','value','expiresAt','createdAt','updatedAt'],
 jwks: ['id','publicKey','privateKey','alg','crv','createdAt','expiresAt'],
 rateLimit: ['key','count','lastRequest'],
};
export async function postgresOptions(): Promise<NativePostgresOptions> {
 const running = await (cluster ??= start());
 return {connectionString: running.connection, schema: 'ba_' + randomUUID().replaceAll('-', ''), uuidIds: true,
  tables: {user:'auth_user', session:'auth_session', account:'auth_account', verification:'auth_verification', jwks:'jwks', twoFactor:'auth_two_factor', rateLimit:'auth_rate_limit'},
  fields: Object.fromEntries(Object.entries(columns).map(([model, fields]) => [model, Object.fromEntries(fields.map(field => [field, snake(field)]))])),
 };
}
export const getTestInstance: typeof nativeInstance = async (options = {} as any, config = {} as any) => {
 if (Object.hasOwn(options, 'database')) throw new Error('PostgreSQL matrix cannot override an explicit upstream database');
 const postgres = (config as any).nativePostgres ?? await postgresOptions();
 const account = (options as any).account;
 return nativeInstance(options, {...config, nativePostgres: {...postgres, fields: {...postgres.fields, account: {...postgres.fields.account, ...account?.fields}}}}) as any;
};
export async function postgresSQL(configuration: NativePostgresOptions, sql: string): Promise<string> {
 const result = await run('psql', [configuration.connectionString, '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', sql]);
 return result.stdout.trim();
}
