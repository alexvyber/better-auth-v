import {describe, expect, it, vi} from 'vitest';
import {getTestInstance, postgresOptions, postgresSQL} from './harness/postgres-fixture.js';

describe('native PostgreSQL physical schema', () => {
 it('persists UUID user/account/session columns and uses the real session token', async () => {
  const configuration = await postgresOptions();
  const {auth, signInWithTestUser} = await getTestInstance({}, {nativePostgres: configuration});
  const {headers} = await signInWithTestUser();
  const current = await auth.api.getSession({headers});
  expect(current?.user.email).toBe('test@test.com');
  expect(await postgresSQL(configuration, `SELECT email_verified FROM "${configuration.schema}".auth_user LIMIT 1`)).toBe('f');
  const token = await postgresSQL(configuration, `SELECT token FROM "${configuration.schema}".auth_session ORDER BY created_at DESC LIMIT 1`);
  expect(token).toBe(current!.session.token);
  expect((await auth.api.listSessions({headers})).map((session: any) => session.token)).toContain(token);
 });
});

describe('PostgreSQL multi-connection contracts', () => {
 it('allows only one consumer and one reservation owner across separate native processes', async () => {
  const configuration = await postgresOptions();
  const options = {verification: {storeIdentifier: 'hashed' as const}};
  const first = await getTestInstance(options, {nativePostgres: configuration, disableTestUser: true});
  const second = await getTestInstance(options, {nativePostgres: configuration, disableTestUser: true});
  const adapters = await Promise.all([first, second].map(async instance => (await instance.auth.$context).internalAdapter));
  const proof = {identifier: 'physical:consume', value: 'secret', expiresAt: new Date(Date.now() + 60000)};
  await adapters[0].createVerificationValue(proof);
  const results = await Promise.all(adapters.map(adapter => adapter.consumeVerificationValue(proof.identifier)));
  expect(results.filter(Boolean)).toHaveLength(1);
  expect(results.find(Boolean).value).toBe('secret');
  const owners = await Promise.all(adapters.map(adapter => adapter.reserveVerificationValue({...proof, identifier: 'physical:reserve'})));
  expect(owners.filter(Boolean)).toHaveLength(1);
  expect(await adapters[0].reserveVerificationValue({...proof, identifier: 'physical:reserve'})).toBe(false);
 });

 it('preserves application-owned columns and defaults in an existing schema', async () => {
  const configuration = await postgresOptions();
  configuration.tables.user = 'auth "user';
  configuration.fields.user.name = 'display "name';
  const instance = await getTestInstance({}, {nativePostgres: configuration});
  const table = `"${configuration.schema}"."auth ""user"`;
  await postgresSQL(configuration, `ALTER TABLE ${table} ADD COLUMN domain_state text NOT NULL DEFAULT 'retained'`);
  const {headers} = await instance.signInWithTestUser();
  expect((await instance.auth.api.getSession({headers}))?.user.name).toBe('test user');
  await instance.auth.api.updateUser({headers, body: {name: 'Renamed'}});
  expect(await postgresSQL(configuration, `SELECT "display ""name" FROM ${table} LIMIT 1`)).toBe('Renamed');
  expect(await postgresSQL(configuration, `SELECT domain_state FROM ${table} LIMIT 1`)).toBe('retained');
  expect((await instance.auth.api.getSession({headers}))?.user.name).toBe('Renamed');
 });
});


describe('PostgreSQL application update isolation', () => {
 it('preserves a concurrent role demotion and reports the stored row to hooks and sessions', async () => {
  const configuration = await postgresOptions();
  const after = vi.fn();
  let demote = false;
  const {auth, signInWithTestUser} = await getTestInstance({
   user: {additionalFields: {role: {type: 'string', input: false, defaultValue: 'admin'}}},
   databaseHooks: {user: {update: {
    before: async data => {
     if (demote) await postgresSQL(configuration, `UPDATE "${configuration.schema}".auth_user SET role='member'`);
     return {data};
    },
    after,
   }}},
  }, {nativePostgres: configuration});
  const {headers} = await signInWithTestUser();
  demote = true;
  await auth.api.updateUser({headers, body: {name: 'Renamed'}});
  expect(await postgresSQL(configuration, `SELECT role FROM "${configuration.schema}".auth_user LIMIT 1`)).toBe('member');
  expect((await auth.api.getSession({headers}))?.user).toMatchObject({name: 'Renamed', role: 'member'});
  expect(after.mock.calls.at(-1)?.[0]).toMatchObject({name: 'Renamed', role: 'member'});
 });
});

describe('PostgreSQL database limiter', () => {
 it('enforces one shared limit across separate native connections', async () => {
  const configuration = await postgresOptions();
  const options = {rateLimit: {enabled: true, storage: 'database' as const, window: 60, max: 1}};
  const instances = await Promise.all([0, 1].map(() => getTestInstance(options, {nativePostgres: configuration, disableTestUser: true})));
  const responses = await Promise.all(instances.map(instance => instance.auth.handler(new Request('http://localhost:3000/api/auth/get-session'))));
  expect(responses.map(response => response.status).sort()).toEqual([200, 429]);
  expect(await postgresSQL(configuration, `SELECT count FROM "${configuration.schema}".auth_rate_limit LIMIT 1`)).toBe('1');
 });
});
