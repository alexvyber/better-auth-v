import type {BetterAuthOptions as CoreOptions} from '@better-auth/core';
import {DatabaseSync} from './native-auth.js';
import {getTestInstance} from './test-instance.js';
export {DatabaseSync};
export type BetterAuthOptions = Omit<CoreOptions, 'database'> & {database?: DatabaseSync};
const instances = new WeakMap<object, ReturnType<typeof getTestInstance>>();
export async function getMigrations(options: BetterAuthOptions) {
  if (!(options.database instanceof DatabaseSync)) throw new Error('Expected native SQLite descriptor');
  const {database: _database, ...configuration} = options;
  const ready = getTestInstance(configuration, {disableTestUser: true, deferMigrations: true});
  instances.set(options, ready);
  return {async runMigrations() { await (await ready).bridge.send('migrate'); }};
}
export async function init(options: BetterAuthOptions) {
  const ready = instances.get(options);
  if (!ready) throw new Error('Native migrations must initialize the fixture first');
  return (await ready).auth.$context;
}
