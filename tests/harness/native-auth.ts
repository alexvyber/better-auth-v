import { getTestInstance } from './test-instance.js';

// Configuration descriptors for the upstream raw-constructor regression. No JS
// database is opened: explicit migration and the actual transaction run in V.
export class DatabaseSync {
  constructor(readonly path: string) {
    if (path !== ':memory:') throw new Error('Only native in-memory SQLite descriptors are supported');
  }
}
export class NodeSqliteDialect {
  constructor(readonly options: {database: DatabaseSync}) {}
}

type Options = Omit<NonNullable<Parameters<typeof getTestInstance>[0]>, 'database'> & {
  database: {dialect: NodeSqliteDialect; type: string; transaction: boolean};
};
type Instance = Awaited<ReturnType<typeof getTestInstance>>;
const instances = new WeakMap<object, Promise<Instance>>();

export function betterAuth(options: Options) {
  const {database, ...configuration} = options;
  if (database.type !== 'sqlite' || database.transaction !== true || !(database.dialect instanceof NodeSqliteDialect)) {
    throw new Error('Unported raw auth database configuration');
  }
  const ready = getTestInstance(configuration, {disableTestUser: true, realPasswords: true, deferMigrations: true});
  instances.set(options, ready);
  return {
    options,
    $context: ready.then(instance => instance.auth.$context),
    api: new Proxy({} as Instance['auth']['api'], {
      get: (_target, name: string) => async (args: Record<string, unknown> = {}) => {
        const instance = await ready;
        const endpoint = instance.auth.api[name];
        if (typeof endpoint !== 'function') throw new Error('Unported native API: ' + name);
        return endpoint(args);
      },
    }),
  };
}

export async function getMigrations(options: Options) {
  const ready = instances.get(options);
  if (!ready) throw new Error('Migrations require a native auth descriptor');
  return {async runMigrations() { await (await ready).bridge.send('migrate'); }};
}

export async function runWithTransaction<T>(adapter: unknown, callback: () => Promise<T>): Promise<T> {
  const native = adapter as {nativeRunWithTransaction?: (operation: () => Promise<T>) => Promise<T>};
  if (!native.nativeRunWithTransaction) throw new Error('A native transaction adapter is required');
  return native.nativeRunWithTransaction(callback);
}
