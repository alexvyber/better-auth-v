import type { memoryAdapter as upstreamMemoryAdapter } from "better-auth/adapters/memory";

// A fixture descriptor selects the native V map adapter. It never creates a TS
// database or executes the upstream authentication implementation.
const factories = new WeakSet<Function>();
export function memoryAdapter(...[database, config]: Parameters<typeof upstreamMemoryAdapter>): ReturnType<typeof upstreamMemoryAdapter> {
  if (config && Object.keys(config).length) throw new Error("Memory-adapter fixture configuration is not yet bridged");
  if (Object.values(database).some((rows) => rows.length !== 0))
    throw new Error("Memory-adapter fixture seeding is not yet bridged");
  const factory = (() => { throw new Error("The fixture descriptor must be executed in V"); }) as ReturnType<typeof upstreamMemoryAdapter>;
  factories.add(factory);
  return factory;
}
export function isNativeMemoryAdapter(value: unknown): boolean {
  return typeof value === "function" && factories.has(value);
}
