import type {FixtureOptions} from "./fixture-types.js";

export function assertKeys(value: FixtureOptions, allowed: string[], label: string) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key))
      throw new Error(`Unsupported V fixture option: ${label}.${key}`);
  }
}
