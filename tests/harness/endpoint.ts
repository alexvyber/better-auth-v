import type { originCheck as upstreamOriginCheck } from 'better-auth/api';
import type { createAuthEndpoint as upstreamCreateAuthEndpoint } from '@better-auth/core/api';

type Descriptor = { path: string; options: {metadata?: {openapi?:Record<string,unknown>;scope?:string}; method?: string; use?: unknown[]; body?: {parse(input: unknown): unknown}; query?: {parse(input: unknown): unknown}}; handler: (context: any) => unknown };
const descriptors = new WeakMap<Function, Descriptor>();
// Middleware descriptors are interpreted by V and never executed in JS.
export const freshSessionMiddleware: any = Object.freeze({nativeMiddleware: 'fresh-session'});
export const createAuthEndpoint = ((path: string, options: Descriptor['options'], handler: Descriptor['handler']) => {
  const endpoint = Object.assign(async () => { throw new Error('Native endpoint descriptors cannot execute in JS'); }, {path, options});
  descriptors.set(endpoint, {path, options, handler});
  return endpoint;
}) as unknown as typeof upstreamCreateAuthEndpoint;

export function nativeEndpoint(value: unknown): Descriptor | undefined {
  return typeof value === 'function' ? descriptors.get(value) : undefined;
}

const originSelectors = new WeakMap<object, (context: any) => unknown>();
export const originCheck = ((select: (context: any) => unknown) => {
  const descriptor = Object.freeze({nativeMiddleware: 'origin-check'});
  originSelectors.set(descriptor, select);
  return descriptor;
}) as unknown as typeof upstreamOriginCheck;
export function nativeOriginSelector(value: unknown) {
  return value && (typeof value === 'object' || typeof value === 'function') ? originSelectors.get(value) : undefined;
}
