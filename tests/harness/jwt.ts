import { isDeepStrictEqual } from 'node:util';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { JwtOptions } from 'better-auth/plugins/jwt';
import type { JWK } from 'jose';
import type { GenericEndpointContext } from '@better-auth/core';
import { getTestInstance } from './test-instance.js';
import { jwt } from './plugins.js';

export const SESSION_COOKIE_JWT_TYPE = 'better-auth.session-cache+jwt';

export function createCookieCacheSigner(options?: JwtOptions) {
  return {
    async verify(endpoint: GenericEndpointContext, token: string) {
      const context = endpoint.context as unknown as {options: {plugins?: {id: string; options?: unknown}[]}; nativeVerifyCookieJWT(token: string): Promise<unknown>};
      const configured = context.options.plugins?.find(plugin => plugin.id === 'jwt')?.options;
      if (options !== configured) throw new Error('The native cookie signer fixture requires the configured plugin options');
      return context.nativeVerifyCookieJWT(token);
    },
  };
}

export async function generateExportedKeyPair(options?: JwtOptions) {
  const {bridge} = await getTestInstance({plugins: [jwt(options)]}, {disableTestUser: true});
  const reply = await bridge.send('internal', {method: 'generateJWK'});
  return JSON.parse(reply.value_json) as {publicWebKey: JWK; privateWebKey: JWK; alg: string};
}

// The original utility tests are synchronous. This one-shot transport executes
// the native parser without booting an auth instance or duplicating time logic.
export function toExpJWT(value: number | Date | string, iat: number): number {
  const reply = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--jwt-expiration'], {
    input: JSON.stringify({kind: value instanceof Date ? 'date' : typeof value, value: value instanceof Date ? value.getTime() : value, iat}) + '\n',
    encoding: 'utf8',
  });
  if (reply.error) throw reply.error;
  if (reply.status !== 0) throw new TypeError(reply.stderr.trim());
  return JSON.parse(reply.stdout);
}

interface NativeJWTContext {
  options: {plugins?: {id: string; options?: unknown}[]};
  nativeSignJWT(payload: unknown, signing: unknown): Promise<string>;
  nativeJwkLookup(method: string, value: string, algorithm: string): Promise<any>;
}

export async function signJWT(endpoint: GenericEndpointContext, config: {
  options?: JwtOptions; payload: Record<string, unknown>; header?: Record<string, unknown>;
  signingKeyId?: string; signingAlgorithm?: string;
}) {
  const context = endpoint.context as unknown as NativeJWTContext;
  const configured = context.options.plugins?.find(plugin => plugin.id === 'jwt')?.options;
  // Helpers operate on the configured native plugin. Per-call option replacement
  // remains separate work; fail rather than silently ignore a different config.
  if (config.options !== configured && !isDeepStrictEqual(config.options ?? {}, configured ?? {})) throw new Error('Unimplemented native JWT option replacement');
  return context.nativeSignJWT(config.payload, {header: config.header, signingKeyId: config.signingKeyId, signingAlgorithm: config.signingAlgorithm});
}

export function getJwksAdapter(_adapter: unknown, options?: JwtOptions) {
  return Object.fromEntries(['getAllKeys', 'getKeyById', 'getLatestKey', 'getLatestKeyByAlg'].map(method => [method,
    (endpoint: GenericEndpointContext, value = '') => (endpoint.context as unknown as NativeJWTContext).nativeJwkLookup(method, value, options?.jwks?.keyPairConfig?.alg ?? 'EdDSA'),
  ])) as Record<'getAllKeys' | 'getKeyById' | 'getLatestKey' | 'getLatestKeyByAlg', (endpoint: GenericEndpointContext, value?: string) => Promise<any>>;
}
