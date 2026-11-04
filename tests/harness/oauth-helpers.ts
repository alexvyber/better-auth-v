import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import type {createAuthorizationURL as ReferenceCreateAuthorizationURL} from '@better-auth/core/oauth2';

export function oauthNative<T>(input: Record<string, unknown>): T {
  const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--oauth-helpers'], {input: JSON.stringify(input) + '\n', encoding: 'utf8'});
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim());
  return JSON.parse(result.stdout);
}
export const RESERVED_AUTHORIZATION_PARAMS = oauthNative<string[]>({op: 'reserved'});
export function encodeBasicCredentials(clientId: string, clientSecret: string): string {
  return oauthNative({op: 'basic-encode', clientId, clientSecret});
}
export function decodeBasicCredentials(authorization: string): {clientId: string; clientSecret: string} {
  return oauthNative({op: 'basic-decode', authorization});
}
export async function createAuthorizationURL(input: Parameters<typeof ReferenceCreateAuthorizationURL>[0]): Promise<URL> {
  const options = typeof input.options === 'function' ? await input.options() : input.options;
  return new URL(oauthNative<string>({op: 'authorization-url', input: {...input, options}}));
}
