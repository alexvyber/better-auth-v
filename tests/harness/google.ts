import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {betterFetch} from '@better-fetch/fetch';
import type {GoogleOptions} from '@better-auth/core/social-providers';

function native<T>(input: Record<string, unknown>): T {
  const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--google'], {input: JSON.stringify(input) + '\n', encoding: 'utf8'});
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim());
  return JSON.parse(result.stdout);
}

// Thin transport/platform counterpart: V supplies policy and decides whether a
// key request is needed. The supplied HTTP client remains mockable upstream.
export async function verifyGoogleIdToken({token, audience, nonce}: {token: string; audience: string | string[]; nonce?: string}): Promise<Record<string, unknown> | null> {
  const request = native<{url: string; method: string} | null>({op: 'keys-request', token});
  if (request === null) return null;
  let keys: unknown = {};
  try { keys = (await betterFetch(request.url, {method: request.method, redirect: 'manual'})).data ?? {}; } catch {}
  return native({op: 'verify', token, audiences: typeof audience === 'string' ? [audience] : audience, nonce, jwks: keys, now: Math.floor(Date.now() / 1000)});
}

export function google(options: GoogleOptions) {
  const metadata = native<{hasHostedDomainVerifier: boolean}>({op: 'metadata', options});
  return {
    id: 'google', options,
    idToken: {verifyClaims: metadata.hasHostedDomainVerifier ? (claims: Record<string, unknown>) => native<boolean>({op: 'hosted-domain', options, claim: claims.hd}) : undefined},
    async getUserInfo(tokens: {idToken?: string; accessToken?: string}) { return native<any>({op: 'profile', options, token: tokens.idToken ?? ''}); },
  };
}
