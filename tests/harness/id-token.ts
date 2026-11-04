import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {KeyObject} from 'node:crypto';
import {exportJWK, importJWK, type JWK, type JWSHeaderParameters} from 'jose';
import type {GenericEndpointContext} from '@better-auth/core';
import type {OAuthIdTokenConfig} from '@better-auth/core/oauth2';
import {Bridge} from './bridge.js';

type Provider = {id: string; idToken?: OAuthIdTokenConfig; options?: Record<string, any>};
function native<T>(input: Record<string, unknown>): T {
  const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--provider-id-token'], {input: JSON.stringify(input) + '\n', encoding: 'utf8'});
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim());
  return JSON.parse(result.stdout);
}
function flags(provider: Provider) {
  const config = provider.idToken;
  return {
    disabled: Boolean(provider.options?.disableIdTokenSignIn), configured: Boolean(config),
    override: Boolean(provider.options?.verifyIdToken), custom: Boolean(config && 'verify' in config),
  };
}
export function supportsIdTokenSignIn(provider: Provider): boolean {
  return native({op: 'supports', ...flags(provider)});
}

// The peer invokes application callbacks and serializes platform keys; V handles
// precedence, signature/claim validation, nonce checking and fail-closed results.
export async function verifyProviderIdToken(provider: Provider, token: string, nonce?: string, ctx?: GenericEndpointContext): Promise<boolean> {
  const bridge = new Bridge(['--provider-id-token']);
  const config: any = provider.idToken ?? {};
  bridge.setCallback('id.override', ({token}) => provider.options!.verifyIdToken(token, nonce, ctx));
  bridge.setCallback('id.custom', ({token}) => config.verify(token, nonce, ctx));
  bridge.setCallback('id.claims', (payload) => config.verifyClaims(payload));
  bridge.setCallback('id.key', async ({header, token}: {header: JWSHeaderParameters; token: string}) => {
    const [protectedHeader, payload, signature] = token.split('.');
    const key = await config.jwks(header, {protected: protectedHeader, payload, signature});
    if (key instanceof Uint8Array) return {kind: 'bytes', jwk: {kty: 'oct', k: Buffer.from(key).toString('base64url')}};
    if (key instanceof CryptoKey) {
      let jwk: JWK;
      try { jwk = await exportJWK(key); }
      catch { jwk = KeyObject.from(key).export({format: 'jwk'}); }
      return {kind: 'crypto', jwk, algorithm: key.algorithm, type: key.type, usages: key.usages};
    }
    if (key instanceof KeyObject) return {kind: 'object', type: key.type,
      jwk: key.type === 'secret' ? {kty: 'oct', k: key.export().toString('base64url')} : key.export({format: 'jwk'})};
    return {kind: 'jwk', jwk: key};
  });
  try {
    const reply = await bridge.send('verify', {...flags(provider), token, nonce, config,
      allowOpaqueToken: config.allowOpaqueToken === true, claims: Boolean(config.verifyClaims)});
    return JSON.parse(reply.value_json);
  } finally { await bridge.close(); }
}

// These expose native ID-token verification profiles, not full OAuth providers.
// The source verifier regression tests use only this portion of each provider.
function profile(id: string, options: Record<string, any>): Provider {
  const metadata = native<{configured: boolean; config: Omit<Extract<OAuthIdTokenConfig, {jwks: unknown}>, 'jwks' | 'verifyClaims'>; url: string}>({op: 'profile', provider: id, options});
  if (!metadata.configured) return {id, options};
  const config = {
    ...metadata.config,
    jwks: async (header: JWSHeaderParameters) => {
      const response = await fetch(metadata.url, {redirect: 'manual'});
      if (!response.ok) throw new Error('ID token key request failed');
      const jwk = native<JWK>({op: 'profile-key', provider: id, options, header, jwks: await response.json()});
      return importJWK(jwk, 'RS256');
    },
    verifyClaims: (payload: Record<string, unknown>) => native<boolean>({op: 'profile-claims', provider: id, options, payload}),
  } as OAuthIdTokenConfig;
  return {id, options, idToken: config};
}
export const apple = (options: Record<string, any>) => profile('apple', options);
export const cognito = (options: Record<string, any>) => profile('cognito', options);
export const facebook = (options: Record<string, any>) => profile('facebook', options);
export const google = (options: Record<string, any>) => profile('google', options);
export const microsoft = (options: Record<string, any>) => profile('microsoft', options);
export const paypal = (options: Record<string, any>) => profile('paypal', options);
