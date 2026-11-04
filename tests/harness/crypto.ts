import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { SecretConfig } from '@better-auth/core';

type Secret = string | SecretConfig;
export type EncryptionPurpose = 'oauth-state-cookie' | 'oauth-proxy-state' | 'oauth-proxy-package' | 'oauth-proxy-profile';

function native(op: string, args: unknown[]): any {
  const reply = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--crypto'], {
    input: JSON.stringify({op, args}, (_key, value) => value instanceof Map ? Object.fromEntries(value) : value) + '\n',
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  if (reply.error) throw reply.error;
  if (reply.status !== 0) throw new Error(reply.stderr.trim());
  return JSON.parse(reply.stdout);
}
function hydrateSecret(value: any): Secret {
  return typeof value === 'string' ? value : {...value, keys: new Map(Object.entries(value.keys).map(([version, key]) => [Number(version), key as string]))};
}

export function parseEnvelope(data: string): {version: number; ciphertext: string} | null { return native('parseEnvelope', [data]); }
export function formatEnvelope(version: number, ciphertext: string): string { return native('formatEnvelope', [version, ciphertext]); }
export async function symmetricEncrypt({key, data}: {key: Secret; data: string}): Promise<string> { return native('symmetricEncrypt', [key, data]); }
export async function symmetricDecrypt({key, data}: {key: Secret; data: string}): Promise<string> { return native('symmetricDecrypt', [key, data]); }
export function derivePurposeKey(secret: Secret, purpose: EncryptionPurpose): Secret { return hydrateSecret(native('derivePurposeKey', [secret, purpose])); }
export async function symmetricEncodeJWT(payload: Record<string, unknown>, key: Secret, salt: string, expiresIn = 3600): Promise<string> {
  return native('symmetricEncodeJWT', [payload, key, salt, expiresIn, Math.floor(Date.now() / 1000)]);
}
export async function symmetricDecodeJWT<T = any>(token: string, key: Secret, salt: string): Promise<T | null> {
  return native('symmetricDecodeJWT', [token, key, salt, Math.floor(Date.now() / 1000)]);
}
export function parseSecretsEnv(value?: string): {version: number; value: string}[] | null { return native('parseSecretsEnv', [value]); }
export function validateSecretsArray(entries: {version: number; value: string}[], logger: {warn(message: string): unknown}): void {
  const warnings = native('validateSecretsArray', [entries]) as string[];
  for (const message of warnings) logger.warn(message);
}
export function buildSecretConfig(entries: {version: number; value: string}[], legacySecret: string): SecretConfig {
  return hydrateSecret(native('buildSecretConfig', [entries, legacySecret])) as SecretConfig;
}
