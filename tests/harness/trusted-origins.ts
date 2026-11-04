import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import type {BetterAuthOptions} from 'better-auth';

export async function getTrustedOrigins(options: BetterAuthOptions, request?: Request): Promise<string[]> {
  const trustedOrigins = typeof options.trustedOrigins === 'function' ? await options.trustedOrigins(request) : options.trustedOrigins;
  const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--trusted-origins'], {
    input: JSON.stringify({options: {baseURL: options.baseURL, trustedOrigins}, request_url: request?.url ?? ''}) + '\n', encoding: 'utf8',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim());
  return JSON.parse(result.stdout);
}
