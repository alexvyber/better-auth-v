import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {betterFetch} from '@better-fetch/fetch';
import type * as Core from '@better-auth/core/oauth2';
import {Bridge} from './bridge.js';
import {oauthNative} from './oauth-helpers.js';

function assertionNative<T>(input: Record<string, unknown>): T {
  const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--oauth-assertion'], {input: JSON.stringify(input) + '\n', encoding: 'utf8'});
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim());
  return JSON.parse(result.stdout);
}
const metadata = assertionNative<{type: string; algorithms: Core.PrivateKeyJwtSigningAlgorithm[]}>({op: 'metadata'});
export const CLIENT_ASSERTION_TYPE = metadata.type;
export const PRIVATE_KEY_JWT_SIGNING_ALGORITHMS = metadata.algorithms;
export async function signPrivateKeyJwtClientAssertion(input: Parameters<typeof Core.signPrivateKeyJwtClientAssertion>[0]): Promise<string> {
  return assertionNative({op: 'sign', options: input, context: {clientId: input.clientId, tokenEndpoint: input.tokenEndpoint}, now: Math.floor(Date.now() / 1000)});
}
export function createPrivateKeyJwtClientAssertionGetter(options: Core.PrivateKeyJwtClientAssertionGetterOptions): Core.ClientAssertionGetter {
  assertionNative({op: 'validate', options});
  return context => signPrivateKeyJwtClientAssertion({...options, clientId: context.clientId, tokenEndpoint: context.tokenEndpoint});
}
export async function resolveClientAssertionParams(input: Parameters<typeof Core.resolveClientAssertionParams>[0]) {
  return {client_assertion: await input.getClientAssertion(input.context), client_assertion_type: CLIENT_ASSERTION_TYPE};
}

type Input = Record<string, any> & {options: any};
async function nativeToken(input: Input, grant: string, exchange: boolean): Promise<any> {
  const options = typeof input.options === 'function' ? await input.options() : input.options;
  const bridge = new Bridge(['--oauth-token']);
  let callbackError: unknown;
  const remember = (callback: (payload: any) => any) => async (payload: any) => {
    try { return await callback(payload); } catch (error) { callbackError = error; throw error; }
  };
  bridge.setCallback('token.clock', () => Date.now());
  bridge.setCallback('token.assertion', remember(context => input.tokenEndpointAuth.getClientAssertion(context)));
  bridge.setCallback('token.customize', remember(async ({request, tokenEndpoint, grantType}) => {
    const body = new URLSearchParams(request.body);
    const headers = request.headers;
    await input.tokenEndpointAuth.customizeRequest({body, headers, options, tokenEndpoint, grantType});
    return {body: body.toString(), headers};
  }));
  bridge.setCallback('token.fetch', remember(async request => {
    let status: number | undefined;
    let statusText = '';
    const result = await betterFetch(request.url, {method: request.method, body: new URLSearchParams(request.body), headers: request.headers, redirect: 'manual',
      onResponse(context) { status = context.response.status; statusText = context.response.type === 'opaqueredirect' ? 'opaqueredirect' : context.response.statusText; },
    });
    return {status: status ?? result.error?.status ?? 200, status_text: statusText, body: JSON.stringify(result.error ?? result.data)};
  }));
  try {
    const reply = await bridge.send(exchange ? 'exchange' : 'request', {input: {...input, options}, grant_type: grant});
    const value = JSON.parse(reply.value_json);
    if (!exchange) return {body: new URLSearchParams(value.body), headers: value.headers};
    for (const name of ['accessTokenExpiresAt', 'refreshTokenExpiresAt']) {
      if (name in value) value[name] = new Date(value[name] === null ? NaN : value[name]);
    }
    return value;
  } catch (error) { if (callbackError !== undefined) throw callbackError; throw error; }
  finally { await bridge.close(); }
}
export async function authorizationCodeRequest(input: Parameters<typeof Core.authorizationCodeRequest>[0]) { return nativeToken(input, 'authorization_code', false); }
export async function refreshAccessTokenRequest(input: Parameters<typeof Core.refreshAccessTokenRequest>[0]) { return nativeToken(input, 'refresh_token', false); }
export async function clientCredentialsTokenRequest(input: Parameters<typeof Core.clientCredentialsTokenRequest>[0]) { return nativeToken(input, 'client_credentials', false); }
export async function validateAuthorizationCode(input: Parameters<typeof Core.validateAuthorizationCode>[0]): Promise<Core.OAuth2Tokens> { return nativeToken(input, 'authorization_code', true); }
export async function refreshAccessToken(input: Parameters<typeof Core.refreshAccessToken>[0]): Promise<Core.OAuth2Tokens> { return nativeToken(input, 'refresh_token', true); }
export async function clientCredentialsToken(input: Parameters<typeof Core.clientCredentialsToken>[0]): Promise<Core.OAuth2Tokens> { return nativeToken(input, 'client_credentials', true); }
export function parseScopeField(scope: unknown): string[] { return oauthNative({op: 'parse-scope', value: scope}); }
export function mergeScopes(stored: string | null | undefined, incoming: string[] | undefined): string { return oauthNative({op: 'merge-scopes', stored, incoming}); }
