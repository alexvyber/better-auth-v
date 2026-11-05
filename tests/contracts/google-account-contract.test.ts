import {createHash} from 'node:crypto';
import {afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi} from 'vitest';
import {SignJWT} from 'jose';
import {http, HttpResponse} from 'msw';
import {setupServer} from 'msw/node';
import {symmetricDecodeJWT, symmetricDecrypt} from 'better-auth/crypto';
import {getTestInstance} from '../harness/test-instance.js';
import {getChunkedCookie, parseCookies, parseSetCookieHeader} from '../harness/cookies.js';

const NOW = Date.UTC(2030, 0, 1) + 123;
let subject = 'google-user';
let hostedDomain = 'example.com';
let tokenFields: Record<string, unknown>;
let profileFields: Record<string, unknown>;
const requests: URLSearchParams[] = [];
const server = setupServer(http.post('https://oauth2.googleapis.com/token', async ({request}) => {
  requests.push(new URLSearchParams(await request.text()));
  const idToken = await new SignJWT({sub: subject, email: `${subject}@example.com`, email_verified: true, name: 'Google User', picture: 'https://example.com/avatar', hd: hostedDomain, ...profileFields})
    .setProtectedHeader({alg: 'HS256'}).sign(new TextEncoder().encode('trusted-code-endpoint-fixture-key'));
  return HttpResponse.json({access_token: `access-${subject}`, refresh_token: `refresh-${subject}`, id_token: idToken, expires_in: 12.5, refresh_token_expires_in: 120.5, scope: 'email read', ...tokenFields});
}));
beforeAll(() => server.listen({onUnhandledRequest: 'error'}));
afterAll(() => server.close());
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); subject = 'google-user'; hostedDomain = 'example.com'; tokenFields = {}; profileFields = {}; requests.length = 0; });
afterEach(() => { vi.useRealTimers(); server.resetHandlers(); });

const provider = {clientId: 'client', clientSecret: 'secret', enabled: true};
async function login(instance: any, headers = new Headers()) {
  const started: Response = await instance.auth.api.signInSocial({body: {provider: 'google', callbackURL: '/done'}, headers, asResponse: true});
  expect(started.status).toBe(200);
  const url = new URL((await started.json()).url);
  instance.cookieSetter(headers)({response: started});
  const response: Response = await instance.auth.handler(new Request(`http://localhost:3000/api/auth/callback/google?state=${url.searchParams.get('state')}&code=authorization-code`, {headers}));
  if (response.status === 302) instance.cookieSetter(headers)({response});
  return {response, headers, url};
}
function accountValue(headers: Headers) {
  const cookies = parseCookies(headers.get('cookie') ?? '');
  return getChunkedCookie({headers, getCookie: name => cookies.get(name)}, 'better-auth.account_data');
}

describe('native Google code flow and account cookies', () => {
  it('constructs the grant in V and binds PKCE, redirect URI, scopes and credentials', async () => {
    const instance = await getTestInstance({socialProviders: {google: {...provider, scope: ['calendar', 'email'], accessType: 'offline', includeGrantedScopes: false, hd: 'example.com'}}, account: {storeAccountCookie: true}, session: {cookieCache: {enabled: true}}});
    const {response, headers, url} = await login(instance);
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('/done');
    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(url.searchParams.get('scope')).toBe('email profile openid calendar email');
    expect(url.searchParams.has('include_granted_scopes')).toBe(false);
    expect(url.searchParams.get('access_type')).toBe('offline');
    expect(requests).toHaveLength(1);
    const grant = requests[0];
    expect(grant.get('client_id')).toBe('client');
    expect(grant.get('client_secret')).toBe('secret');
    expect(grant.get('grant_type')).toBe('authorization_code');
    expect(grant.get('code')).toBe('authorization-code');
    expect(grant.get('redirect_uri')).toBe('http://localhost:3000/api/auth/callback/google');
    expect(createHash('sha256').update(grant.get('code_verifier')!).digest('base64url')).toBe(url.searchParams.get('code_challenge'));
    const session = await instance.auth.api.getSession({headers});
    const ctx = await instance.auth.$context;
    const account = await symmetricDecodeJWT<any>(accountValue(headers)!, ctx.secretConfig, 'better-auth-account');
    expect(account?.userId).toBe(session?.user.id);
    expect(account?.accountId).toBe('google-user');
    expect(account?.accessToken).toBe('access-google-user');
    expect(account?.scope).toBe('email,read');
  });

  it.each([false, true])('persists tokens and precise expiries with encryption=%s', async encrypt => {
    const instance = await getTestInstance({socialProviders: {google: provider}, account: {storeAccountCookie: true, encryptOAuthTokens: encrypt}, session: {cookieCache: {enabled: true}}});
    const {response} = await login(instance);
    expect(response.status).toBe(302);
    const account = (await instance.db.findMany<any>({model: 'account', where: [{field: 'providerId', value: 'google'}]}))[0];
    expect(account.accessTokenExpiresAt).toEqual(new Date(NOW + 12500));
    expect(account.refreshTokenExpiresAt).toEqual(new Date(NOW + 120500));
    const ctx = await instance.auth.$context;
    if (encrypt) {
      expect(account.accessToken).not.toBe('access-google-user');
      expect(await symmetricDecrypt({key: ctx.secretConfig, data: account.accessToken})).toBe('access-google-user');
      expect(await symmetricDecrypt({key: ctx.secretConfig, data: account.refreshToken})).toBe('refresh-google-user');
    } else expect(account.accessToken).toBe('access-google-user');
  });

  it('retains omitted refresh tokens and unions grants during subsequent code exchanges', async () => {
    const instance = await getTestInstance({socialProviders: {google: provider}, account: {storeAccountCookie: true}, session: {cookieCache: {enabled: true}}});
    const first = await login(instance);
    const before = (await instance.db.findMany<any>({model: 'account', where: [{field: 'providerId', value: 'google'}]}))[0];
    tokenFields = {access_token: 'renewed', refresh_token: undefined, scope: ['write', ' read ', false, '']};
    const second = await login(instance, first.headers);
    expect(second.response.status).toBe(302);
    const after = (await instance.db.findMany<any>({model: 'account', where: [{field: 'providerId', value: 'google'}]}))[0];
    expect(after.id).toBe(before.id);
    expect(after.userId).toBe(before.userId);
    expect(after.accessToken).toBe('renewed');
    expect(after.refreshToken).toBe('refresh-google-user');
    expect(after.scope).toBe('email,read,write');
    expect((await instance.db.findMany({model: 'account', where: [{field: 'providerId', value: 'google'}]}))).toHaveLength(1);
  });

  it('enforces hosted-domain claims independently of the authorization hint', async () => {
    const instance = await getTestInstance({socialProviders: {google: {...provider, hd: 'example.com'}}});
    hostedDomain = 'other.example';
    const {response} = await login(instance);
    expect(response.status).toBe(403);
    expect((await response.json()).code).toBe('OAUTH_HOSTED_DOMAIN_MISMATCH');
    expect(await instance.db.findMany({model: 'account', where: [{field: 'providerId', value: 'google'}]})).toEqual([]);
  });

  it('refuses token endpoint redirects without forwarding credentials to another endpoint', async () => {
    let leaked = false;
    server.use(http.post('https://oauth2.googleapis.com/token', () => new HttpResponse(null, {status: 302, headers: {location: 'https://other.example/token'}})), http.post('https://other.example/token', () => { leaked = true; return HttpResponse.json({}); }));
    const instance = await getTestInstance({socialProviders: {google: provider}});
    expect((await login(instance)).response.status).toBe(502);
    expect(leaked).toBe(false);
  });

  it('rolls back account hooks that change the selected provider binding', async () => {
    const instance = await getTestInstance({socialProviders: {google: provider}, databaseHooks: {account: {create: {before: async account => account.providerId === 'google' ? {data: {...account, accountId: 'wrong-subject'}} : undefined}}}});
    const {response} = await login(instance);
    expect(response.status).toBe(409);
    expect((await response.json()).code).toBe('account_hook_binding_conflict');
    expect(await instance.db.findMany({model: 'account', where: [{field: 'providerId', value: 'google'}]})).toEqual([]);
    expect(await instance.db.findMany({model: 'user', where: [{field: 'email', value: 'google-user@example.com'}]})).toEqual([]);
  });

  it('chunks account data, keeps it readable and expires every chunk on logout', async () => {
    profileFields = {large: 'x'.repeat(8000)};
    const instance = await getTestInstance({socialProviders: {google: provider}, account: {storeAccountCookie: true}, session: {cookieCache: {enabled: true}}});
    const {headers, response} = await login(instance);
    const chunks = [...parseSetCookieHeader(response.headers.get('set-cookie')!)].filter(([name]) => name.startsWith('better-auth.account_data.'));
    expect(chunks.length).toBeGreaterThan(1);
    for (const line of response.headers.getSetCookie().filter(line => line.startsWith('better-auth.account_data.'))) expect(line.length).toBeLessThanOrEqual(4050);
    const ctx = await instance.auth.$context;
    expect((await symmetricDecodeJWT<any>(accountValue(headers)!, ctx.secretConfig, 'better-auth-account'))?.accessToken).toBe('access-google-user');
    const logout: Response = await instance.auth.api.signOut({headers, asResponse: true});
    const expired = parseSetCookieHeader(logout.headers.get('set-cookie')!);
    for (const [name] of chunks) expect(expired.get(name)?.['max-age']).toBe(0);
    expect(expired.get('better-auth.account_data')?.['max-age']).toBe(0);
  });

  it('issues account cookies even when the session cache is disabled', async () => {
    const instance = await getTestInstance({socialProviders: {google: provider}, account: {storeAccountCookie: true}});
    const {headers, response} = await login(instance);
    expect(response.status).toBe(302);
    expect(accountValue(headers)).toBeTruthy();
    expect(parseCookies(headers.get('cookie')!).has('better-auth.session_data')).toBe(false);
  });
});
