import {createHash} from 'node:crypto';
import {APIError} from '@better-auth/core/error';
import {OAuth2Server} from 'oauth2-mock-server';
import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import {genericOAuth} from './harness/plugins.js';
import {getTestInstance} from './harness/test-instance.js';

const provider = new OAuth2Server();
let issuer = '';
let email = 'provisioned@example.com';
let verified = true;
let tokenRequest: {authorization?: string; verifier?: string; secret?: string} = {};
beforeAll(async () => {
 await provider.start(); issuer = provider.issuer.url!;
 await provider.issuer.keys.generate('RS256');
 provider.service.on('beforeTokenSigning', token => {Object.assign(token.payload, {email, email_verified: verified, name: 'Nabu operator'});});
 provider.service.on('beforeResponse', (_response, request) => {
  if (request.url?.startsWith('/token')) tokenRequest = {authorization: request.headers.authorization, verifier: request.body.code_verifier, secret: request.body.client_secret};
 });
});
afterAll(async () => {await provider.stop();});

async function instance() {
 const configuration = genericOAuth({config: [{
  providerId: 'tinyauth', name: 'Code & Money', discoveryUrl: `${issuer}/.well-known/openid-configuration`,
  clientId: 'nabu-client', clientSecret: 'nabu-secret', requireIdTokenVerification: true,
  tokenEndpointAuth: {method: 'client_secret_basic'}, scopes: ['openid', 'profile', 'email'], pkce: true,
  disableImplicitSignUp: true, disableSignUp: true, disableProviderLogout: true,
  async mapProfileToUser(profile) {
   if (profile.email_verified !== true || typeof profile.email !== 'string' || !profile.email.trim()) throw new APIError('FORBIDDEN', {message: 'A verified SSO email is required'});
   const normalized = profile.email.trim().toLowerCase();
   if (normalized !== 'provisioned@example.com') throw new APIError('FORBIDDEN', {message: 'This SSO identity is not provisioned for Nabu'});
   return {email: normalized, emailVerified: true};
  },
 }]});
 const ready = await getTestInstance({
  plugins: [configuration], account: {accountLinking: {enabled: true, trustedProviders: ['tinyauth'], allowDifferentEmails: false}},
  emailAndPassword: {enabled: false, disableSignUp: true, minPasswordLength: 12},
 }, {disableTestUser: true});
 const adapter = (await ready.auth.$context).internalAdapter;
 const user = await adapter.createUser({email: 'provisioned@example.com', name: 'Provisioned', emailVerified: true}, {method: 'test'});
 return {...ready, user};
}
async function authorize(ready: Awaited<ReturnType<typeof instance>>) {
 const headers = new Headers();
 const response = await ready.auth.api.signInSocial({body: {provider: 'tinyauth', callbackURL: 'http://localhost:3000/nabu'}, asResponse: true});
 ready.cookieSetter(headers)({response});
 const {url} = await response.json();
 const authorization = new URL(url);
 const redirect = await fetch(url, {redirect: 'manual'});
 const callback = redirect.headers.get('location')!;
 const result = await ready.auth.handler(new Request(callback, {headers}));
 return {authorization, callback, headers, result};
}

describe('Nabu provisioned OIDC configuration', () => {
 it('verifies signed identity, uses Basic and PKCE, and links only the provisioned user', async () => {
  email = 'Provisioned@Example.com'; verified = true;
  const ready = await instance();
  const {authorization, result, callback, headers} = await authorize(ready);
  expect(result.status).toBe(302); expect(result.headers.get('location')).toBe('http://localhost:3000/nabu');
  expect(tokenRequest.authorization).toBe('Basic ' + Buffer.from('nabu-client:nabu-secret').toString('base64'));
  expect(tokenRequest.secret).toBeUndefined();
  expect(createHash('sha256').update(tokenRequest.verifier!).digest('base64url')).toBe(authorization.searchParams.get('code_challenge'));
  expect(authorization.searchParams.get('nonce')).toBeTruthy();
  const replayHeaders = new Headers(headers);
  ready.cookieSetter(headers)({response: result});
  expect((await ready.auth.api.getSession({headers}))?.user.id).toBe(ready.user.id);
  expect((await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).map((account: any) => account.providerId)).toEqual(['tinyauth']);
  expect((await ready.auth.handler(new Request(callback, {headers: replayHeaders}))).status).toBe(400);
 });

 it('rejects a signed but unprovisioned identity without registering it', async () => {
  email = 'outsider@example.com'; verified = true;
  const ready = await instance();
  const {result} = await authorize(ready);
  expect(result.headers.get('location')).toContain('?error=');
  const adapter = (await ready.auth.$context).internalAdapter;
  expect(await adapter.findUserByEmail(email)).toBeNull();
  expect(await adapter.findAccounts(ready.user.id)).toEqual([]);
  expect(result.headers.getSetCookie().some(value => value.startsWith('better-auth.session_token='))).toBe(false);
 });

 it('rejects a signed profile whose email is unverified', async () => {
  email = 'provisioned@example.com'; verified = false;
  const ready = await instance();
  expect((await authorize(ready)).result.headers.get('location')).toContain('?error=');
  expect(await (await ready.auth.$context).internalAdapter.findAccounts(ready.user.id)).toEqual([]);
 });

 it('disables public password registration while retaining provisioned password login', async () => {
  const {auth} = await getTestInstance({emailAndPassword: {enabled: true, disableSignUp: true, minPasswordLength: 12}}, {disableTestUser: true});
  await expect(auth.api.signUpEmail({body: {email: 'outsider@example.com', name: 'Outsider', password: 'long-password'}})).rejects.toMatchObject({body: {code: 'EMAIL_PASSWORD_SIGN_UP_DISABLED'}});
  const context = await auth.$context;
  const user = await context.internalAdapter.createUser({email: 'operator@example.com', name: 'Operator', emailVerified: true}, {method: 'test'});
  await context.internalAdapter.createAccount({userId: user.id, providerId: 'credential', accountId: user.id, password: await context.password.hash('long-password')});
  expect((await auth.api.signInEmail({body: {email: user.email, password: 'long-password'}})).user.id).toBe(user.id);
 });
});
