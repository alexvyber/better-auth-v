import {describe, expect, it, vi} from 'vitest';
import {createHash} from 'node:crypto';
import {createAuthorizationURL as referenceURL, encodeBasicCredentials as referenceEncode, decodeBasicCredentials as referenceDecode} from '@better-auth/core/oauth2';
import {google as referenceGoogle} from '@better-auth/core/social-providers';
import {getTestInstance} from './harness/test-instance.js';
import {createAuthorizationURL, encodeBasicCredentials, decodeBasicCredentials, oauthNative} from './harness/oauth-helpers.js';

const base = {
  id: 'test', options: {clientId: 'client', clientSecret: 'secret'},
  authorizationEndpoint: 'https://idp.example/authorize', state: 'state', redirectURI: 'https://app.example/callback', scopes: ['openid'],
};
describe('native shared OAuth authorization and credential helpers', () => {
  it.each([
    {authorizationEndpoint: 'https://IDP.example:443', state: '', redirectURI: '', scopes: []},
    {authorizationEndpoint: 'https://idp.example/auth?state=old&state=other&custom=a%20b&flag=&x=a;b#fragment', scopes: ['email', 'email', 'openid'], codeVerifier: 'verifier!*', nonce: 'server', additionalParams: {state: 'evil', code_challenge: 'evil', identity_provider: 'A B', custom: 'changed!*~'}},
    {options: {clientId: ['primary', 'secondary'], authorizationEndpoint: 'https://override.example/?a=1&a=2', redirectURI: 'https://configured.example/'}, claims: ['2', '__proto__', 'email', '0', 'name'], display: 'popup', loginHint: 'user@example.com', responseMode: 'form_post', accessType: 'offline', duration: 'permanent', prompt: 'consent', hd: 'example.com', responseType: 'id_token', scopeJoiner: ','},
    {authorizationEndpoint: 'https://idp.example/?scope=existing&bad=%E1%80&escape=%ZZ', scopes: [], claims: []},
  ])('matches source URL construction for %#', async (patch) => {
    const input = {...base, ...patch};
    const expected = (await referenceURL(input)).href;
    expect(oauthNative({op: 'authorization-url', input})).toBe(expected);
    expect((await createAuthorizationURL(input)).href).toBe(expected);
  });

  it('awaits the supplied options callback once and derives PKCE in V', async () => {
    const options = vi.fn(async () => ({clientId: 'resolved'}));
    const url = await createAuthorizationURL({...base, options, codeVerifier: 'native verifier'});
    expect(options).toHaveBeenCalledOnce();
    expect(url.searchParams.get('client_id')).toBe('resolved');
    expect(url.searchParams.get('code_challenge')).toBe(createHash('sha256').update('native verifier').digest('base64url'));
  });

  it.each([undefined, '', [], ['', 'secondary']])('rejects a missing designated primary client ID: %j', async (clientId) => {
    const input = {...base, options: {clientId}};
    await expect(referenceURL(input)).rejects.toThrow('requires clientId');
    await expect(createAuthorizationURL(input)).rejects.toThrow('requires clientId');
  });

  it.each([
    ['alice!*\'~', 'p@ss word (1)'], ['クライアント', '🔑secret'], ['\uFEFFid', 'nul\u0000+&:'],
  ])('matches independent Basic credential encoding for %j', (id, secret) => {
    expect(encodeBasicCredentials(id, secret)).toBe(referenceEncode(id, secret));
    expect(decodeBasicCredentials(referenceEncode(id, secret))).toEqual({clientId: id, clientSecret: secret});
  });

  it.each(['id:%E1%80', 'id:%F0%9F%92', 'id:%E0%80%AF', 'id:%FF%ZZ+%20', 'id:%EF%BB%BFsecret', 'id:first&other=ignored', '\uFEFFid:secret'])('matches lenient form/UTF-8 decoding for %j', (payload) => {
    const header = 'Basic ' + Buffer.from(payload).toString('base64');
    expect(decodeBasicCredentials(header)).toEqual(referenceDecode(header));
  });

  it.each(['Basic abc\n', 'Basic\tabc', ' Basic aWQ6cw==', 'Basic aWQ6cw== ', 'Basic !', 'Basic aWQ6cw==trailing!'])('matches Basic malformed header handling for %j', (header) => {
    let expected: ReturnType<typeof referenceDecode> | undefined;
    let failure: Error | undefined;
    try { expected = referenceDecode(header); } catch (error) { failure = error as Error; }
    if (failure) expect(() => decodeBasicCredentials(header)).toThrow(failure.message);
    else expect(decodeBasicCredentials(header)).toEqual(expected);
  });

  it('forwards per-request Google scopes, hints and non-reserved parameters and sets Location only for redirects', async () => {
    const {auth} = await getTestInstance({socialProviders: {google: {clientId: 'client', clientSecret: 'secret', includeGrantedScopes: false}}});
    const request = (disableRedirect: boolean) => auth.handler(new Request('http://localhost:3000/api/auth/sign-in/social', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({provider: 'google', scopes: ['calendar'], loginHint: 'user@example.com', disableRedirect, additionalParams: {include_granted_scopes: 'true', access_type: 'offline'}})}));
    const redirect = await request(false);
    expect(redirect.status).toBe(200);
    const body = await redirect.json();
    expect(body.redirect).toBe(true);
    expect(redirect.headers.get('location')).toBe(body.url);
    const url = new URL(body.url);
    expect(url.searchParams.get('scope')).toBe('email profile openid calendar');
    expect(url.searchParams.get('login_hint')).toBe('user@example.com');
    expect(url.searchParams.get('include_granted_scopes')).toBe('true');
    expect(url.searchParams.get('access_type')).toBe('offline');
    const manual = await request(true);
    expect(manual.headers.has('location')).toBe(false);
  });

  it('rejects reserved and malformed authorization input at the HTTP boundary', async () => {
    const {auth} = await getTestInstance({socialProviders: {google: {clientId: 'client', clientSecret: 'secret'}}});
    const invalid = [
      ...['state', 'client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'nonce', 'scope'].map(key => ({additionalParams: {[key]: 'untrusted'}})),
      {additionalParams: null}, {additionalParams: []}, {additionalParams: {custom: 42}}, {scopes: null}, {scopes: 'calendar'}, {scopes: [42]}, {loginHint: null},
    ];
    for (const fields of invalid) {
      const response = await auth.handler(new Request('http://localhost:3000/api/auth/sign-in/social', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({provider: 'google', ...fields})}));
      expect(response.status, JSON.stringify(fields)).toBe(400);
      expect(response.headers.has('set-cookie')).toBe(false);
    }
  });

  it('uses the shared builder in real Google HTTP sign-in, preserving repeated scopes and endpoint configuration', async () => {
    const {auth} = await getTestInstance({socialProviders: {google: {clientId: 'client', clientSecret: 'secret', scope: ['email', 'calendar'], authorizationEndpoint: 'https://google.example/authorize?state=old&state=other'}}});
    const result = await auth.api.signInSocial({body: {provider: 'google', callbackURL: '/', disableRedirect: true}});
    const url = new URL(result.url);
    expect(url.origin).toBe('https://google.example');
    expect(url.searchParams.getAll('state')).toHaveLength(1);
    const expected = await referenceGoogle({clientId: 'client', clientSecret: 'secret', scope: ['email', 'calendar']}).createAuthorizationURL({state: 'state', codeVerifier: 'verifier', redirectURI: 'https://app.example/callback'});
    expect(url.searchParams.get('scope')).toBe(expected.searchParams.get('scope'));
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });
});
