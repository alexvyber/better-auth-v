import {describe, expect, it, vi} from 'vitest';
import {exportJWK, exportPKCS8, generateKeyPair, jwtVerify} from 'jose';
import {http, HttpResponse} from 'msw';
import {setupServer} from 'msw/node';
import {authorizationCodeRequest, clientCredentialsToken, refreshAccessToken, signPrivateKeyJwtClientAssertion, validateAuthorizationCode} from './harness/oauth-token.js';

describe('native token endpoint contracts', () => {
  it.each(['RS256', 'PS256', 'ES256', 'EdDSA'] as const)('signs PKCS#8 %s assertions that JOSE independently verifies', async algorithm => {
    const pair = await generateKeyPair(algorithm, {extractable: true});
    const assertion = await signPrivateKeyJwtClientAssertion({clientId: 'client', tokenEndpoint: 'https://idp.example/token', privateKeyPem: await exportPKCS8(pair.privateKey), algorithm, expiresIn: 45.5});
    const {payload, protectedHeader} = await jwtVerify(assertion, pair.publicKey, {issuer: 'client', audience: 'https://idp.example/token'});
    expect(payload.sub).toBe('client');
    expect(payload.exp! - payload.iat!).toBe(45.5);
    expect(protectedHeader.typ).toBe('JWT');
  });

  it.each(['authorization_code', 'refresh_token', 'client_credentials'] as const)('sends a real %s request and dates tokens from response time', async grant => {
    let seen: URLSearchParams | undefined;
    let responseTime = 2000000000000;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => responseTime);
    const server = setupServer(http.post('https://idp.example/token', async ({request}) => {
      seen = new URLSearchParams(await request.text());
      expect(request.headers.get('authorization')).toBe('Basic Y2xpZW50OnNlY3JldA==');
      responseTime += 5000;
      return HttpResponse.json({access_token: 'access', refresh_token: 'refresh', token_type: 'Bearer', expires_in: 12.5, refresh_token_expires_in: 30, scope: 'openid  email'});
    }));
    server.listen({onUnhandledRequest: 'error'});
    try {
      const common = {options: {clientId: 'client', clientSecret: 'secret'}, authentication: 'basic' as const, tokenEndpoint: 'https://idp.example/token', resource: ['one', 'two']};
      const tokens = grant === 'authorization_code' ? await validateAuthorizationCode({...common, code: 'code', codeVerifier: 'verifier', redirectURI: 'https://app.example/callback'}) : grant === 'refresh_token' ? await refreshAccessToken({...common, refreshToken: 'old'}) : await clientCredentialsToken({...common, scope: 'openid'});
      expect(seen!.get('grant_type')).toBe(grant);
      expect(seen!.getAll('resource')).toEqual(['one', 'two']);
      expect(tokens.accessToken).toBe('access');
      expect(tokens.accessTokenExpiresAt!.getTime()).toBe(responseTime + 12500);
      expect(tokens.scopes).toEqual(grant === 'client_credentials' ? ['openid', '', 'email'] : ['openid', 'email']);
      if (grant !== 'client_credentials') expect(tokens.refreshTokenExpiresAt!.getTime()).toBe(responseTime + 30000);
    } finally { server.close(); clock.mockRestore(); }
  });

  it('preserves async custom authentication context, repeated form fields and callback failures', async () => {
    const options = {clientId: ['primary', 'secondary']};
    const error = new Error('business callback failed');
    const result = await authorizationCodeRequest({code: 'code', redirectURI: 'https://app.example/callback', options, tokenEndpoint: 'https://idp.example/token', resource: ['one', 'two'], tokenEndpointAuth: {method: 'custom', async customizeRequest(context) {
      expect(context.options).toBe(options);
      expect(context.grantType).toBe('authorization_code');
      context.body.append('resource', 'three');
      context.headers.authorization = 'custom';
    }}});
    expect(result.body.getAll('resource')).toEqual(['one', 'two', 'three']);
    expect(result.headers.authorization).toBe('custom');
    await expect(authorizationCodeRequest({code: 'code', redirectURI: 'callback', options, tokenEndpointAuth: {method: 'custom', async customizeRequest() { throw error; }}})).rejects.toBe(error);
  });
});
