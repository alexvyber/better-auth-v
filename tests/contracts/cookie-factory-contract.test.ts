import {afterEach, describe, expect, it, vi} from 'vitest';
import type {BetterAuthOptions} from 'better-auth';
import {createCookieGetter, getCookieCache, getCookies, parseSetCookieHeader} from '../harness/cookies.js';
import {getTestInstance} from '../harness/test-instance.js';
import {jwt} from '../harness/plugins.js';
import {decodeJwt} from 'jose';
import {spawnSync} from 'node:child_process';

afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); vi.resetModules(); });

describe('native cookie factory', () => {
  it.each([
    ['defaults', false, {}],
    ['production fallback', true, {}],
    ['static HTTP in production', true, {baseURL: 'http://example.com'}],
    ['static HTTPS', false, {baseURL: 'https://example.com'}],
    ['explicit false', true, {baseURL: 'https://example.com', advanced: {useSecureCookies: false}}],
    ['dynamic HTTPS', false, {baseURL: {allowedHosts: ['*.example.com'], protocol: 'https'}}],
    ['dynamic HTTP', true, {baseURL: {allowedHosts: ['*.example.com'], protocol: 'http'}}],
    ['dynamic auto', true, {baseURL: {allowedHosts: ['*.example.com'], protocol: 'auto'}}],
    ['dynamic cross-domain init', false, {baseURL: {allowedHosts: ['*.example.com']}, advanced: {crossSubDomainCookies: {enabled: true}}}],
    ['derived domain', false, {baseURL: 'https://login.example.com:8443', advanced: {crossSubDomainCookies: {enabled: true}}}],
    ['attribute precedence', false, {session: {expiresIn: 900, cookieCache: {maxAge: 123}}, advanced: {cookiePrefix: 'brand', defaultCookieAttributes: {maxAge: 456, sameSite: 'strict', path: '/default', httpOnly: false}, cookies: {session_token: {name: 'custom', attributes: {sameSite: 'none', path: '/session', maxAge: 42}}}}}],
    ['null and date attributes', false, {advanced: {defaultCookieAttributes: {expires: new Date('2030-01-01T00:00:00Z')}, cookies: {session_data: {attributes: {domain: null, maxAge: null}}}}}],
    ['fractional descriptors', false, {session: {expiresIn: 60.5, cookieCache: {maxAge: 12.5}}}],
    ['IPv6 domain', false, {baseURL: 'https://[::1]:8443', advanced: {crossSubDomainCookies: {enabled: true}}}],
  ] as const)('matches upstream descriptors: %s', async (_label, production, raw) => {
    vi.stubEnv('NODE_ENV', production ? 'production' : 'test');
    const options = raw as BetterAuthOptions;
    // External ESM dependencies retain their captured environment across
    // vi.resetModules. A fresh reference process proves initialization semantics.
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import {getCookies,createCookieGetter} from 'better-auth/cookies';
      import {readFileSync} from 'node:fs';
      const options=JSON.parse(readFileSync(0,'utf8'));
      console.log(JSON.stringify({cookies:getCookies(options),custom:createCookieGetter(options)('custom',{path:'/override',maxAge:15})}));
    `], {input: JSON.stringify(options), encoding: 'utf8'});
    expect(result.status, result.stderr).toBe(0);
    const reference = JSON.parse(result.stdout);
    expect(JSON.parse(JSON.stringify(getCookies(options)))).toEqual(reference.cookies);
    expect(JSON.parse(JSON.stringify(createCookieGetter(options)('custom', {path: '/override', maxAge: 15})))).toEqual(reference.custom);
    if (_label === 'null and date attributes') expect(getCookies(options).sessionToken.attributes.expires).toBeInstanceOf(Date);
  });

  it('rejects cross-domain initialization without a domain or base URL', async () => {
    const reference = await import('better-auth/cookies');
    const options = {advanced: {crossSubDomainCookies: {enabled: true}}};
    expect(() => getCookies(options)).toThrow('baseURL is required');
    expect(() => reference.getCookies(options)).toThrow('baseURL is required');
  });

  it('preserves initialization-time security when environment and request scheme change', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    const {auth, testUser} = await getTestInstance({baseURL: undefined});
    vi.stubEnv('NODE_ENV', 'test');
    const response = await auth.handler(new Request('http://localhost:3000/api/auth/sign-in/email', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(testUser)}));
    expect(response.status).toBe(200);
    const token = response.headers.getSetCookie().find(value => value.startsWith('__Secure-better-auth.session_token='));
    expect(token).toContain('; Secure');
  });

  it('applies default/per-cookie attributes consistently to issuance and expiry', async () => {
    const {auth, testUser, cookieSetter} = await getTestInstance({advanced: {
      defaultCookieAttributes: {path: '/custom', httpOnly: false, sameSite: 'strict'},
      cookies: {session_token: {attributes: {partitioned: true}}, session_data: {attributes: {httpOnly: true, path: '/cache'}}},
    }, session: {cookieCache: {enabled: true}}});
    const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const cookies = parseSetCookieHeader(response.headers.get('set-cookie')!);
    const token = cookies.get('better-auth.session_token')!;
    expect(token.path).toBe('/custom');
    expect(token.httponly).toBeUndefined();
    expect(token.secure).toBe(true);
    expect(token.partitioned).toBe(true);
    expect(token.samesite).toBe('strict');
    expect(cookies.get('better-auth.session_data')?.path).toBe('/cache');
    expect(cookies.get('better-auth.session_data')?.httponly).toBe(true);
    const headers = new Headers(); cookieSetter(headers)({response});
    const logout: Response = await auth.api.signOut({headers, asResponse: true});
    const expired = parseSetCookieHeader(logout.headers.get('set-cookie')!);
    expect(expired.get('better-auth.session_token')).toEqual({...token, value: '', 'max-age': 0});
    expect(expired.get('better-auth.session_data')?.path).toBe('/cache');
  });

  it.each(['compact', 'jwt', 'jwe', 'jwks'] as const)('uses configured cache lifetime for %s and respects rememberMe', async strategy => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2030-01-01T00:00:00.123Z'));
    const plugins = strategy === 'jwks' ? [jwt({sessionCookieCache: true})] : [];
    const secret = 'cookie-factory-contract-secret-at-least-32-bytes';
    const {auth, testUser} = await getTestInstance({secret, plugins, session: {cookieCache: {enabled: true, strategy: strategy === 'jwks' ? 'jwt' : strategy, maxAge: 300}}, advanced: {
      defaultCookieAttributes: {maxAge: 999}, cookies: {session_token: {attributes: {maxAge: 99}}, session_data: {attributes: {maxAge: 12}}},
    }});
    const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const cookies = parseSetCookieHeader(response.headers.get('set-cookie')!);
    expect(cookies.get('better-auth.session_token')?.['max-age']).toBe(604800);
    expect(cookies.get('better-auth.session_data')?.['max-age']).toBe(12);
    if (strategy === 'jwks') {
      const claims = decodeJwt(cookies.get('better-auth.session_data')!.value);
      expect(claims.exp! - claims.iat!).toBe(12);
    }
    const temporary: Response = await auth.api.signInEmail({body: {...testUser, rememberMe: false}, asResponse: true});
    const temporaryCookies = parseSetCookieHeader(temporary.headers.get('set-cookie')!);
    expect(temporaryCookies.get('better-auth.session_data')?.['max-age']).toBeUndefined();
    expect(temporaryCookies.get('better-auth.dont_remember')?.['max-age']).toBe(999);
    if (strategy === 'jwks') {
      const claims = decodeJwt(temporaryCookies.get('better-auth.session_data')!.value);
      expect(claims.exp! - claims.iat!).toBe(300);
    } else {
      const header = new Headers({cookie: `better-auth.session_data=${cookies.get('better-auth.session_data')!.value}`});
      expect(await getCookieCache(header, {secret, strategy})).not.toBeNull();
      vi.setSystemTime(Date.now() + 12001);
      if (strategy === 'jwe') {
        expect(await getCookieCache(header, {secret, strategy})).not.toBeNull();
        vi.setSystemTime(Date.now() + 15000);
      }
      expect(await getCookieCache(header, {secret, strategy})).toBeNull();
    }
  });

  it('enforces Host-prefix invariants and rejects attribute header injection', async () => {
    const {auth, testUser} = await getTestInstance({advanced: {cookies: {session_token: {name: '__Host-token', attributes: {path: '/wrong', domain: 'example.com', secure: false}}}}});
    const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const token = parseSetCookieHeader(response.headers.get('set-cookie')!).get('__Host-token')!;
    expect(token.path).toBe('/');
    expect(token.secure).toBe(true);
    expect(token.domain).toBeUndefined();
    await expect(getTestInstance({advanced: {defaultCookieAttributes: {path: '/\r\nInjected: value'}}})).rejects.toThrow('invalid cookie attribute path');
  });
});
