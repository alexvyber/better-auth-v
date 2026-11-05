import {describe, expect, it} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';

describe('native cookie configuration and scope', () => {
  it.each([true, false])('uses secure override %s consistently for custom token, cache and marker cookies', async secure => {
    const {auth, testUser, cookieSetter} = await getTestInstance({baseURL: 'https://login.example.com',
      advanced: {useSecureCookies: secure, crossSubDomainCookies: {enabled: true, domain: '.example.com'},
        cookies: {session_token: {name: 'token'}, session_data: {name: 'cache'}, dont_remember: {name: 'marker'}}},
      session: {cookieCache: {enabled: true}},
    });
    const response: Response = await auth.api.signInEmail({body: {...testUser, rememberMe: false}, asResponse: true});
    const cookies = response.headers.getSetCookie();
    const prefix = secure ? '__Secure-' : '';
    for (const name of ['token', 'cache', 'marker']) {
      const value = cookies.find(cookie => cookie.startsWith(`${prefix}${name}=`));
      expect(value).toBeDefined();
      expect(value).toContain('Domain=.example.com');
      expect(value!.includes('; Secure')).toBe(secure);
      expect(value).not.toContain('Max-Age=');
    }
    const headers = new Headers();
    cookieSetter(headers)({response});
    expect(await auth.api.getSession({headers})).not.toBeNull();
    const signedOut: Response = await auth.api.signOut({headers, asResponse: true});
    for (const name of ['token', 'cache', 'marker']) {
      const value = signedOut.headers.getSetCookie().find(cookie => cookie.startsWith(`${prefix}${name}=`));
      expect(value).toContain('Domain=.example.com');
      expect(value).toContain('Max-Age=0');
      expect(value!.includes('; Secure')).toBe(secure);
    }
  });

  it('derives the cookie domain from the configured hostname and honors a prefix', async () => {
    const {auth, testUser} = await getTestInstance({baseURL: 'https://login.example.com:8443',
      advanced: {cookiePrefix: 'brand', crossSubDomainCookies: {enabled: true}},
    });
    const response: Response = await auth.api.signInEmail({body: testUser, asResponse: true});
    const token = response.headers.getSetCookie().find(value => value.startsWith('__Secure-brand.session_token='));
    expect(token).toContain('Domain=login.example.com');
    expect(token).not.toContain('Domain=login.example.com:8443');
  });

  it('rejects cookie name and domain header injection at initialization', async () => {
    await expect(getTestInstance({advanced: {cookies: {session_token: {name: 'bad;name'}}}})).rejects.toThrow('invalid cookie name');
    await expect(getTestInstance({advanced: {crossSubDomainCookies: {enabled: true, domain: '.example.com; Secure'}}})).rejects.toThrow('invalid cookie domain');
  });
});
