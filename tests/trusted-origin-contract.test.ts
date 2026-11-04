import {describe, expect, it} from 'vitest';
import {getTrustedOrigins} from './harness/trusted-origins.js';
import {getTestInstance} from './harness/test-instance.js';

describe('native request-scoped origin enforcement', () => {
  it('keeps callback-derived allowlists isolated across concurrent HTTP calls', async () => {
    const {auth, testUser} = await getTestInstance({trustedOrigins: async request => {
      if (!request) return [];
      await new Promise(resolve => setTimeout(resolve, 5));
      return [request.headers.get('x-allowed-origin')!];
    }});
    const request = (allowed: string) => new Request('http://localhost:3000/api/auth/sign-in/email', {
      method: 'POST', headers: {'content-type': 'application/json', origin: 'https://tenant-one.test', 'x-allowed-origin': allowed}, body: JSON.stringify(testUser),
    });
    const [allowed, rejected] = await Promise.all([
      auth.handler(request('https://tenant-one.test')),
      auth.handler(request('https://tenant-two.test')),
    ]);
    expect(allowed.status).toBe(200);
    expect(rejected.status).toBe(403);
    expect(rejected.headers.get('access-control-allow-origin')).toBeNull();
    expect((await auth.handler(request('https://tenant-two.test'))).status).toBe(403);
  });

  it('adds HTTP for loopback hosts without treating lookalike domains as loopback', async () => {
    const allowedHosts = ['tenant.localhost:3000', '[0:0:0:0:0:0:0:1]:8080', '[::ffff:127.0.0.1]:8080', '127.evil.test', '127.999.0.1'];
    const origins = await getTrustedOrigins({baseURL: {allowedHosts, protocol: 'https'}});
    for (const host of allowedHosts.slice(0, 3)) expect(origins).toContain('http://' + host);
    for (const host of allowedHosts.slice(3)) expect(origins).not.toContain('http://' + host);
  });

  it('enforces wildcard boundaries and relative-path safety at the HTTP boundary', async () => {
    const {auth, testUser} = await getTestInstance({trustedOrigins: ['https://*.tenant.test']});
    const request = (origin: string, callbackURL: string) => new Request('http://localhost:3000/api/auth/sign-in/email', {
      method: 'POST', headers: {'content-type': 'application/json', origin}, body: JSON.stringify({...testUser, callbackURL}),
    });
    expect((await auth.handler(request('https://one.tenant.test', '/café?next=%2Fdashboard'))).status).toBe(200);
    expect((await auth.handler(request('https://one.tenant.test.evil.test', '/dashboard'))).status).toBe(403);
    expect((await auth.handler(request('http://one.tenant.test', '/dashboard'))).status).toBe(403);
    expect((await auth.handler(request('https://one.tenant.test', '/safe/%2f/evil.test'))).status).toBe(403);
    expect((await auth.handler(request('https://one.tenant.test', '/safe/%5c/evil.test'))).status).toBe(403);
    expect((await auth.handler(request('https://one.tenant.test', '//evil.test'))).status).toBe(403);
  });
});
