import {describe, expect, it} from 'vitest';
import {getTestInstance} from './harness/test-instance.js';

describe('Nabu database rate limits', () => {
 it('keeps failed authentication attempts counted after the auth transaction rolls back', async () => {
  const {auth} = await getTestInstance({rateLimit: {enabled: true, storage: 'database', customRules: {'/sign-in/email': {max: 1, window: 10}}}}, {disableTestUser: true});
  const request = () => new Request('http://localhost:3000/api/auth/sign-in/email', {method: 'POST', headers: {'content-type': 'application/json', origin: 'http://localhost:3000'}, body: JSON.stringify({email: 'unknown@example.com', password: 'long-password'})});
  expect((await auth.handler(request())).status).toBe(401);
  const blocked = await auth.handler(request());
  expect(blocked.status).toBe(429);
  expect(blocked.headers.get('x-retry-after')).toBe('10');
  expect(await blocked.json()).toEqual({message: 'Too many requests. Please try again later.'});
  await expect(auth.api.signInEmail({body: {email: 'unknown@example.com', password: 'long-password'}})).rejects.toMatchObject({statusCode: 401});
 });

 it('isolates trusted client buckets and ignores attacker-controlled left chain entries', async () => {
  const {auth} = await getTestInstance({advanced: {trustedProxyHeaders: true}, rateLimit: {enabled: true, storage: 'database', max: 1, window: 60}}, {disableTestUser: true});
  const request = (ip: string) => new Request('http://localhost:3000/api/auth/get-session', {headers: {'x-forwarded-for': ip}});
  expect((await auth.handler(request('attacker-a, 203.0.113.1'))).status).toBe(200);
  expect((await auth.handler(request('attacker-b, 203.0.113.1'))).status).toBe(429);
  expect((await auth.handler(request('203.0.113.2'))).status).toBe(200);
 });
});
