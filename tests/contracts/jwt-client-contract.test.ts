import { describe, expect, expectTypeOf, it } from 'vitest';
import type { BetterAuthClientPlugin } from '@better-auth/core';
import { createAuthClient } from 'better-auth/client';
import { inferAdditionalFields, jwtClient } from 'better-auth/client/plugins';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { getTestInstance } from '../harness/test-instance.js';
import { jwt } from '../harness/plugins.js';

describe('official typed JWT client against the native backend', () => {
  it('preserves inferred optional fields through signup, update, sessions and JWT issuance', async () => {
    const {auth, cookieSetter} = await getTestInstance({
      user: {additionalFields: {logo: {type: 'string', required: false}}},
      plugins: [jwt()],
    }, {disableTestUser: true});
    const headers = new Headers();
    const clientPlugin: BetterAuthClientPlugin = jwtClient();
    expect(clientPlugin.id).toBe('better-auth-client');
    const client = createAuthClient({
      baseURL: 'http://localhost:3000/api/auth',
      plugins: [inferAdditionalFields({user: {logo: {type: 'string', required: false}}}), jwtClient()],
      fetchOptions: {
        customFetchImpl: async (url, init) => {
          const request = new Request(url, init);
          const cookie = headers.get('cookie');
          if (cookie) request.headers.set('cookie', cookie);
          if (request.method === 'POST') request.headers.set('origin', 'http://localhost:3000');
          return auth.handler(request);
        },
        onSuccess(context) { cookieSetter(headers)({response: context.response}); },
      },
    });
    type UpdateBody = NonNullable<Parameters<typeof client.updateUser>[0]>;
    expectTypeOf<UpdateBody>().toMatchTypeOf<{logo?: string | null | undefined}>();
    const signup = await client.signUp.email({email: 'typed-client@example.com', password: 'password123', name: 'Typed', logo: 'https://example.com/first.png'});
    expect(signup.error).toBeNull();
    expect(signup.data?.user.logo).toBe('https://example.com/first.png');
    const body = {logo: 'https://example.com/updated.png'} satisfies UpdateBody;
    expect((await client.updateUser(body)).error).toBeNull();
    expect((await client.getSession()).data?.user.logo).toBe(body.logo);
    const jwks = await client.jwks();
    expect(jwks.error).toBeNull();
    const signed = await client.token();
    expect(signed.error).toBeNull();
    expect((await jwtVerify(signed.data!.token, createLocalJWKSet(jwks.data!))).payload.logo).toBe(body.logo);
    expect((await client.updateUser({logo: null} satisfies UpdateBody)).error).toBeNull();
    expect((await client.getSession()).data?.user.logo).toBeNull();
  });
});
