import {describe, expect, it, vi} from 'vitest';
import {getTestInstance} from './harness/test-instance.js';
import {genericOAuth} from './harness/plugins.js';

async function expectLocalSignOut(instance: Awaited<ReturnType<typeof getTestInstance>>, headers: Headers) {
  let response: Response | undefined;
  const result = await instance.client.signOut({fetchOptions: {headers, onSuccess: context => {response = context.response;}}});
  expect(result.error).toBeNull();
  expect(result.data).toEqual({success: true});
  expect(response!.headers.get('set-cookie')).toContain('better-auth.session_token=;');
  expect(response!.headers.get('set-cookie')).toContain('Max-Age=0');
}

describe('native sign-out failure isolation', () => {
  it.each(['deleteSession', 'transaction'] as const)('clears local cookies when %s fails', async method => {
    const instance = await getTestInstance();
    const {headers} = await instance.signInWithTestUser();
    const context = await instance.auth.$context;
    if (method === 'deleteSession') vi.spyOn(context.internalAdapter, method).mockRejectedValue(new Error('database unavailable'));
    else vi.spyOn(context.adapter, method).mockRejectedValue(new Error('commit unavailable'));
    await expectLocalSignOut(instance, headers);
  });

  it('clears local cookies after a database-backed secondary revocation fails', async () => {
    const store = new Map<string, string>();
    let failDeletes = false;
    const instance = await getTestInstance({session: {storeSessionInDatabase: true}, secondaryStorage: {
      get: key => store.get(key) ?? null,
      set: (key, value) => {store.set(key, value);},
      delete: key => {if (failDeletes) throw new Error('cache unavailable'); store.delete(key);},
      getAndDelete: key => {const value = store.get(key) ?? null; store.delete(key); return value;},
      increment: key => {const count = Number(store.get(key) ?? 0) + 1; store.set(key, String(count)); return count;},
    }});
    const {headers} = await instance.signInWithTestUser();
    failDeletes = true;
    await expectLocalSignOut(instance, headers);
  });

  it('falls back from an invalid newer logout endpoint and preserves existing URL parameters', async () => {
    const common = {clientId: 'client', clientSecret: 'secret', authorizationUrl: 'https://idp.test/auth', tokenUrl: 'https://idp.test/token', userInfoUrl: 'https://idp.test/userinfo'};
    const {auth, client, signInWithTestUser} = await getTestInstance({plugins: [genericOAuth({config: [
      {...common, providerId: 'older', endSessionEndpoint: 'https://idp.test/logout?existing=keep', postLogoutRedirectURI: '/goodbye?from=provider'},
      {...common, providerId: 'newer', endSessionEndpoint: 'not-an-absolute-url'},
    ]})]});
    const {headers, user} = await signInWithTestUser();
    const context = await auth.$context;
    await context.internalAdapter.createAccount({userId: user.id, providerId: 'older', accountId: 'old', idToken: 'id-token', updatedAt: new Date('2026-01-01T00:00:00Z')});
    await context.internalAdapter.createAccount({userId: user.id, providerId: 'newer', accountId: 'new', updatedAt: new Date('2026-01-02T00:00:00Z')});
    const result = await client.signOut({state: 'state value', disableRedirect: true, fetchOptions: {headers}});
    const url = new URL(result.data!.url!);
    expect(url.origin).toBe('https://idp.test');
    expect(url.searchParams.get('existing')).toBe('keep');
    expect(url.searchParams.get('id_token_hint')).toBe('id-token');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:3000/goodbye?from=provider');
    expect(url.searchParams.get('client_id')).toBe('client');
    expect(url.searchParams.get('state')).toBe('state value');
    expect(await auth.api.getSession({headers})).toBeNull();
  });
});
