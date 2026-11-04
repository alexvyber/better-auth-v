import { describe, expect, it } from 'vitest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { jwt } from './harness/plugins.js';
import { betterAuth, DatabaseSync, getMigrations, NodeSqliteDialect, runWithTransaction } from './harness/native-auth.js';

describe('native JWT transaction fixture', () => {
  it('requires real migrations and rolls back a minted signing key on an outer failure', async () => {
    const auth = betterAuth({
      baseURL: 'http://localhost:3000',
      secret: 'transaction-test-secret-that-is-long-enough',
      database: {dialect: new NodeSqliteDialect({database: new DatabaseSync(':memory:')}), type: 'sqlite', transaction: true},
      emailAndPassword: {enabled: true},
      plugins: [jwt()],
    });
    const ctx = await auth.$context;
    await expect(ctx.adapter.findMany({model: 'jwks'})).rejects.toThrow();
    await (await getMigrations(auth.options)).runMigrations();
    const signup = await auth.api.signUpEmail({body: {email: 'txn@example.com', password: 'password123', name: 'Transaction'}, returnHeaders: true});
    const headers = new Headers({cookie: signup.headers.getSetCookie()[0]});
    const failure = new Error('Abort the outer transaction');
    await expect(runWithTransaction(ctx.adapter, async () => {
      const {token} = await auth.api.getToken({headers});
      expect(token.split('.')).toHaveLength(3);
      expect(await ctx.adapter.findMany({model: 'jwks'})).toHaveLength(1);
      throw failure;
    })).rejects.toBe(failure);
    expect(await ctx.adapter.findMany({model: 'jwks'})).toHaveLength(0);
    const {token} = await runWithTransaction(ctx.adapter, async () => runWithTransaction(ctx.adapter, () => auth.api.getToken({headers})));
    expect(await ctx.adapter.findMany({model: 'jwks'})).toHaveLength(1);
    expect((await jwtVerify(token, createLocalJWKSet(await auth.api.getJwks()))).payload.sub).toBeTypeOf('string');
  });
});
