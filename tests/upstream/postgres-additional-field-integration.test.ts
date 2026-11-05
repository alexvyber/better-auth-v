// Generated from pinned upstream source; do not edit assertions here.
import {describe,expect,expectTypeOf,it} from 'vitest';
import {createAuthClient} from 'better-auth/client';
import {inferAdditionalFields,twoFactorClient} from 'better-auth/client/plugins';
import {twoFactor} from '../harness/plugins.js';
import {getTestInstance} from '../harness/postgres-fixture.js';

describe("additionalFields", async () => {
	const { auth, signInWithTestUser, customFetchImpl, sessionSetter } =
		await getTestInstance({
			plugins: [twoFactor()],
			user: {
				additionalFields: {
					newField: {
						type: "string",
						defaultValue: "default-value",
					},
					nonRequiredFiled: {
						type: "string",
						required: false,
					},
				},
			},
		});

	it("should extends fields", async () => {
		const { headers } = await signInWithTestUser();
		const res = await auth.api.getSession({
			headers,
		});
		expect(res?.user.newField).toBeDefined();
		expect(res?.user.nonRequiredFiled).toBeNull();
	});

	it("should require additional fields on signUp", async () => {
		await auth.api
			.signUpEmail({
				body: {
					email: "test@test.com",
					name: "test",
					password: "test-password",
					newField: "new-field",
					nonRequiredFiled: "non-required-field",
				},
			})
			.catch(() => {});

		const client = createAuthClient({
			plugins: [
				inferAdditionalFields({
					user: {
						newField: {
							type: "string",
						},
						nonRequiredFiled: {
							type: "string",
							defaultValue: "test",
						},
					},
				}),
			],
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
			},
		});
		const headers = new Headers();
		await client.signUp.email(
			{
				email: "test3@test.com",
				name: "test3",
				password: "test-password",
				newField: "new-field",
			},
			{
				onSuccess: sessionSetter(headers),
			},
		);
		const res = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(res.data?.user.newField).toBe("new-field");
	});

	it("should infer additional fields on update", async () => {
		const client = createAuthClient({
			plugins: [
				inferAdditionalFields({
					user: {
						newField: {
							type: "string",
						},
					},
				}),
			],
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
			},
		});
		const headers = new Headers();
		await client.signUp.email(
			{
				email: "test5@test.com",
				name: "test5",
				password: "test-password",
				newField: "new-field",
			},
			{
				onSuccess: sessionSetter(headers),
			},
		);
		await client.updateUser({
			name: "test",
			newField: "updated-field",
			fetchOptions: {
				headers,
			},
		});
		const session = await client.getSession({
			fetchOptions: {
				headers,
				throw: true,
			},
		});
		expect(session?.user.newField).toBe("updated-field");
	});

	it("should work with other plugins", async () => {
		const client = createAuthClient({
			plugins: [
				inferAdditionalFields({
					user: {
						newField: {
							type: "string",
							required: true,
						},
					},
				}),
				twoFactorClient(),
			],
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
			},
		});
		expectTypeOf(client.twoFactor).toMatchTypeOf<{}>();

		const headers = new Headers();
		await client.signUp.email(
			{
				email: "test4@test.com",
				name: "test4",
				password: "test-password",
				newField: "new-field",
			},
			{
				onSuccess: sessionSetter(headers),
			},
		);
		await client.updateUser(
			{
				name: "test",
				newField: "updated-field",
			},
			{
				headers,
			},
		);
	});;;;;

	it("should apply default values", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			databaseHooks: {
				session: {
					create: {
						before: async (session) => {
							return {
								data: {
									newField2: "new-field-2",
								},
							};
						},
					},
				},
			},
			session: {
				additionalFields: {
					newField: {
						type: "string",
						defaultValue: "default-value",
					},
					newField2: {
						type: "string",
					},
				},
			},
		});

		const { headers } = await signInWithTestUser();
		const res = await auth.api.getSession({
			headers,
		});
		expect(res?.session.newField).toBe("default-value");
	});
	it("should apply default values with secondary storage", async () => {
		const store = new Map<string, string>();
		const { auth, signInWithTestUser } = await getTestInstance({
			secondaryStorage: {
				set(key, value) {
					store.set(key, value);
				},
				get(key) {
					return store.get(key) || null;
				},
				getAndDelete(key) {
					const value = store.get(key) || null;
					store.delete(key);
					return value;
				},
				increment(key) {
					const count = Number(store.get(key) ?? 0) + 1;
					store.set(key, String(count));
					return count;
				},
				delete(key) {
					store.delete(key);
				},
			},
			databaseHooks: {
				session: {
					create: {
						before: async (session) => {
							return {
								data: {
									newField2: "new-field-2",
								},
							};
						},
					},
				},
			},
			session: {
				additionalFields: {
					newField: {
						type: "string",
						defaultValue: "default-value",
					},
					newField2: {
						type: "string",
					},
				},
			},
		});

		const { headers } = await signInWithTestUser();
		const res = await auth.api.getSession({
			headers,
		});
		expect(res?.session.newField).toBe("default-value");
	});
});
