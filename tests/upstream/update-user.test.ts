// Generated from pinned upstream source; do not edit assertions here.
import { describe, expect, it, vi } from "vitest";
import { createAuthClient } from "better-auth/client";
import { inferAdditionalFields } from "better-auth/client/plugins";
import { getTestInstance } from "../harness/test-instance.js";
import type { Account, Session } from "better-auth";

describe("updateUser", () => {
	it("should update the user's name", async () => {
		const { client, signInWithTestUser } = await getTestInstance();
		const { runWithUser } = await signInWithTestUser();
		await runWithUser(async () => {
			const updated = await client.updateUser({
				name: "newName",
				image: "https://example.com/image.jpg",
			});
			const sessionRes = await client.getSession();
			expect(updated.data?.status).toBe(true);
			expect(sessionRes.data?.user.name).toBe("newName");
		});
	});

	it("should unset image", async () => {
		const { client, signInWithTestUser } = await getTestInstance(undefined, {
			testUser: { image: "https://example.com/image.jpg" },
		});
		const { runWithUser } = await signInWithTestUser();
		await runWithUser(async () => {
			await client.updateUser({
				image: null,
			});
			const sessionRes = await client.getSession();
			expect(sessionRes.data?.user.image).toBeNull();
		});
	});

	it("should change email only after confirming both addresses", async () => {
		let confirmationToken = "";
		let verificationToken = "";
		const sendChangeEmailConfirmation = vi.fn(
			async ({ token }: { token: string }) => {
				confirmationToken = token;
			},
		);
		const sendVerificationEmail = vi.fn(
			async ({ token }: { token: string }) => {
				verificationToken = token;
			},
		);
		const { client, testUser, db, signInWithTestUser } = await getTestInstance({
			emailVerification: { sendVerificationEmail },
			user: {
				changeEmail: { enabled: true, sendChangeEmailConfirmation },
			},
		});
		const { runWithUser } = await signInWithTestUser();
		// Ensure user is verified to trigger the confirmation flow
		await db.update({
			model: "user",
			update: {
				emailVerified: true,
			},
			where: [
				{
					field: "email",
					value: testUser.email,
				},
			],
		});

		const newEmail = "new-email@email.com";
		await runWithUser(async () => {
			await client.changeEmail({
				newEmail,
			});
			const sessionRes = await client.getSession();
			// Should NOT update email yet
			expect(sessionRes.data?.user.email).not.toBe(newEmail);
			expect(sessionRes.data?.user.email).toBe(testUser.email);
		});
		expect(sendChangeEmailConfirmation).toHaveBeenCalledOnce();
		expect(sendChangeEmailConfirmation).toHaveBeenCalledWith(
			expect.objectContaining({
				user: expect.objectContaining({ email: testUser.email }),
				newEmail,
			}),
			expect.anything(),
		);
		expect(confirmationToken).not.toBe("");

		await runWithUser(async () => {
			const res = await client.verifyEmail({
				query: {
					token: confirmationToken,
				},
			});
			expect(res.data?.status).toBe(true);

			expect(sendVerificationEmail).toHaveBeenCalledOnce();
			expect(verificationToken).not.toBe("");

			// User email should STILL be old email
			const sessionRes = await client.getSession();
			expect(sessionRes.data?.user.email).toBe(testUser.email);

			// 2. Verify the new email token
			const res2 = await client.verifyEmail({
				query: {
					token: verificationToken,
				},
			});
			expect(res2.data?.status).toBe(true);

			// NOW user email should be updated
			const sessionRes2 = await client.getSession();
			expect(sessionRes2.data?.user.email).toBe(newEmail);
			expect(sessionRes2.data?.user.emailVerified).toBe(true);
		});
	});

	it("should update the user's password", async () => {
		const { client, testUser, signInWithTestUser } = await getTestInstance();
		const { runWithUser } = await signInWithTestUser();
		await runWithUser(async () => {
			const updated = await client.changePassword({
				newPassword: "newPassword",
				currentPassword: testUser.password,
				revokeOtherSessions: true,
			});
			expect(updated.data?.token).toEqual(expect.any(String));
		});
		const signInRes = await client.signIn.email({
			email: testUser.email,
			password: "newPassword",
		});
		expect(signInRes.data?.user).toBeDefined();
		const signInCurrentPassword = await client.signIn.email({
			email: testUser.email,
			password: testUser.password,
		});
		expect(signInCurrentPassword.data).toBeNull();
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/11597
	 */
	describe("with revokeOtherSessions, when a step fails", () => {
		async function setup(options?: Parameters<typeof getTestInstance>[0]) {
			const instance = await getTestInstance(options);
			const { headers } = await instance.signInWithTestUser();
			const ctx = await instance.auth.$context;
			const changePassword = () =>
				instance.client.changePassword({
					newPassword: "newPassword",
					currentPassword: instance.testUser.password,
					revokeOtherSessions: true,
					fetchOptions: { headers },
				});
			const signInWith = (password: string) =>
				instance.client.signIn.email({
					email: instance.testUser.email,
					password,
				});
			const getExistingSession = () =>
				instance.auth.api.getSession({ headers });
			return {
				...instance,
				ctx,
				changePassword,
				signInWith,
				getExistingSession,
			};
		}

		it("keeps the old password when revocation fails", async () => {
			const { ctx, testUser, changePassword, signInWith, getExistingSession } =
				await setup();
			vi.spyOn(ctx.internalAdapter, "deleteUserSessions").mockRejectedValue(
				new Error("session store unavailable"),
			);

			expect((await changePassword()).error?.status).toBe(500);
			expect((await signInWith("newPassword")).error?.status).toBe(401);
			expect((await signInWith(testUser.password)).data).not.toBeNull();
			expect(await getExistingSession()).not.toBeNull();
		});

		it("keeps existing sessions when the password write fails", async () => {
			const { ctx, testUser, changePassword, signInWith, getExistingSession } =
				await setup();
			vi.spyOn(ctx.internalAdapter, "updateAccount").mockRejectedValue(
				new Error("database unavailable"),
			);

			expect((await changePassword()).error?.status).toBe(500);
			expect(await getExistingSession()).not.toBeNull();
			expect((await signInWith(testUser.password)).data).not.toBeNull();
		});

		it("keeps the old password and sessions when the replacement session cannot be created", async () => {
			const { ctx, testUser, changePassword, signInWith, getExistingSession } =
				await setup();
			const createSession = vi
				.spyOn(ctx.internalAdapter, "createSession")
				.mockResolvedValue(null as never);

			expect((await changePassword()).error?.status).toBe(500);
			createSession.mockRestore();
			expect(await getExistingSession()).not.toBeNull();
			expect((await signInWith("newPassword")).error?.status).toBe(401);
			expect((await signInWith(testUser.password)).data).not.toBeNull();
		});

		it("keeps the old password when secondary storage cannot store the replacement session", async () => {
			const store = new Map<string, string>();
			let failWrites = false;
			const { testUser, changePassword, signInWith } = await setup({
				secondaryStorage: {
					set(key, value) {
						if (failWrites) throw new Error("storage unavailable");
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
			});
			failWrites = true;

			expect((await changePassword()).error?.status).toBe(500);
			failWrites = false;
			expect((await signInWith("newPassword")).error?.status).toBe(401);
			expect((await signInWith(testUser.password)).data).not.toBeNull();
		});

		it("does not cache the replacement session when the transaction fails", async () => {
			const store = new Map<string, string>();
			const { ctx, changePassword } = await setup({
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
				session: { storeSessionInDatabase: true },
			});
			const transaction = ctx.adapter.transaction;
			vi.spyOn(ctx.adapter, "transaction").mockImplementation(async (cb) => {
				await transaction(cb);
				throw new Error("commit failed");
			});
			const keysBefore = [...store.keys()].sort();

			expect((await changePassword()).error?.status).toBe(500);
			expect([...store.keys()].sort()).toEqual(keysBefore);
		});
	});

	it("should update account's updatedAt when changing password", async () => {
		const { client, sessionSetter, db } = await getTestInstance();
		const newHeaders = new Headers();
		await client.signUp.email({
			name: "Test User",
			email: "test-updated-at@email.com",
			password: "originalPassword",
			fetchOptions: {
				onSuccess: sessionSetter(newHeaders),
			},
		});

		// Get the initial account data
		const initialSession = await client.getSession({
			fetchOptions: {
				headers: newHeaders,
				throw: true,
			},
		});
		const userId = initialSession?.user.id;

		// Get initial account updatedAt
		const initialAccounts: Account[] = await db.findMany({
			model: "account",
			where: [
				{
					field: "userId",
					value: userId!,
				},
				{
					field: "providerId",
					value: "credential",
				},
			],
		});
		expect(initialAccounts.length).toBe(1);
		const initialUpdatedAt = initialAccounts[0]!.updatedAt;

		await new Promise((resolve) => setTimeout(resolve, 100));

		// Change password
		const updated = await client.changePassword({
			newPassword: "newPassword123",
			currentPassword: "originalPassword",
			fetchOptions: {
				headers: newHeaders,
			},
		});
		expect(updated.data).toBeDefined();

		// Get updated account data
		const updatedAccounts: Account[] = await db.findMany({
			model: "account",
			where: [
				{
					field: "userId",
					value: userId!,
				},
				{
					field: "providerId",
					value: "credential",
				},
			],
		});
		expect(updatedAccounts.length).toBe(1);
		const newUpdatedAt = updatedAccounts[0]!.updatedAt;

		// Verify updatedAt was refreshed
		expect(newUpdatedAt).not.toBe(initialUpdatedAt);
		expect(new Date(newUpdatedAt).getTime()).toBeGreaterThan(
			new Date(initialUpdatedAt).getTime(),
		);
	});

	it("should not update password if current password is wrong", async () => {
		const { client, sessionSetter } = await getTestInstance();
		const newHeaders = new Headers();
		await client.signUp.email({
			name: "name",
			email: "new-email-2@email.com",
			password: "password",
			fetchOptions: {
				onSuccess: sessionSetter(newHeaders),
			},
		});
		const res = await client.changePassword({
			newPassword: "newPassword",
			currentPassword: "wrongPassword",
			fetchOptions: {
				headers: newHeaders,
			},
		});
		expect(res.data).toBeNull();
		const signInAttempt = await client.signIn.email({
			email: "new-email-2@email.com",
			password: "newPassword",
		});
		expect(signInAttempt.data).toBeNull();
	});

	it("should revoke other sessions", async () => {
		const { client, testUser, sessionSetter, signInWithTestUser } =
			await getTestInstance();
		const { runWithUser } = await signInWithTestUser();
		await runWithUser(async (headers) => {
			const newHeaders = new Headers();
			await client.changePassword({
				newPassword: "newPassword",
				currentPassword: testUser.password,
				revokeOtherSessions: true,
				fetchOptions: {
					onSuccess: sessionSetter(newHeaders),
				},
			});
			const cookie = newHeaders.get("cookie");
			const oldCookie = headers.get("cookie");
			expect(cookie).not.toBe(oldCookie);
			// Try to use the old session - it should be revoked
			const sessionAttempt = await client.getSession();
			// The old session should still be invalidated even though we're using runWithClient
			// because revokeOtherSessions should have invalidated it on the server
			expect(sessionAttempt.data).toBeNull();
		});
	});

	/**
	 * @see https://github.com/better-auth/better-auth/pull/10390#discussion_r3585595438
	 */
	it("should preserve the replacement session in secondary storage", async () => {
		const store = new Map<string, string>();
		const {
			client: secondaryStorageClient,
			testUser: secondaryStorageUser,
			signInWithTestUser: signInWithSecondaryStorageUser,
			sessionSetter: setSecondaryStorageSession,
		} = await getTestInstance({
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
		});
		const { headers: previousSessionHeaders, user: signedInUser } =
			await signInWithSecondaryStorageUser();
		const replacementSessionHeaders = new Headers();

		const passwordChange = await secondaryStorageClient.changePassword({
			newPassword: "new-secondary-storage-password",
			currentPassword: secondaryStorageUser.password,
			revokeOtherSessions: true,
			fetchOptions: {
				headers: previousSessionHeaders,
				onSuccess: setSecondaryStorageSession(replacementSessionHeaders),
			},
		});

		expect(passwordChange.data?.token).toBeDefined();
		const previousSession = await secondaryStorageClient.getSession({
			fetchOptions: { headers: previousSessionHeaders },
		});
		expect(previousSession.data).toBeNull();

		const replacementSession = await secondaryStorageClient.getSession({
			fetchOptions: {
				headers: replacementSessionHeaders,
				throw: true,
			},
		});
		if (!replacementSession) {
			throw new Error("Replacement session was not created");
		}
		expect(replacementSession.user.id).toBe(signedInUser.id);
		expect(replacementSession.session.token).toBe(passwordChange.data?.token);

		const activeSessions = JSON.parse(
			store.get(`active-sessions-${signedInUser.id}`) ?? "[]",
		) as { token: string; expiresAt: number }[];
		expect(activeSessions).toEqual([
			expect.objectContaining({ token: passwordChange.data?.token }),
		]);
	});

	it("shouldn't pass defaults", async () => {
		const { client, sessionSetter, db } = await getTestInstance(
			{
				user: {
					additionalFields: {
						newField: {
							type: "string",
							defaultValue: "default",
						},
					},
				},
			},
			{
				disableTestUser: true,
			},
		);
		const headers = new Headers();
		await client.signUp.email({
			email: "new-email@emial.com",
			name: "name",
			password: "password",
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});

		const res = await db.update<{ newField: string }>({
			model: "user",
			update: {
				newField: "new",
			},
			where: [
				{
					field: "email",
					value: "new-email@emial.com",
				},
			],
		});
		expect(res?.newField).toBe("new");

		await client.updateUser({
			name: "newName",
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
		// @ts-expect-error
		expect(session?.user.newField).toBe("new");
	});

	it("should propagate updates across sessions when secondaryStorage is enabled", async () => {
		const store = new Map<string, string>();
		const { client: authClient, signInWithTestUser: signIn } =
			await getTestInstance({
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
			});

		const { headers: headers1 } = await signIn();
		const { headers: headers2 } = await signIn();

		await authClient.updateUser({
			name: "updatedName",
			fetchOptions: {
				headers: headers1,
			},
		});

		const secondSession = await authClient.getSession({
			fetchOptions: {
				headers: headers2,
				throw: true,
			},
		});
		expect(secondSession?.user.name).toBe("updatedName");

		const firstSession = await authClient.getSession({
			fetchOptions: {
				headers: headers1,
				throw: true,
			},
		});

		expect(firstSession?.user.name).toBe("updatedName");
	});

	it("should not write to secondary storage multiple times for the same session token during updateUser", async () => {
		const store = new Map<string, string>();
		const writeLog: { key: string; timestamp: number }[] = [];

		const { auth, signInWithTestUser: signIn } = await getTestInstance({
			secondaryStorage: {
				set(key, value) {
					writeLog.push({ key, timestamp: Date.now() });
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
		});

		// Clear any previous state
		store.clear();
		writeLog.length = 0;

		const { headers } = await signIn();

		// Get the session token that was just created
		const sessionTokens = Array.from(store.keys()).filter(
			(k) => !k.startsWith("active-sessions-"),
		);
		expect(sessionTokens.length).toBe(1);
		const sessionToken = sessionTokens[0];

		// Clear the write log before updateUser call
		writeLog.length = 0;

		// Use auth.api.updateUser directly to reproduce the issue
		await auth.api.updateUser({
			body: {
				name: "updatedName",
			},
			headers,
		});

		// Count how many times the same session token was written
		const sessionTokenWrites = writeLog.filter(
			(log) => log.key === sessionToken,
		);

		// Should only write once per session token, not multiple times
		expect(sessionTokenWrites.length).toBe(1);
	});

	it("should not allow updating user with additional fields that are input: false", async () => {
		const { auth, customFetchImpl, signInWithTestUser } = await getTestInstance(
			{
				user: {
					additionalFields: {
						newField: {
							type: "string",
							defaultValue: "default",
							input: false,
						},
					},
				},
			},
		);
		const client = createAuthClient({
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
			},
			plugins: [inferAdditionalFields<typeof auth>()],
		});
		const { headers } = await signInWithTestUser();
		const res = await client.updateUser(
			{
				//@ts-expect-error - newField is not available in the user input
				newField: "new",
			},
			{
				headers,
			},
		);
		expect(res.error).toBeDefined();
		expect(res.error?.message).toBe("newField is not allowed to be set");
	});
});
