// Generated from pinned upstream source; do not edit assertions here.
import type {BetterAuthPlugin} from '@better-auth/core';
import type {UserWithRole} from 'better-auth/plugins/admin';
import {BetterAuthError} from '@better-auth/core/error';
import {createAccessControl} from 'better-auth/plugins/access';
import {ADMIN_ERROR_CODES} from 'better-auth/client/plugins';
import {createAuthMiddleware} from 'better-auth/api';
import {getSessionFromCtx} from '../harness/session.js';
import type {GoogleProfile} from '@better-auth/core/social-providers';
import {exportJWK,generateKeyPair,SignJWT} from 'jose';
import {HttpResponse,http} from 'msw';
import {setupServer} from 'msw/node';
import {beforeAll,afterAll,afterEach,describe,it,expect,vi} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';
import {admin} from '../harness/plugins.js';
import {createAuthClient} from 'better-auth/client';
import {adminClient} from 'better-auth/client/plugins';
import {signJWT} from '../harness/crypto.js';
import {DEFAULT_SECRET} from '../harness/constants.js';

let testIdToken: string;

let handlers: ReturnType<typeof http.post>[];

const server = setupServer();

beforeAll(async () => {
	const data: GoogleProfile = {
		email: "user@email.com",
		email_verified: true,
		name: "First Last",
		picture: "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw",
		exp: 1234567890,
		sub: "1234567890",
		iat: 1234567890,
		aud: "test",
		azp: "test",
		nbf: 1234567890,
		iss: "test",
		locale: "en",
		jti: "test",
		given_name: "First",
		family_name: "Last",
	};
	testIdToken = await signJWT(data, DEFAULT_SECRET);

	handlers = [
		http.post("https://oauth2.googleapis.com/token", () => {
			return HttpResponse.json({
				access_token: "test",
				refresh_token: "test",
				id_token: testIdToken,
			});
		}),
	];

	server.listen({ onUnhandledRequest: "bypass" });
	server.use(...handlers);
});

afterEach(() => {
	server.resetHandlers();
	server.use(...handlers);
});

afterAll(() => server.close());

describe("Admin plugin", async () => {
	const {
		auth,
		signInWithTestUser,
		signInWithUser,
		cookieSetter,
		customFetchImpl,
	} = await getTestInstance(
		{
			trustedOrigins: ["https://frontend.example.com"],
			plugins: [
				admin({
					bannedUserMessage: async (user) =>
						user.banReason
							? `Banned: ${user.banReason}`
							: "Custom banned user message",
				}),
			],
			databaseHooks: {
				user: {
					create: {
						before: async (user) => ({
							data: {
								...user,
								emailVerified: true,
								...(user.name === "Admin" ? { role: "admin" } : {}),
							},
						}),
					},
				},
			},
		},
		{
			testUser: {
				name: "Admin",
			},
		},
	);
	const client = createAuthClient({
		fetchOptions: {
			customFetchImpl,
		},
		plugins: [adminClient()],
		baseURL: "http://localhost:3000",
	});

	const { headers: adminHeaders } = await signInWithTestUser();

	afterEach(() => {
		vi.useRealTimers();
	});

	let newUser: UserWithRole | undefined;
	const testNonAdminUser = {
		id: "123",
		email: "user@test.com",
		password: "password",
		name: "Test User",
	};
	const { data: testNonAdminUserRes } =
		await client.signUp.email(testNonAdminUser);
	testNonAdminUser.id = testNonAdminUserRes?.user.id || "";
	const { headers: userHeaders } = await signInWithUser(
		testNonAdminUser.email,
		testNonAdminUser.password,
	);

	it("should allow admin to get user", async () => {
		const res = await client.admin.getUser(
			{
				query: {
					id: testNonAdminUser.id,
				},
			},
			{
				headers: adminHeaders,
			},
		);

		expect(res.data?.email).toBe(testNonAdminUser.email);
	});

	it("should not allow non-admin to get user", async () => {
		const res = await client.admin.getUser(
			{
				query: {
					id: testNonAdminUser.id,
				},
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_GET_USER");
	});

	it("should allow admin to create users", async () => {
		const res = await client.admin.createUser(
			{
				name: "Test User",
				email: "user@email.com",
				password: "test",
				role: "user",
			},
			{
				headers: adminHeaders,
			},
		);
		newUser = res.data?.user;
		expect(newUser?.role).toBe("user");
	});

	it("should allow admin to create users without password", async () => {
		const res = await client.admin.createUser(
			{
				name: "Passwordless User",
				email: "passwordless@email.com",
				role: "user",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.user?.email).toBe("passwordless@email.com");
		expect(res.data?.user?.name).toBe("Passwordless User");
		expect(res.data?.user?.role).toBe("user");

		// User should not be able to sign in with password since no credential account exists
		const signInRes = await client.signIn.email({
			email: "passwordless@email.com",
			password: "anypassword",
		});
		expect(signInRes.error).toBeDefined();

		// Clean up
		await client.admin.removeUser(
			{
				userId: res.data?.user?.id || "",
			},
			{
				headers: adminHeaders,
			},
		);
	});

	it("should allow admin to create user with multiple roles", async () => {
		const res = await client.admin.createUser(
			{
				name: "Test User mr",
				email: "testmr@test.com",
				password: "test",
				role: ["user", "admin"],
			},
			{
				headers: adminHeaders,
			},
		);
		const result = await client.admin.listUsers({
			query: {
				filterField: "role",
				filterOperator: "contains",
				filterValue: "admin",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(result.data?.users.length).toBe(2);
		expect(res.data?.user.role).toBe("user,admin");
		await client.admin.removeUser(
			{
				userId: res.data?.user.id || "",
			},
			{
				headers: adminHeaders,
			},
		);
	});

	it("should not allow non-admin to create users", async () => {
		const res = await client.admin.createUser(
			{
				name: "Test User",
				email: "test2@test.com",
				password: "test",
				role: "user",
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});
	it("should allow admin to list users", async () => {
		const res = await client.admin.listUsers({
			query: {
				limit: 2,
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res.data?.users.length).toBe(2);
	});

	it("should list users with search query", async () => {
		const res = await client.admin.listUsers({
			query: {
				filterField: "role",
				filterOperator: "eq",
				filterValue: "admin",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res.data?.total).toBe(1);
	});

	it("should not allow non-admin to list users", async () => {
		const res = await client.admin.listUsers({
			query: {
				limit: 2,
			},
			fetchOptions: {
				headers: userHeaders,
			},
		});
		expect(res.error?.status).toBe(403);
	});

	it("should allow admin to count users", async () => {
		const res = await client.admin.listUsers({
			query: {
				limit: 2,
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res.data?.users.length).toBe(2);
		expect(res.data?.total).toBe(3);
	});

	it("should allow to sort users by name", async () => {
		const res = await client.admin.listUsers({
			query: {
				sortBy: "name",
				sortDirection: "desc",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});

		expect(res.data?.users[0]!.name).toBe("Test User");

		const res2 = await client.admin.listUsers({
			query: {
				sortBy: "name",
				sortDirection: "asc",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res2.data?.users[0]!.name).toBe("Admin");
	});

	it("should allow offset and limit", async () => {
		const res = await client.admin.listUsers({
			query: {
				limit: 1,
				offset: 1,
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res.data?.users.length).toBe(1);
		expect(res.data?.users[0]!.name).toBe("Test User");
	});

	it("should allow to search users by name", async () => {
		const res = await client.admin.listUsers({
			query: {
				searchValue: "Admin",
				searchField: "name",
				searchOperator: "contains",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res.data?.users.length).toBe(1);
	});

	it("should allow to filter users by role", async () => {
		await client.admin.listUsers({
			query: {
				filterValue: "admin",
				filterField: "role",
				filterOperator: "eq",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/7837
	 */
	it("should apply filter when filterValue is defined", async () => {
		// Create a dedicated user for this test to avoid invalidating shared sessions
		const { data: tempUser } = await client.signUp.email({
			email: "falsy-filter-test@test.com",
			password: "password",
			name: "Falsy Filter Test",
		});
		const tempUserId = tempUser!.user.id;

		const allUsers = await auth.api.listUsers({
			headers: adminHeaders,
			query: {},
		});
		const totalBefore = allUsers.total;
		expect(totalBefore).toBeGreaterThanOrEqual(2);

		// Ban the temp user so the dataset has both banned=true and banned=false
		await auth.api.banUser({
			headers: adminHeaders,
			body: { userId: tempUserId },
		});

		// Filter by banned = false should exclude the banned user
		const res = await auth.api.listUsers({
			headers: adminHeaders,
			query: {
				filterField: "banned",
				filterOperator: "eq",
				filterValue: false,
			},
		});

		expect(res.users.length).toBe(totalBefore - 1);
		expect(res.users.every((u) => u.banned === false)).toBe(true);
		expect(res.users.every((u) => u.id !== tempUserId)).toBe(true);

		// Cleanup: unban the user
		await auth.api.unbanUser({
			headers: adminHeaders,
			body: { userId: tempUserId },
		});
	});

	it("should filter users by id with ne operator", async () => {
		const allUsers = await client.admin.listUsers({
			query: {},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		const firstUserId = allUsers.data?.users[0]!.id;

		const res = await client.admin.listUsers({
			query: {
				filterValue: firstUserId,
				filterField: "id",
				filterOperator: "ne",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});

		expect(res.data?.users.length).toBe(allUsers.data!.total - 1);
		expect(res.data?.users.every((u) => u.id !== firstUserId)).toBe(true);
	});

	it("should filter users by _id with ne operator", async () => {
		const allUsers = await client.admin.listUsers({
			query: {},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		const firstUserId = allUsers.data?.users[0]!.id;

		const res = await client.admin.listUsers({
			query: {
				filterValue: firstUserId,
				filterField: "_id",
				filterOperator: "ne",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});

		expect(res.data?.users.length).toBe(allUsers.data!.total - 1);
		expect(res.data?.users.every((u) => u.id !== firstUserId)).toBe(true);
	});

	it("should allow to combine search and filter", async () => {
		const res = await client.admin.listUsers({
			query: {
				filterValue: "admin",
				filterField: "role",
				filterOperator: "eq",
				searchValue: "test",
				searchField: "email",
				searchOperator: "contains",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(res.data?.users.length).toBe(1);
		expect(res.data?.users[0]!.email).toBe("test@test.com");
	});

	it("should allow to set user role", async () => {
		const res = await client.admin.setRole(
			{
				userId: newUser?.id || "",
				role: "admin",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.user?.role).toBe("admin");
	});

	it("should allow to set multiple user roles", async () => {
		const createdUser = await client.admin.createUser(
			{
				name: "Test User mr",
				email: "testmr@test.com",
				password: "test",
				role: "user",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(createdUser.data?.user.role).toBe("user");
		const res = await client.admin.setRole(
			{
				userId: createdUser.data?.user.id || "",
				role: ["user", "admin"],
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.user?.role).toBe("user,admin");
		await client.admin.removeUser(
			{
				userId: createdUser.data?.user.id || "",
			},
			{
				headers: adminHeaders,
			},
		);
	});

	it("should not allow non-admin to set user role", async () => {
		const res = await client.admin.setRole(
			{
				userId: newUser?.id || "",
				role: "admin",
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});

	it("should allow to ban user", async () => {
		const res = await client.admin.banUser(
			{
				userId: newUser?.id || "",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.user?.banned).toBe(true);
	});

	it("should not allow non-admin to ban user", async () => {
		const res = await client.admin.banUser(
			{
				userId: newUser?.id || "",
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});

	it("should allow to ban user with reason and expiration", async () => {
		const res = await client.admin.banUser(
			{
				userId: newUser?.id || "",
				banReason: "Test reason",
				banExpiresIn: 60 * 60 * 24,
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.user?.banned).toBe(true);
		expect(res.data?.user?.banReason).toBe("Test reason");
		expect(res.data?.user?.banExpires).toBeDefined();
	});

	it("should not allow banned user to sign in", async () => {
		const res = await client.signIn.email({
			email: newUser?.email || "",
			password: "test",
		});
		expect(res.error?.code).toBe("BANNED_USER");
		expect(res.error?.status).toBe(403);
	});;;

	it("should resolve async banned user message", async () => {
		const res = await client.signIn.email({
			email: newUser?.email || "",
			password: "test",
		});
		expect(res.error?.message).toBe("Banned: Test reason");
	});

	it("should allow banned user to sign in if ban expired", async () => {
		vi.useFakeTimers();
		await vi.advanceTimersByTimeAsync(60 * 60 * 24 * 1000);
		const res = await client.signIn.email({
			email: newUser?.email || "",
			password: "test",
		});
		expect(res.data?.user).toBeDefined();
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/10820
	 */
	it("should clear the expired expiration when banning again without a duration", async () => {
		const created = await client.admin.createUser(
			{
				name: "Reban User",
				email: "reban@email.com",
				password: "test",
				role: "user",
			},
			{
				headers: adminHeaders,
			},
		);
		const userId = created.data?.user.id || "";
		await client.admin.banUser(
			{
				userId,
				banExpiresIn: 60 * 60,
			},
			{
				headers: adminHeaders,
			},
		);
		vi.useFakeTimers();
		await vi.advanceTimersByTimeAsync(60 * 60 * 2 * 1000);
		const res = await client.admin.banUser(
			{
				userId,
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.user?.banned).toBe(true);
		expect(res.data?.user?.banExpires).toBeNull();
		const signIn = await client.signIn.email({
			email: "reban@email.com",
			password: "test",
		});
		expect(signIn.error?.status).toBe(403);
	});

	it("should not create a session for a banned user outside an endpoint context", async () => {
		const created = await client.admin.createUser(
			{
				name: "Out Of Context User",
				email: "out-of-context@email.com",
				password: "test",
				role: "user",
			},
			{
				headers: adminHeaders,
			},
		);
		const userId = created.data?.user.id || "";
		await client.admin.banUser(
			{
				userId,
			},
			{
				headers: adminHeaders,
			},
		);
		const ctx = await auth.$context;
		await expect(
			ctx.internalAdapter.createSession(userId),
		).rejects.toMatchObject({
			body: {
				code: "BANNED_USER",
			},
		});
	});

	it("should allow to unban user", async () => {
		const res = await client.admin.unbanUser(
			{
				userId: newUser?.id || "",
			},
			{
				headers: adminHeaders,
			},
		);

		expect(res.data?.user?.banned).toBe(false);
		expect(res.data?.user?.banExpires).toBeNull();
		expect(res.data?.user?.banReason).toBeNull();
	});

	it("should not allow non-admin to unban user", async () => {
		const res = await client.admin.unbanUser(
			{
				userId: newUser?.id || "",
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});

	it("should allow admin to list user sessions", async () => {
		const res = await client.admin.listUserSessions(
			{
				userId: newUser?.id || "",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.sessions.length).toBe(1);
	});

	it("should return 404 from unbanUser when the target user does not exist", async () => {
		const res = await client.admin.unbanUser(
			{
				userId: "nonexistent-user-id",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(404);
		expect(res.error?.code).toBe("USER_NOT_FOUND");
	});

	it("should return 404 from banUser when the target user does not exist", async () => {
		const res = await client.admin.banUser(
			{
				userId: "nonexistent-user-id",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(404);
		expect(res.error?.code).toBe("USER_NOT_FOUND");
	});

	it("should return 404 from setRole when the target user does not exist", async () => {
		const res = await client.admin.setRole(
			{
				userId: "nonexistent-user-id",
				role: "admin",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(404);
		expect(res.error?.code).toBe("USER_NOT_FOUND");
	});

	it("should return 404 from admin.updateUser when the target user does not exist", async () => {
		const res = await client.admin.updateUser(
			{
				userId: "nonexistent-user-id",
				data: {
					name: "John Doe",
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(404);
		expect(res.error?.code).toBe("USER_NOT_FOUND");
	});

	it("should not allow non-admin to list user sessions", async () => {
		const res = await client.admin.listUserSessions(
			{
				userId: newUser?.id || "",
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});

	const data = {
		email: "impersonate@mail.com",
		password: "password",
		name: "Impersonate User",
	};

	const impersonateHeaders = new Headers();;;;;;;;;;

	it("should not allow non-admin to revoke user sessions", async () => {
		const res = await client.admin.revokeUserSessions(
			{ userId: newUser?.id || "" },
			{ headers: userHeaders },
		);
		expect(res.error?.status).toBe(403);
	});

	it("should allow admin to revoke user sessions", async () => {
		const res = await client.admin.revokeUserSessions(
			{ userId: newUser?.id || "" },
			{ headers: adminHeaders },
		);
		expect(res.data?.success).toBe(true);
		const sessions2 = await client.admin.listUserSessions(
			{ userId: newUser?.id || "" },
			{ headers: adminHeaders },
		);
		expect(sessions2.data?.sessions.length).toBe(0);
	});

	it("should list with me", async () => {
		const response = await client.admin.listUsers({
			query: {
				sortBy: "createdAt",
				sortDirection: "desc",
				filterField: "role",
				filterOperator: "ne",
				filterValue: "user",
			},
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		expect(response.data?.users.length).toBeGreaterThanOrEqual(2);
		const roles = response.data?.users.map((d) => d.role);
		expect(roles).not.toContain("user");
	});

	it("should allow admin to set user password", async () => {
		const res = await client.admin.setUserPassword(
			{
				userId: newUser?.id || "",
				newPassword: "newPassword",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.status).toBe(true);
		const res2 = await client.signIn.email({
			email: newUser?.email || "",
			password: "newPassword",
		});
		expect(res2.data?.user).toBeDefined();
	});
	it("should not allow admin to set user password with empty userId", async () => {
		const res = await client.admin.setUserPassword(
			{
				userId: "",
				newPassword: "newPassword",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
	});

	it("should not allow admin to set user password with empty new password", async () => {
		const res = await client.admin.setUserPassword(
			{
				userId: newUser?.id || "",
				newPassword: "",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
	});

	it("should not allow admin to set user password with a short new password", async () => {
		const res = await client.admin.setUserPassword(
			{
				userId: newUser!.id,
				newPassword: "1234567",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe("PASSWORD_TOO_SHORT");
		expect(res.error?.message).toBe("Password too short");
	});

	it("should not allow admin to set user password with a long new password", async () => {
		const longNewPassword = Array(129).fill("a").join("");
		const res = await client.admin.setUserPassword(
			{
				userId: newUser!.id,
				newPassword: longNewPassword,
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe("PASSWORD_TOO_LONG");
		expect(res.error?.message).toBe("Password too long");
	});

	it("should not allow non-admin to set user password", async () => {
		const res = await client.admin.setUserPassword(
			{
				userId: newUser?.id || "",
				newPassword: "newPassword",
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/3553
	 */
	it("should create a credential account when setting password for a user without one", async () => {
		const created = await client.admin.createUser(
			{
				name: "No Credential User",
				email: "no-credential@email.com",
				role: "user",
			},
			{
				headers: adminHeaders,
			},
		);
		const userId = created.data?.user?.id || "";
		expect(userId).not.toBe("");

		const preSignIn = await client.signIn.email({
			email: "no-credential@email.com",
			password: "newPassword",
		});
		expect(preSignIn.error).toBeDefined();

		const setRes = await client.admin.setUserPassword(
			{
				userId,
				newPassword: "newPassword",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(setRes.data?.status).toBe(true);

		const postSignIn = await client.signIn.email({
			email: "no-credential@email.com",
			password: "newPassword",
		});
		expect(postSignIn.error).toBeNull();
		expect(postSignIn.data?.user.id).toBe(userId);
		await expect(
			(await auth.$context).internalAdapter.findCredentialAccount(userId),
		).resolves.toMatchObject({
			userId,
			providerId: "credential",
			accountId: userId,
		});

		await client.admin.removeUser({ userId }, { headers: adminHeaders });
	});

	it("should return USER_NOT_FOUND when setting password for a non-existent user", async () => {
		const res = await client.admin.setUserPassword(
			{
				userId: "non-existent-user-id",
				newPassword: "newPassword",
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(404);
		expect(res.error?.code).toBe("USER_NOT_FOUND");
	});

	it("should allow admin to delete user", async () => {
		const res = await client.admin.removeUser(
			{
				userId: newUser?.id || "",
			},
			{
				headers: adminHeaders,
			},
		);

		expect(res.data?.success).toBe(true);
	});

	it("should not allow non-admin to delete user", async () => {
		const res = await client.admin.removeUser(
			{ userId: newUser?.id || "" },
			{ headers: userHeaders },
		);
		expect(res.error?.status).toBe(403);
	});

	it("should allow creating users from server", async () => {
		const res = await auth.api.createUser({
			body: {
				email: "test2@test.com",
				password: "password",
				name: "Test User",
			},
		});
		expect(res.user).toMatchObject({
			email: "test2@test.com",
			name: "Test User",
			role: "user",
		});
	});

	it("should allow admin to update user", async () => {
		const res = await client.admin.updateUser(
			{
				userId: testNonAdminUser.id,
				data: {
					name: "Updated Name",
					customField: "custom value",
					role: ["member", "user"],
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.name).toBe("Updated Name");
		expect(res.data?.role).toBe("member,user");
	});

	it("should not allow non-admin to update user", async () => {
		const res = await client.admin.updateUser(
			{
				userId: testNonAdminUser.id,
				data: {
					name: "Unauthorized Update",
				},
			},
			{
				headers: userHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS");
	});

	it("should not allow updating password through update-user", async () => {
		const res = await client.admin.updateUser(
			{
				userId: testNonAdminUser.id,
				data: {
					password: "new-password",
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe("PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER");
	});

	it("should not allow updating the user id through update-user", async () => {
		const res = await client.admin.updateUser(
			{
				userId: testNonAdminUser.id,
				data: {
					id: "new-user-id",
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe("USER_ID_CANNOT_BE_UPDATED");

		const ctx = await auth.$context;
		const user = await ctx.internalAdapter.findUserById(testNonAdminUser.id);
		expect(user?.id).toBe(testNonAdminUser.id);
	});

	it("should revoke sessions when banning a user via update-user", async () => {
		const targetHeaders = new Headers();
		const { data: target } = await client.signUp.email(
			{
				email: "ban-via-update@test.com",
				password: "password",
				name: "Ban Via Update",
			},
			{
				onSuccess: cookieSetter(targetHeaders),
			},
		);
		const targetId = target?.user.id || "";

		const res = await client.admin.updateUser(
			{
				userId: targetId,
				data: {
					banned: true,
					banReason: "Violation",
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.banned).toBe(true);

		const sessions = await client.admin.listUserSessions(
			{
				userId: targetId,
			},
			{
				headers: adminHeaders,
			},
		);
		expect(sessions.data?.sessions.length).toBe(0);
	});

	it("should not allow admins to ban themselves via update-user", async () => {
		const { data: session } = await client.getSession({
			fetchOptions: {
				headers: adminHeaders,
			},
		});
		const res = await client.admin.updateUser(
			{
				userId: session?.user.id || "",
				data: {
					banned: true,
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe("YOU_CANNOT_BAN_YOURSELF");
	});

	it("should reject email updates that collide with another user", async () => {
		const res = await client.admin.updateUser(
			{
				userId: testNonAdminUser.id,
				data: {
					email: "ban-via-update@test.com",
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
	});

	it("should allow admin to update user email and normalize it", async () => {
		const res = await client.admin.updateUser(
			{
				userId: testNonAdminUser.id,
				data: {
					email: "Updated-Email@Test.com",
					emailVerified: false,
				},
			},
			{
				headers: adminHeaders,
			},
		);
		expect(res.data?.email).toBe("updated-email@test.com");
		expect(res.data?.emailVerified).toBe(false);
	});
});

describe("access control", async () => {
	const ac = createAccessControl({
		user: [
			"create",
			"read",
			"update",
			"delete",
			"list",
			"bulk-delete",
			"set-role",
		],
		order: ["create", "read", "update", "delete", "update-many"],
	});

	const adminAc = ac.newRole({
		user: ["create", "read", "update", "delete", "list", "set-role"],
		order: ["create", "read", "update", "delete"],
	});
	const userAc = ac.newRole({
		user: ["read"],
		order: ["read"],
	});
	const supportAc = ac.newRole({
		user: ["update"],
		order: ["update"],
	});
	const creatorAc = ac.newRole({
		user: ["create"],
		order: [],
	});

	const { signInWithTestUser, cookieSetter, auth, customFetchImpl } =
		await getTestInstance(
			{
				plugins: [
					admin({
						ac,
						roles: {
							admin: adminAc,
							user: userAc,
							support: supportAc,
							creator: creatorAc,
						},
					}),
				],
				databaseHooks: {
					user: {
						create: {
							before: async (user) => {
								if (user.name === "Admin") {
									return {
										data: {
											...user,
											role: "admin",
										},
									};
								}
								if (user.name === "Support") {
									return {
										data: {
											...user,
											role: "support",
										},
									};
								}
								if (user.name === "Creator") {
									return {
										data: {
											...user,
											role: "creator",
										},
									};
								}
							},
						},
					},
				},
			},
			{
				testUser: {
					name: "Admin",
				},
			},
		);

	const client = createAuthClient({
		plugins: [
			adminClient({
				ac,
				roles: {
					admin: adminAc,
					user: userAc,
					support: supportAc,
					creator: creatorAc,
				},
			}),
		],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	const { headers, user } = await signInWithTestUser();

	it("should not allow role updates via update-user without user:set-role", async () => {
		const supportHeaders = new Headers();
		const { data: supportSignUp } = await client.signUp.email(
			{
				email: "support@test.com",
				password: "password",
				name: "Support",
			},
			{
				onSuccess: cookieSetter(supportHeaders),
			},
		);
		const supportUserId = supportSignUp?.user.id || "";

		// Non-sensitive updates should still be allowed with `user:update`
		const ok = await client.admin.updateUser(
			{
				userId: supportUserId,
				data: {
					name: "Support Updated",
				},
			},
			{
				headers: supportHeaders,
			},
		);
		expect(ok.data?.name).toBe("Support Updated");

		// But attempting to update `role` must be rejected without `user:set-role`.
		const res = await client.admin.updateUser(
			{
				userId: supportUserId,
				data: {
					role: "admin",
				},
			},
			{
				headers: supportHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
	});

	it("should reject non-existent roles via update-user", async () => {
		const { data: targetUserRes } = await client.signUp.email(
			{
				email: "role-target@test.com",
				password: "password",
				name: "Role Target",
			},
			{
				onSuccess: cookieSetter(new Headers()),
			},
		);
		const targetUserId = targetUserRes?.user.id || "";

		const res = await client.admin.updateUser(
			{
				userId: targetUserId,
				data: {
					role: "non-existent-role",
				},
			},
			{
				headers,
			},
		);
		expect(res.error?.status).toBe(400);
	});

	it("should allow role updates via update-user for valid roles with user:set-role", async () => {
		const { data: targetUserRes } = await client.signUp.email(
			{
				email: "role-valid-target@test.com",
				password: "password",
				name: "Role Valid Target",
			},
			{
				onSuccess: cookieSetter(new Headers()),
			},
		);
		const targetUserId = targetUserRes?.user.id || "";

		const res = await client.admin.updateUser(
			{
				userId: targetUserId,
				data: {
					role: "support",
				},
			},
			{
				headers,
			},
		);
		expect(res.error).toBeNull();
		expect(res.data?.role).toBe("support");
	});

	it("should require user:set-role to assign roles via create-user", async () => {
		const creatorHeaders = new Headers();
		await client.signUp.email(
			{
				email: "creator@test.com",
				password: "password",
				name: "Creator",
			},
			{
				onSuccess: cookieSetter(creatorHeaders),
			},
		);

		// `user:create` alone is enough when no role is requested
		const ok = await client.admin.createUser(
			{
				name: "Created User",
				email: "created-by-creator@test.com",
				password: "password",
			},
			{
				headers: creatorHeaders,
			},
		);
		expect(ok.data?.user.role).toBe("user");

		// but requesting a role requires `user:set-role`
		const res = await client.admin.createUser(
			{
				name: "Role Requested User",
				email: "role-requested@test.com",
				password: "password",
				role: "admin",
			},
			{
				headers: creatorHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE");

		// `data.role` must go through the same check
		const res2 = await client.admin.createUser(
			{
				name: "Role Requested User",
				email: "role-requested2@test.com",
				password: "password",
				data: {
					role: "admin",
				},
			},
			{
				headers: creatorHeaders,
			},
		);
		expect(res2.error?.status).toBe(403);
		expect(res2.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE");
	});

	it("should reject non-existent roles via create-user", async () => {
		const res = await client.admin.createUser(
			{
				name: "Bad Role User",
				email: "bad-role@test.com",
				password: "password",
				data: {
					role: "non-existent-role",
				},
			},
			{
				headers,
			},
		);
		expect(res.error?.status).toBe(400);
	});

	it("should apply a validated data.role for callers with user:set-role", async () => {
		const res = await client.admin.createUser(
			{
				name: "Data Role User",
				email: "data-role@test.com",
				password: "password",
				data: {
					role: "support",
				},
			},
			{
				headers,
			},
		);
		expect(res.data?.user.role).toBe("support");
	});

	it("should require user:ban to update ban fields via update-user", async () => {
		const supportHeaders = new Headers();
		const { data: supportSignUp } = await client.signUp.email(
			{
				email: "support-ban@test.com",
				password: "password",
				name: "Support",
			},
			{
				onSuccess: cookieSetter(supportHeaders),
			},
		);
		const targetUserId = supportSignUp?.user.id || "";

		const res = await client.admin.updateUser(
			{
				userId: targetUserId,
				data: {
					banned: true,
					banReason: "self-served ban",
				},
			},
			{
				headers: supportHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_BAN_USERS");
	});

	it("should require user:set-email to update email fields via update-user", async () => {
		const supportHeaders = new Headers();
		const { data: supportSignUp } = await client.signUp.email(
			{
				email: "support-email@test.com",
				password: "password",
				name: "Support",
			},
			{
				onSuccess: cookieSetter(supportHeaders),
			},
		);
		const targetUserId = supportSignUp?.user.id || "";

		const res = await client.admin.updateUser(
			{
				userId: targetUserId,
				data: {
					email: "new-address@example.com",
					emailVerified: true,
				},
			},
			{
				headers: supportHeaders,
			},
		);
		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL");
	});;

	it("should validate using userId", async () => {
		const canCreateUser = await auth.api.userHasPermission({
			body: {
				userId: user.id,
				permissions: {
					user: ["create"],
				},
			},
		});
		expect(canCreateUser.success).toBe(true);

		const canCreateUserAndCreateOrder = await auth.api.userHasPermission({
			body: {
				userId: user.id,
				permissions: {
					user: ["create"],
					order: ["create"],
				},
			},
		});
		expect(canCreateUserAndCreateOrder.success).toBe(true);

		const canUpdateManyOrder = await auth.api.userHasPermission({
			body: {
				userId: user.id,
				permissions: {
					order: ["update-many"],
				},
			},
		});
		expect(canUpdateManyOrder.success).toBe(false);

		const canUpdateManyOrderAndBulkDeleteUser =
			await auth.api.userHasPermission({
				body: {
					userId: user.id,
					permissions: {
						user: ["bulk-delete"],
						order: ["update-many"],
					},
				},
			});
		expect(canUpdateManyOrderAndBulkDeleteUser.success).toBe(false);
	});

	it("should validate using role", async () => {
		const canCreateUser = await auth.api.userHasPermission({
			body: {
				role: "admin",
				permissions: {
					user: ["create"],
				},
			},
		});
		expect(canCreateUser.success).toBe(true);

		const canCreateUserAndCreateOrder = await auth.api.userHasPermission({
			body: {
				role: "admin",
				permissions: {
					user: ["create"],
					order: ["create"],
				},
			},
		});
		expect(canCreateUserAndCreateOrder.success).toBe(true);

		const canUpdateOrder = await auth.api.userHasPermission({
			body: {
				role: "user",
				permissions: {
					order: ["update"],
				},
			},
		});
		expect(canUpdateOrder.success).toBe(false);

		const canUpdateOrderAndUpdateUser = await auth.api.userHasPermission({
			body: {
				role: "user",
				permissions: {
					order: ["update"],
					user: ["update"],
				},
			},
		});
		expect(canUpdateOrderAndUpdateUser.success).toBe(false);
	});

	it("should prioritize role over userId when both are provided", async () => {
		const testUser = await client.signUp.email({
			email: "rolepriority@test.com",
			password: "password",
			name: "Role Priority Test User",
		});
		const userId = testUser.data?.user.id;

		const checkWithAdminRole = await auth.api.userHasPermission({
			body: {
				userId: userId, // non-admin user ID
				role: "admin", // admin role
				permissions: {
					user: ["create"],
				},
			},
		});
		expect(checkWithAdminRole.success).toBe(true);

		const checkWithUserRole = await auth.api.userHasPermission({
			body: {
				userId: userId, // non-admin user ID
				role: "user", // user role
				permissions: {
					user: ["create"],
				},
			},
		});
		expect(checkWithUserRole.success).toBe(false);
	});

	it("should check permissions correctly for banned user with role provided", async () => {
		const bannedUser = await client.signUp.email({
			email: "bannedwithRole@test.com",
			password: "password",
			name: "Banned Role Test User",
		});
		const bannedUserId = bannedUser.data?.user.id;

		await client.admin.banUser(
			{
				userId: bannedUserId || "",
				banReason: "Testing role priority",
			},
			{
				headers: headers,
			},
		);

		const checkWithRole = await auth.api.userHasPermission({
			body: {
				userId: bannedUserId, // banned user ID
				role: "admin", // admin role
				permissions: {
					user: ["create"],
				},
			},
		});
		expect(checkWithRole.success).toBe(true);

		const checkWithoutRole = await auth.api.userHasPermission({
			body: {
				userId: bannedUserId, // banned user ID only
				permissions: {
					user: ["create"],
				},
			},
		});
		expect(checkWithoutRole.success).toBe(false); // User doesn't have admin permissions

		await client.admin.unbanUser(
			{
				userId: bannedUserId || "",
			},
			{
				headers: headers,
			},
		);
	});

	it("shouldn't allow to list users", async () => {
		const { headers } = await signInWithTestUser();
		const adminRes = await client.admin.listUsers({
			query: {
				limit: 10,
			},
			fetchOptions: {
				headers,
			},
		});
		// The exact count may vary based on users created in previous tests
		const adminCount = adminRes.data?.users.length || 0;
		expect(adminCount).toBeGreaterThan(0); // Should have at least the admin user

		const userHeaders = new Headers();
		await client.signUp.email(
			{
				email: "test2@test.com",
				password: "password",
				name: "Test User",
			},
			{
				onSuccess: cookieSetter(userHeaders),
			},
		);
		const userRes = await client.admin.listUsers({
			query: {
				limit: 2,
			},
			fetchOptions: {
				headers: userHeaders,
			},
		});
		expect(userRes.error?.status).toBe(403);
	});

	it("should not allow to set multiple non existent user role", async () => {
		const createdUser = await client.admin.createUser(
			{
				name: "Test User mr",
				email: "testmr@test.com",
				password: "test",
				role: ["user"],
			},
			{
				headers: headers,
			},
		);
		expect(createdUser.data?.user.role).toBe("user");
		const res = await client.admin.setRole(
			{
				userId: createdUser.data?.user.id || "",
				role: ["user", "non-user"] as any[],
			},
			{ headers: headers },
		);
		expect(res.error).toBeDefined();
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe(
			ADMIN_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE.code,
		);
		await client.admin.removeUser(
			{ userId: createdUser.data?.user.id || "" },
			{ headers: headers },
		);
	});

	it("should not allow to set non existent user role", async () => {
		const createdUser = await client.admin.createUser(
			{
				name: "Test User mr",
				email: "testmr@test.com",
				password: "test",
				role: "user",
			},
			{
				headers: headers,
			},
		);
		expect(createdUser.data?.user.role).toBe("user");
		const res = await client.admin.setRole(
			{
				userId: createdUser.data?.user.id || "",
				role: "non-user" as any,
			},
			{ headers: headers },
		);
		expect(res.error).toBeDefined();
		expect(res.error?.status).toBe(400);
		expect(res.error?.code).toBe(
			ADMIN_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE.code,
		);
		await client.admin.removeUser(
			{ userId: createdUser.data?.user.id || "" },
			{ headers: headers },
		);
	});;;
});

describe("Admin plugin id-token sign-in", async () => {
	const googleKeyPair = await generateKeyPair("RS256");
	const googleJwk = await exportJWK(googleKeyPair.publicKey);
	const googleKid = "test-admin-google-kid";
	googleJwk.kid = googleKid;
	googleJwk.alg = "RS256";
	googleJwk.use = "sig";

	const clientId = "admin-idtoken-client.googleusercontent.com";

	const signIdToken = (email: string) =>
		new SignJWT({
			email,
			email_verified: true,
			name: "Banned ID Token User",
			sub: "banned-google-sub",
		})
			.setProtectedHeader({ alg: "RS256", kid: googleKid })
			.setIssuedAt()
			.setIssuer("https://accounts.google.com")
			.setAudience(clientId)
			.setExpirationTime("1h")
			.sign(googleKeyPair.privateKey);

	beforeAll(() => {
		server.use(
			http.get("https://www.googleapis.com/oauth2/v3/certs", () =>
				HttpResponse.json({ keys: [googleJwk] }),
			),
		);
	});

	it("should return BANNED_USER 403 JSON for id-token sign-in by banned user", async () => {
		const { client } = await getTestInstance(
			{
				plugins: [admin({ bannedUserMessage: "Custom banned user message" })],
				socialProviders: {
					google: { clientId, clientSecret: "test-secret" },
				},
				databaseHooks: {
					user: {
						create: {
							before: async (user) => ({
								data: { ...user, emailVerified: true, banned: true },
							}),
						},
					},
				},
			},
			{ disableTestUser: true },
		);

		const idToken = await signIdToken("banned-idtoken@test.com");
		const res = await client.signIn.social({
			provider: "google",
			idToken: { token: idToken },
		});

		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("BANNED_USER");
		expect(res.error?.message).toBe("Custom banned user message");
	});
});

describe("admin createUser validateUserInfo provisioning gate", async () => {
	const { signInWithTestUser, customFetchImpl } = await getTestInstance(
		{
			user: {
				validateUserInfo({ user, source }) {
					if (source.method !== "admin") {
						return;
					}
					expect(source.action).toBe("create-user");
					if ((user.email as string).endsWith("@blocked.com")) {
						return {
							error: "admin_create_blocked",
							errorDescription: "This email domain is not allowed",
						};
					}
				},
			},
			plugins: [admin()],
			databaseHooks: {
				user: {
					create: {
						before: async (user) => ({
							data: {
								...user,
								...(user.name === "Admin" ? { role: "admin" } : {}),
							},
						}),
					},
				},
			},
		},
		{
			testUser: {
				name: "Admin",
			},
		},
	);
	const client = createAuthClient({
		fetchOptions: {
			customFetchImpl,
		},
		plugins: [adminClient()],
		baseURL: "http://localhost:3000",
	});
	const { headers: adminHeaders } = await signInWithTestUser();

	it("rejects an admin-created user when validateUserInfo returns error", async () => {
		const res = await client.admin.createUser(
			{
				name: "Blocked User",
				email: "new@blocked.com",
				password: "password",
				role: "user",
			},
			{ headers: adminHeaders },
		);
		expect(res.error?.status).toBe(403);
		expect(res.error?.code).toBe("admin_create_blocked");
	});

	it("allows an admin-created user that passes validation", async () => {
		const res = await client.admin.createUser(
			{
				name: "Allowed User",
				email: "ok@allowed.com",
				password: "password",
				role: "user",
			},
			{ headers: adminHeaders },
		);
		expect(res.data?.user.email).toBe("ok@allowed.com");
	});
});

describe("admin create-user password length", async () => {
	const hash = vi.fn(async (password: string) => `hashed:${password}`);
	const verify = vi.fn(
		async ({ hash, password }: { hash: string; password: string }) =>
			hash === `hashed:${password}`,
	);
	const { auth } = await getTestInstance({
		emailAndPassword: {
			enabled: true,
			password: { hash, verify },
		},
		plugins: [admin()],
	});

	it("should reject a password longer than maxPasswordLength before hashing", async () => {
		hash.mockClear();

		await expect(
			auth.api.createUser({
				body: {
					email: "long-password@test.com",
					password: "x".repeat(129),
					name: "Long Password",
				},
			}),
		).rejects.toMatchObject({
			status: "BAD_REQUEST",
			body: { code: "PASSWORD_TOO_LONG" },
		});

		expect(hash).not.toHaveBeenCalled();
	});
});
