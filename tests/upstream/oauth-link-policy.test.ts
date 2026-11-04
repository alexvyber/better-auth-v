// Generated from pinned upstream source; do not edit assertions here.
import type { GoogleProfile } from "@better-auth/core/social-providers";
import type { User } from "better-auth";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { signJWT } from "../harness/crypto.js";
import { getTestInstance } from "../harness/test-instance.js";
import { DEFAULT_SECRET } from "../harness/constants.js";

let mockEmail = "";

let mockEmailVerified = true;

const server = setupServer();

beforeAll(() => {
	server.listen({ onUnhandledRequest: "bypass" });
});

afterEach(() => {
	server.resetHandlers();
});

afterAll(() => server.close());

describe("oauth2 - email verification on link", async () => {
	const { auth, client, cookieSetter } = await getTestInstance({
		socialProviders: {
			google: {
				clientId: "test",
				clientSecret: "test",
				enabled: true,
			},
		},
		emailAndPassword: {
			enabled: true,
			requireEmailVerification: true,
		},
		account: {
			accountLinking: {
				enabled: true,
				trustedProviders: ["google"],
			},
		},
	});

	const ctx = await auth.$context;

	async function linkGoogleAccount(): Promise<{ redirectLocation: string }> {
		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile: GoogleProfile = {
					email: mockEmail,
					email_verified: mockEmailVerified,
					name: "Test User",
					picture: "https://example.com/photo.jpg",
					exp: 1234567890,
					sub: "google_oauth_sub_1234567890",
					iat: 1234567890,
					aud: "test",
					azp: "test",
					nbf: 1234567890,
					iss: "test",
					locale: "en",
					jti: "test",
					given_name: "Test",
					family_name: "User",
				};
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_access_token",
					refresh_token: "test_refresh_token",
					id_token: idToken,
				});
			}),
		);

		const oAuthHeaders = new Headers();
		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/",
			fetchOptions: {
				onSuccess: cookieSetter(oAuthHeaders),
			},
		});
		const state = new URL(signInRes.data!.url!).searchParams.get("state") || "";
		let redirectLocation = "";
		await client.$fetch("/callback/google", {
			query: { state, code: "test_code" },
			method: "GET",
			headers: oAuthHeaders,
			onError(context) {
				expect(context.response.status).toBe(302);
				redirectLocation = context.response.headers.get("location") || "";
			},
		});
		return { redirectLocation };
	}

	/**
	 * @see https://github.com/better-auth/better-auth/security/advisories/GHSA-g38m-r43w-p2q7
	 */
	it("should reject implicit link when local user is unverified, even if provider email is verified", async () => {
		const testEmail = "unverified-local@example.com";

		// Create user with unverified email
		mockEmail = testEmail;
		mockEmailVerified = false;

		const signUpRes = await client.signUp.email({
			email: testEmail,
			password: "password123",
			name: "Test User",
		});

		const userId = signUpRes.data!.user.id;

		// Initial state: local row is unverified
		let user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(false);

		// Attempt to link with Google account that has verified email
		mockEmailVerified = true;
		const { redirectLocation } = await linkGoogleAccount();

		// Callback redirects with the documented account_not_linked error code so
		// the test can't pass on an unrelated redirect (e.g. server-side failure).
		expect(redirectLocation).toContain("error=account_not_linked");

		// Link is rejected: no Google account row, local emailVerified untouched
		const accounts = await ctx.adapter.findMany<{
			providerId: string;
		}>({
			model: "account",
			where: [{ field: "userId", value: userId }],
		});
		const googleAccount = accounts.find((a) => a.providerId === "google");
		expect(googleAccount).toBeUndefined();

		user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(false);
	});

	it("should link account and preserve emailVerified when local user is already verified", async () => {
		const testEmail = "verified-local@example.com";

		mockEmail = testEmail;
		mockEmailVerified = true;

		const signUpRes = await client.signUp.email({
			email: testEmail,
			password: "password123",
			name: "Test User",
		});

		const userId = signUpRes.data!.user.id;

		// Pre-verify the local user (e.g. via email-otp or verification token)
		await ctx.adapter.update({
			model: "user",
			where: [{ field: "id", value: userId }],
			update: { emailVerified: true },
		});

		await linkGoogleAccount();

		const user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(true);

		const accounts = await ctx.adapter.findMany<{
			providerId: string;
		}>({
			model: "account",
			where: [{ field: "userId", value: userId }],
		});
		expect(accounts.find((a) => a.providerId === "google")).toBeDefined();
	});

	it("should not update emailVerified when provider reports unverified", async () => {
		const testEmail = "unverified@example.com";

		// Create user with unverified email
		mockEmail = testEmail;
		mockEmailVerified = false;

		const signUpRes = await client.signUp.email({
			email: testEmail,
			password: "password123",
			name: "Unverified User",
		});

		const userId = signUpRes.data!.user.id;

		// Link Google account with unverified email from provider
		await linkGoogleAccount();

		// Verify email remains unverified
		const user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(false);
	});

	it("should not update emailVerified when email addresses don't match", async () => {
		const userEmail = "user@example.com";
		const googleEmail = "different@gmail.com";

		// Create user with one email
		mockEmail = userEmail;
		mockEmailVerified = false;

		const signUpRes = await client.signUp.email({
			email: userEmail,
			password: "password123",
			name: "Test User",
		});

		const userId = signUpRes.data!.user.id;

		// Verify initial state
		let user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(false);

		// Try to link with Google using different email (verified)
		mockEmail = googleEmail;
		mockEmailVerified = true;
		await linkGoogleAccount();

		// Verify emailVerified remains false (emails don't match)
		user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(false);
	});

	it("should handle already verified emails gracefully", async () => {
		const testEmail = "already-verified@example.com";

		// Create user with verified email
		mockEmail = testEmail;
		mockEmailVerified = true;

		const signUpRes = await client.signUp.email({
			email: testEmail,
			password: "password123",
			name: "Verified User",
		});

		const userId = signUpRes.data!.user.id;

		// Manually set emailVerified to true
		await ctx.adapter.update({
			model: "user",
			where: [{ field: "id", value: userId }],
			update: { emailVerified: true },
		});

		// Link with Google account (also verified)
		await linkGoogleAccount();

		// Verify email remains verified
		const user = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(user?.emailVerified).toBe(true);
	});
});

describe("oauth2 - account linking without trustedProviders", async () => {
	const { auth, client, cookieSetter } = await getTestInstance({
		socialProviders: {
			google: {
				clientId: "test",
				clientSecret: "test",
				enabled: true,
			},
		},
		emailAndPassword: {
			enabled: true,
		},
		account: {
			accountLinking: {
				enabled: true,
				trustedProviders: [],
			},
		},
	});

	const ctx = await auth.$context;

	it("should deny account linking when provider is not trusted and email is not verified", async () => {
		const testEmail = "untrusted@example.com";

		await ctx.adapter.create({
			model: "user",
			data: {
				id: "existing-user-id",
				email: testEmail,
				name: "Existing User",
				emailVerified: true,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile = {
					email: testEmail,
					email_verified: false,
					name: "Test User",
					sub: "google_untrusted_123",
					iat: 1234567890,
					exp: 1234567890,
					aud: "test",
					iss: "test",
				};
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_access_token",
					refresh_token: "test_refresh_token",
					id_token: idToken,
				});
			}),
		);

		const oAuthHeaders = new Headers();
		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/",
			fetchOptions: {
				onSuccess: cookieSetter(oAuthHeaders),
			},
		});

		const state = new URL(signInRes.data!.url!).searchParams.get("state") || "";
		let redirectLocation = "";
		await client.$fetch("/callback/google", {
			query: { state, code: "test_code" },
			method: "GET",
			headers: oAuthHeaders,
			onError(context) {
				redirectLocation = context.response.headers.get("location") || "";
			},
		});

		expect(redirectLocation).toContain("error=account_not_linked");

		const accounts = await ctx.adapter.findMany<{ providerId: string }>({
			model: "account",
			where: [{ field: "userId", value: "existing-user-id" }],
		});
		const googleAccount = accounts.find((a) => a.providerId === "google");
		expect(googleAccount).toBeUndefined();
	});

	it("should allow account linking when email is verified by provider and local user", async () => {
		const testEmail = "verified-provider@example.com";

		await ctx.adapter.create({
			model: "user",
			data: {
				id: "existing-user-verified",
				email: testEmail,
				name: "Existing User",
				emailVerified: true,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile = {
					email: testEmail,
					email_verified: true,
					name: "Test User",
					sub: "google_verified_456",
					iat: 1234567890,
					exp: 1234567890,
					aud: "test",
					iss: "test",
				};
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_access_token",
					refresh_token: "test_refresh_token",
					id_token: idToken,
				});
			}),
		);

		const oAuthHeaders = new Headers();
		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/dashboard",
			fetchOptions: {
				onSuccess: cookieSetter(oAuthHeaders),
			},
		});

		const state = new URL(signInRes.data!.url!).searchParams.get("state") || "";
		let redirectLocation = "";
		await client.$fetch("/callback/google", {
			query: { state, code: "test_code" },
			method: "GET",
			headers: oAuthHeaders,
			onError(context) {
				redirectLocation = context.response.headers.get("location") || "";
			},
		});

		expect(redirectLocation).not.toContain("error=account_not_linked");

		const user = await ctx.adapter.findOne<{ id: string }>({
			model: "user",
			where: [{ field: "email", value: testEmail }],
		});
		expect(user).toBeTruthy();

		const accounts = await ctx.adapter.findMany<{ providerId: string }>({
			model: "account",
			where: [{ field: "userId", value: user!.id }],
		});
		const googleAccount = accounts.find((a) => a.providerId === "google");
		expect(googleAccount).toBeTruthy();
	});
});

describe("oauth2 - disableImplicitLinking", async () => {
	const { auth, client, cookieSetter } = await getTestInstance({
		socialProviders: {
			google: {
				clientId: "test",
				clientSecret: "test",
				enabled: true,
			},
		},
		emailAndPassword: {
			enabled: true,
		},
		account: {
			accountLinking: {
				enabled: true,
				disableImplicitLinking: true,
				trustedProviders: ["google"],
			},
		},
	});

	const ctx = await auth.$context;

	it("should block implicit linking on sign-in even for trusted providers", async () => {
		const testEmail = "implicit-block@example.com";

		await ctx.adapter.create({
			model: "user",
			data: {
				id: "implicit-block-user",
				email: testEmail,
				name: "Existing User",
				emailVerified: true,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile = {
					email: testEmail,
					email_verified: true,
					name: "Test User",
					sub: "google_implicit_block_123",
					iat: 1234567890,
					exp: 1234567890,
					aud: "test",
					iss: "test",
				};
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_access_token",
					refresh_token: "test_refresh_token",
					id_token: idToken,
				});
			}),
		);

		const oAuthHeaders = new Headers();
		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/",
			fetchOptions: {
				onSuccess: cookieSetter(oAuthHeaders),
			},
		});

		const state = new URL(signInRes.data!.url!).searchParams.get("state") || "";
		let redirectLocation = "";
		await client.$fetch("/callback/google", {
			query: { state, code: "test_code" },
			method: "GET",
			headers: oAuthHeaders,
			onError(context) {
				redirectLocation = context.response.headers.get("location") || "";
			},
		});

		expect(redirectLocation).toContain("error=account_not_linked");

		const accounts = await ctx.adapter.findMany<{ providerId: string }>({
			model: "account",
			where: [{ field: "userId", value: "implicit-block-user" }],
		});
		const googleAccount = accounts.find((a) => a.providerId === "google");
		expect(googleAccount).toBeUndefined();
	});

	it("should allow new user sign-up even with disableImplicitLinking", async () => {
		const newUserEmail = "new-user-implicit@example.com";

		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile = {
					email: newUserEmail,
					email_verified: true,
					name: "New User",
					sub: "google_new_user_implicit_456",
					iat: 1234567890,
					exp: 1234567890,
					aud: "test",
					iss: "test",
				};
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_access_token",
					refresh_token: "test_refresh_token",
					id_token: idToken,
				});
			}),
		);

		const oAuthHeaders = new Headers();
		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/dashboard",
			fetchOptions: {
				onSuccess: cookieSetter(oAuthHeaders),
			},
		});

		const state = new URL(signInRes.data!.url!).searchParams.get("state") || "";
		let redirectLocation = "";
		await client.$fetch("/callback/google", {
			query: { state, code: "test_code" },
			method: "GET",
			headers: oAuthHeaders,
			onError(context) {
				redirectLocation = context.response.headers.get("location") || "";
			},
		});

		expect(redirectLocation).not.toContain("error");

		const user = await ctx.adapter.findOne<{ id: string }>({
			model: "user",
			where: [{ field: "email", value: newUserEmail }],
		});
		expect(user).toBeTruthy();
	});;
});

describe("oauth2 - accountLinking.requireLocalEmailVerified: false opt-out", async () => {
	const { auth, client, cookieSetter } = await getTestInstance({
		socialProviders: {
			google: {
				clientId: "test",
				clientSecret: "test",
				enabled: true,
			},
		},
		emailAndPassword: { enabled: true },
		account: {
			accountLinking: {
				enabled: true,
				trustedProviders: ["google"],
				requireLocalEmailVerified: false,
			},
		},
	});
	const ctx = await auth.$context;

	async function linkGoogleAccount() {
		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile: GoogleProfile = {
					email: mockEmail,
					email_verified: mockEmailVerified,
					name: "Test User",
					picture: "",
					exp: 1,
					sub: "google_opt_out_sub",
					iat: 1,
					aud: "test",
					azp: "test",
					nbf: 1,
					iss: "test",
					locale: "en",
					jti: "test",
					given_name: "Test",
					family_name: "User",
				};
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "t",
					refresh_token: "r",
					id_token: idToken,
				});
			}),
		);

		const oAuthHeaders = new Headers();
		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/",
			fetchOptions: { onSuccess: cookieSetter(oAuthHeaders) },
		});
		const state = new URL(signInRes.data!.url!).searchParams.get("state") || "";
		await client.$fetch("/callback/google", {
			query: { state, code: "test_code" },
			method: "GET",
			headers: oAuthHeaders,
			onError(context) {
				// The callback ends in a 302 to the callbackURL on success; the
				// HTTP client surfaces that as an error path. Ignore the redirect
				// so the test reaches the post-callback adapter assertions.
				expect(context.response.status).toBe(302);
			},
		});
	}

	it("links the account when local user is unverified and the option opts out", async () => {
		mockEmail = "opt-out@example.com";
		mockEmailVerified = true;
		const signUpRes = await client.signUp.email({
			email: mockEmail,
			password: "password123",
			name: "Opt Out User",
		});
		const userId = signUpRes.data!.user.id;

		await linkGoogleAccount();

		const accounts = await ctx.adapter.findMany<{
			providerId: string;
			userId: string;
		}>({
			model: "account",
			where: [{ field: "userId", value: userId }],
		});
		expect(accounts.some((a) => a.providerId === "google")).toBe(true);

		// The legacy emailVerified-promotion path is reachable when the gate is
		// opted out, so the IdP's verified email lifts the local row.
		const promoted = await ctx.adapter.findOne<User>({
			model: "user",
			where: [{ field: "id", value: userId }],
		});
		expect(promoted?.emailVerified).toBe(true);
	});
});
