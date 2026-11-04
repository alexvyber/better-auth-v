// Generated from pinned upstream source; do not edit assertions here.
import type { GoogleProfile } from "@better-auth/core/social-providers";
import type { User } from "better-auth";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import * as z from "zod";
import { signJWT } from "../harness/crypto.js";
import { getTestInstance } from "../harness/postgres-fixture.js";
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

describe("oauth2 - updateUserInfoOnLink on implicit sign-in link", async () => {
	const { auth, client, cookieSetter } = await getTestInstance({
		user: {
			additionalFields: {
				googleSub: { type: "string", required: false },
				profileCode: {
					type: "string",
					required: false,
					transform: {
						input(value) {
							return typeof value === "string" ? value.toLowerCase() : value;
						},
					},
				},
				validatedProfileCode: {
					type: "string",
					required: false,
					validator: {
						input: z.string().min(3),
					},
				},
				serverManagedField: {
					type: "string",
					required: false,
					input: false,
				},
			},
		},
		socialProviders: {
			google: {
				clientId: "test",
				clientSecret: "test",
				enabled: true,
				mapProfileToUser(profile: GoogleProfile) {
					return {
						googleSub: profile.sub,
						profileCode: profile.sub,
						validatedProfileCode: profile.sub,
						serverManagedField: "elevated",
					};
				},
			},
		},
		account: {
			accountLinking: {
				enabled: true,
				trustedProviders: ["google"],
				updateUserInfoOnLink: true,
			},
		},
		session: {
			cookieCache: { enabled: true, maxAge: 300 },
		},
	});

	const ctx = await auth.$context;

	async function signInAndLink(email: string, sub: string) {
		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile = {
					sub,
					email,
					email_verified: true,
					name: "Updated Name From Google",
					picture: "https://example.com/avatar.jpg",
				} as GoogleProfile;
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_token",
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
				expect(context.response.status).toBe(302);
				cookieSetter(oAuthHeaders)(context as any);
			},
		});
		return oAuthHeaders;
	}

	it("returns the freshly linked name and image in the new session", async () => {
		const testEmail = "implicit-link@example.com";
		await ctx.adapter.create({
			model: "user",
			data: { email: testEmail, name: "Original Name", emailVerified: true },
		});

		const oAuthHeaders = await signInAndLink(testEmail, "google_implicit_name");

		// The cookie cache is seeded from the value handleOAuthUserInfo returns,
		// and getSession serves it without a database read, so a stale return
		// would surface right here.
		const session = await client.getSession({
			fetchOptions: { headers: oAuthHeaders },
		});
		expect(session.data?.user.name).toBe("Updated Name From Google");
		expect(session.data?.user.image).toBe("https://example.com/avatar.jpg");
	});

	it("syncs mapProfileToUser fields on link, not only name and image", async () => {
		const testEmail = "implicit-link-mapped@example.com";
		await ctx.adapter.create({
			model: "user",
			data: { email: testEmail, name: "Original Name", emailVerified: true },
		});

		const updateUserSpy = vi.spyOn(ctx.internalAdapter, "updateUser");
		try {
			await signInAndLink(testEmail, "GOOGLE_IMPLICIT_MAPPED");

			expect(updateUserSpy).toHaveBeenCalledWith(
				expect.any(String),
				expect.objectContaining({
					googleSub: "GOOGLE_IMPLICIT_MAPPED",
					profileCode: "google_implicit_mapped",
				}),
			);

			const user = await ctx.adapter.findOne<
				User & { googleSub?: string; profileCode?: string }
			>({
				model: "user",
				where: [{ field: "email", value: testEmail }],
			});
			expect(user?.googleSub).toBe("GOOGLE_IMPLICIT_MAPPED");
			expect(user?.profileCode).toBe("google_implicit_mapped");
		} finally {
			updateUserSpy.mockRestore();
		}
	});

	it("does not copy fields marked input: false from the provider on link", async () => {
		const testEmail = "implicit-link-input-false@example.com";
		await ctx.adapter.create({
			model: "user",
			data: { email: testEmail, name: "Original Name", emailVerified: true },
		});

		await signInAndLink(testEmail, "google_link_input_false");

		const user = await ctx.adapter.findOne<
			User & { googleSub?: string; serverManagedField?: string | null }
		>({
			model: "user",
			where: [{ field: "email", value: testEmail }],
		});
		expect(user?.googleSub).toBe("google_link_input_false");
		expect(user?.serverManagedField ?? null).toBeNull();
	});

	it("continues linking when mapped profile fields fail validation", async () => {
		const testEmail = "implicit-link-invalid-profile@example.com";
		await ctx.adapter.create({
			model: "user",
			data: { email: testEmail, name: "Original Name", emailVerified: true },
		});

		const oAuthHeaders = await signInAndLink(testEmail, "x");

		const session = await client.getSession({
			fetchOptions: { headers: oAuthHeaders },
		});
		expect(session.data?.user.email).toBe(testEmail);
		expect(session.data?.user.name).toBe("Original Name");

		const accounts = await ctx.adapter.findMany<{ providerId: string }>({
			model: "account",
			where: [{ field: "userId", value: session.data!.user.id }],
		});
		expect(accounts.find((a) => a.providerId === "google")).toBeTruthy();

		const user = await ctx.adapter.findOne<
			User & { validatedProfileCode?: string | null }
		>({
			model: "user",
			where: [{ field: "email", value: testEmail }],
		});
		expect(user?.validatedProfileCode ?? null).toBeNull();
	});
});

describe("oauth2 - first sign-in provisioning applies user input rules", async () => {
	const { auth, client, cookieSetter } = await getTestInstance({
		user: {
			additionalFields: {
				googleSub: { type: "string", required: false },
				profileCode: {
					type: "string",
					required: false,
					transform: {
						input(value) {
							return typeof value === "string" ? value.toLowerCase() : value;
						},
					},
				},
				serverManagedField: {
					type: "string",
					required: false,
					input: false,
				},
				serverManagedDefault: {
					type: "string",
					required: false,
					defaultValue: "member",
					input: false,
				},
			},
		},
		socialProviders: {
			google: {
				clientId: "test",
				clientSecret: "test",
				enabled: true,
				mapProfileToUser(profile: GoogleProfile) {
					return {
						googleSub: profile.sub,
						profileCode: "PROVIDER-CODE",
						serverManagedField: "elevated",
						serverManagedDefault: "admin",
					};
				},
			},
		},
	});

	const ctx = await auth.$context;

	it("does not copy fields marked input: false from the provider on first sign-in", async () => {
		const testEmail = "implicit-create-input-false@example.com";

		server.use(
			http.post("https://oauth2.googleapis.com/token", async () => {
				const profile = {
					sub: "google_create_input_false",
					email: testEmail,
					email_verified: true,
					name: "Created From Google",
				} as GoogleProfile;
				const idToken = await signJWT(profile, DEFAULT_SECRET);
				return HttpResponse.json({
					access_token: "test_token",
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
				expect(context.response.status).toBe(302);
				cookieSetter(oAuthHeaders)(context as any);
			},
		});

		const user = await ctx.adapter.findOne<
			User & {
				googleSub?: string;
				profileCode?: string;
				serverManagedField?: string | null;
				serverManagedDefault?: string | null;
			}
		>({
			model: "user",
			where: [{ field: "email", value: testEmail }],
		});
		// The mapped, input-enabled field is still written...
		expect(user?.googleSub).toBe("google_create_input_false");
		expect(user?.profileCode).toBe("provider-code");
		// ...while the input: false provider value is ignored.
		expect(user?.serverManagedField ?? null).toBeNull();
		// The schema-owned default still applies on create.
		expect(user?.serverManagedDefault).toBe("member");
	});
});
