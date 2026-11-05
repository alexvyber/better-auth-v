// Generated from pinned upstream source; do not edit assertions here.
import {parseSetCookieHeader} from "better-auth/cookies";
import {APIError} from "@better-auth/core/error";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { GenericEndpointContext } from "@better-auth/core";
import { runWithEndpointContext } from "@better-auth/core/context";
import { betterFetch } from "@better-fetch/fetch";
import { generateKeyPair, SignJWT } from "jose";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { OAuth2Server } from "oauth2-mock-server";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuthClient } from "better-auth/client";
import { getTestInstance } from "../harness/test-instance.js";
import { genericOAuth } from "../harness/plugins.js";

describe("oauth2", async () => {
	const providerId = "test";
	const clientId = "test-client-id";
	const clientSecret = "test-client-secret";
	const server = new OAuth2Server();
	const mswServer = setupServer();
	await server.start();
	const port = Number(server.issuer.url?.split(":")[2]!);

	beforeAll(() => {
		mswServer.listen({ onUnhandledRequest: "bypass" });
	});

	afterEach(() => {
		mswServer.resetHandlers();
	});

	afterAll(async () => {
		mswServer.close();
		await server.stop();
	});

	const { customFetchImpl, auth, cookieSetter } = await getTestInstance({
		databaseHooks: {
			user: {
				create: {
					before: async (user) => ({
						data: { ...user, emailVerified: true },
					}),
				},
			},
		},
		plugins: [
			genericOAuth({
				config: [
					{
						providerId,
						discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
						clientId: clientId,
						clientSecret: clientSecret,
						pkce: true,
					},
				],
			}),
		],
	});

	const authClient = createAuthClient({
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	async function createMicrosoftIdToken(payload: Record<string, unknown>) {
		return new SignJWT(payload)
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt()
			.setExpirationTime("1h")
			.sign(new TextEncoder().encode("microsoft-test-secret"));
	}

	beforeAll(async () => {
		const context = await auth.$context;
		await runWithEndpointContext(
			{
				context,
			} as unknown as GenericEndpointContext,
			async () => {
				await context.internalAdapter.createUser(
					{
						email: "oauth2@test.com",
						name: "OAuth2 Test",
					},
					{ method: "test" },
				);
			},
		);
		await server.issuer.keys.generate("RS256");
	});

	server.service.on("beforeUserinfo", (userInfoResponse, req) => {
		userInfoResponse.body = {
			email: "oauth2@test.com",
			name: "OAuth2 Test",
			sub: "oauth2",
			picture: "https://test.com/picture.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	});

	async function simulateOAuthFlow(
		authUrl: string,
		headers: Headers,
		fetchImpl?: ((...args: any) => any) | undefined,
	) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");

		let callbackURL = "";
		let setCookieHeader = "";
		const newHeaders = new Headers();
		await betterFetch(location, {
			method: "GET",
			customFetchImpl: fetchImpl || customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				setCookieHeader = context.response.headers.get("set-cookie") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders, setCookieHeader };
	};

	it("should delete state cookie with path attribute", async () => {
		const headers = new Headers();
		const signInRes = await authClient.signIn.social({
			provider: "test",
			callbackURL: "http://localhost:3000/dashboard",
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});

		const { setCookieHeader } = await simulateOAuthFlow(
			signInRes.data?.url || "",
			headers,
		);

		const cookies = parseSetCookieHeader(setCookieHeader);
		const stateCookie = cookies.get("better-auth.state");

		expect(stateCookie?.["max-age"]).toBe(0);
		expect(stateCookie?.path).toBe("/");
	});

	it("should complete full sign-in flow and return correct session data", async () => {
		const headers = new Headers();
		const signInRes = await authClient.signIn.social({
			provider: "test",
			callbackURL: "http://localhost:3000/dashboard",
			newUserCallbackURL: "http://localhost:3000/new_user",
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});
		expect(signInRes.data).toMatchObject({
			url: expect.stringContaining(`http://localhost:${port}/authorize`),
			redirect: true,
		});
		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			signInRes.data?.url || "",
			headers,
		);
		expect(callbackURL).toBe("http://localhost:3000/dashboard");

		const session = await authClient.getSession({
			fetchOptions: { headers: sessionHeaders },
		});
		expect(session.data).not.toBeNull();
		expect(session.data?.user.email).toBe("oauth2@test.com");
		expect(session.data?.user.name).toBe("OAuth2 Test");
		expect(session.data?.session.userId).toBe(session.data?.user.id);

		const ctx = await auth.$context;
		const accounts = await ctx.internalAdapter.findAccounts(
			session.data?.user.id!,
		);
		expect(accounts).toHaveLength(1);
		expect(accounts[0]).toMatchObject({
			providerId: "test",
			accountId: "oauth2",
		});
	});

	it("should redirect to the provider and handle the response for a new user", async () => {
		server.service.once("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: "oauth2-2@test.com",
				name: "OAuth2 Test 2",
				sub: "oauth2-2",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});

		const headers = new Headers();
		const signInRes = await authClient.signIn.social({
			provider: "test",
			callbackURL: "http://localhost:3000/dashboard",
			newUserCallbackURL: "http://localhost:3000/new_user",
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});
		expect(signInRes.data).toMatchObject({
			url: expect.stringContaining(`http://localhost:${port}/authorize`),
			redirect: true,
		});
		const { callbackURL, headers: newHeaders } = await simulateOAuthFlow(
			signInRes.data?.url || "",
			headers,
		);
		expect(callbackURL).toBe("http://localhost:3000/new_user");
		const session = await authClient.getSession({
			fetchOptions: {
				headers: newHeaders,
			},
		});
		const ctx = await auth.$context;
		const accounts = await ctx.internalAdapter.findAccounts(
			session.data?.user.id!,
		);
		const account = accounts[0];
		expect(account).toMatchObject({
			providerId,
			accountId: "oauth2-2",
			userId: session.data?.user.id,
			accessToken: expect.any(String),
			refreshToken: expect.any(String),
			accessTokenExpiresAt: expect.any(Date),
			refreshTokenExpiresAt: null,
			scope: expect.any(String),
			idToken: expect.any(String),
		});
	});;;;;;;;

	it("should redirect to the provider and handle the response after linked", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.social({
			provider: "test",
			callbackURL: "http://localhost:3000/dashboard",
			newUserCallbackURL: "http://localhost:3000/new_user",
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});
		const { callbackURL } = await simulateOAuthFlow(
			res.data?.url || "",
			headers,
		);
		expect(callbackURL).toBe("http://localhost:3000/dashboard");
	});;

	it("should handle server error during OAuth flow", async () => {
		server.service.once("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: "oauth2@test.com",
				name: "OAuth2 Test",
				sub: "oauth2",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 500;
		});

		const headers = new Headers();
		const res = await authClient.signIn.social(
			{
				provider: "test",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
			},
			{
				onSuccess(context) {
					const parsedSetCookie = parseSetCookieHeader(
						context.response.headers.get("Set-Cookie") || "",
					);
					headers.set(
						"cookie",
						`better-auth.state=${
							parsedSetCookie.get("better-auth.state")?.value
						}; better-auth.pk_code_verifier=${
							parsedSetCookie.get("better-auth.pk_code_verifier")?.value
						}`,
					);
				},
			},
		);

		const { callbackURL } = await simulateOAuthFlow(
			res.data?.url || "",
			headers,
		);
		expect(callbackURL).toContain("?error=");
	});;

	it("should not create user when sign ups are disabled", async () => {
		server.service.once("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: "oauth2-signup-disabled@test.com",
				name: "OAuth2 Test Signup Disabled",
				sub: "oauth2-signup-disabled",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});

		const { customFetchImpl, cookieSetter } = await getTestInstance({
			plugins: [
				genericOAuth({
					config: [
						{
							providerId: "test2",
							discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
							clientId: clientId,
							clientSecret: clientSecret,
							pkce: true,
							disableImplicitSignUp: true,
						},
					],
				}),
			],
		});
		const authClient = createAuthClient({
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
			},
		});
		const headers = new Headers();
		const res = await authClient.signIn.social({
			provider: "test2",
			callbackURL: "http://localhost:3000/dashboard",
			errorCallbackURL: "http://localhost:3000/error",
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.data?.url).toContain(`http://localhost:${port}/authorize`);
		const { callbackURL } = await simulateOAuthFlow(
			res.data?.url || "",
			headers,
			customFetchImpl,
		);
		expect(callbackURL).toBe(
			"http://localhost:3000/error?error=signup_disabled",
		);
	});;

	it("should create user when sign ups are disabled and sign up is requested", async () => {
		server.service.once("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: "oauth2-signup-disabled-and-requested@test.com",
				name: "OAuth2 Test Signup Disabled And Requested",
				sub: "oauth2-signup-disabled-and-requested",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});

		const { customFetchImpl, cookieSetter } = await getTestInstance({
			plugins: [
				genericOAuth({
					config: [
						{
							providerId: "test2",
							discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
							clientId: clientId,
							clientSecret: clientSecret,
							pkce: true,
							disableImplicitSignUp: true,
						},
					],
				}),
			],
		});

		const authClient = createAuthClient({
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
			},
		});
		const headers = new Headers();
		const res = await authClient.signIn.social({
			provider: "test2",
			callbackURL: "http://localhost:3000/dashboard",
			errorCallbackURL: "http://localhost:3000/error",
			requestSignUp: true,
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.data?.url).toContain(`http://localhost:${port}/authorize`);
		const { callbackURL } = await simulateOAuthFlow(
			res.data?.url || "",
			headers,
			customFetchImpl,
		);
		expect(callbackURL).toBe("http://localhost:3000/dashboard");
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/9702
	 */
	it("should redirect to cross-origin errorCallbackURL when a session hook throws APIError", async () => {
		server.service.once("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: "hook-reject@test.com",
				name: "Hook Reject User",
				sub: "hook-reject",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});

		const { customFetchImpl, cookieSetter } = await getTestInstance(
			{
				trustedOrigins: ["https://frontend.example.com"],
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test-hook-reject",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
							},
						],
					}),
				],
				databaseHooks: {
					user: {
						create: {
							before: async (user) => ({
								data: { ...user, emailVerified: true },
							}),
						},
					},
					session: {
						create: {
							before: async () => {
								throw APIError.from("FORBIDDEN", {
									code: "HOOK_REJECTED",
									message: "Session hook rejected this user",
								});
							},
						},
					},
				},
			},
			{ disableTestUser: true },
		);
		const authClient = createAuthClient({
			baseURL: "http://localhost:3000",
			fetchOptions: { customFetchImpl },
		});
		const headers = new Headers();
		const res = await authClient.signIn.social({
			provider: "test-hook-reject",
			callbackURL: "https://frontend.example.com/dashboard",
			errorCallbackURL: "https://frontend.example.com/auth-error",
			fetchOptions: { onSuccess: cookieSetter(headers) },
		});
		const { callbackURL } = await simulateOAuthFlow(
			res.data?.url || "",
			headers,
			customFetchImpl,
		);
		const url = new URL(callbackURL);
		expect(url.origin).toBe("https://frontend.example.com");
		expect(url.pathname).toBe("/auth-error");
		expect(url.searchParams.get("error")).toBe("HOOK_REJECTED");
		expect(url.searchParams.get("error_description")).toBe(
			"Session hook rejected this user",
		);
	});;;;;;;;;;;;;;;;;;;

	/**
	 * @see https://github.com/better-auth/better-auth/pull/4951
	 * @see https://github.com/better-auth/better-auth/pull/9069
	 */
	it("should redirect to the error page when a GET callback arrives without state", async () => {
		const res = await customFetchImpl(
			`http://localhost:3000/api/auth/callback/${providerId}?code=dummy`,
			{
				method: "GET",
				redirect: "manual",
			},
		);

		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toContain("state_not_found");
	});;;;;;;;;;;;;;;;;;;;

	it("should merge client-requested scopes with config scopes", async () => {
		const { customFetchImpl, cookieSetter } = await getTestInstance({
			plugins: [
				genericOAuth({
					config: [
						{
							providerId: "scopes-test",
							discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
							clientId: clientId,
							clientSecret: clientSecret,
							scopes: ["openid", "email", "profile"],
						},
					],
				}),
			],
		});
		const headers = new Headers();
		const authClient = createAuthClient({
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
				onSuccess: cookieSetter(headers),
			},
		});

		const res = await authClient.signIn.social({
			provider: "scopes-test",
			callbackURL: "http://localhost:3000/dashboard",
			scopes: ["custom_scope"],
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});

		const url = res.data?.url || "";
		const scopeParam = new URL(url).searchParams.get("scope") || "";
		const scopes = scopeParam.split(" ");
		expect(scopes).toContain("custom_scope");
		expect(scopes).toContain("openid");
		expect(scopes).toContain("email");
		expect(scopes).toContain("profile");
	});;

	it("should pass discovered issuer to the provider for RFC 9207 validation", async () => {
		const { auth } = await getTestInstance({
			plugins: [
				genericOAuth({
					config: [
						{
							providerId: "issuer-test",
							discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
							clientId: clientId,
							clientSecret: clientSecret,
						},
					],
				}),
			],
		});

		const ctx = await auth.$context;
		const provider = ctx.socialProviders.find((p) => p.id === "issuer-test");
		expect(provider).toBeDefined();
		expect(provider?.issuer).toBe(`http://localhost:${port}`);
	});;;;

	describe("validateUserInfo callback", () => {
		it("should reject sign-in with provider metadata and raw profile", async () => {
			server.service.once("beforeUserinfo", (userInfoResponse) => {
				userInfoResponse.body = {
					email: "bad@blocked.com",
					name: "Bad User",
					sub: "bad-oauth",
					email_verified: true,
					custom_field: "custom-value",
				};
				userInfoResponse.statusCode = 200;
			});

			let capturedProfile: unknown;
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				user: {
					validateUserInfo({ user, source }) {
						if (source.method !== "oauth") {
							return;
						}
						expect(source.action).toBe("create-user");
						expect(source.oauth?.providerId).toBe("validate-generic");
						capturedProfile = source.oauth?.profile;
						if (user.email?.endsWith("@blocked.com")) {
							return {
								error: "domain_blocked",
								errorDescription:
									"Only company emails are allowed for this provider",
							};
						}
					},
				},
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "validate-generic",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
							},
						],
					}),
				],
			});

			const localAuthClient = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});

			const headers = new Headers();
			const res = await localAuthClient.signIn.social({
				provider: "validate-generic",
				callbackURL: "http://localhost:3000/dashboard",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			const { callbackURL } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);

			expect(callbackURL).toContain("error=domain_blocked");
			expect(callbackURL).toContain(
				"error_description=Only+company+emails+are+allowed+for+this+provider",
			);
			expect((capturedProfile as Record<string, unknown>).custom_field).toBe(
				"custom-value",
			);
		});

		it("should work in stateless mode (no database)", async () => {
			server.service.once("beforeUserinfo", (userInfoResponse) => {
				userInfoResponse.body = {
					email: "stateless@blocked.com",
					name: "Stateless User",
					sub: "stateless-oauth",
					email_verified: true,
				};
				userInfoResponse.statusCode = 200;
			});

			const { customFetchImpl, cookieSetter } = await getTestInstance({
				database: undefined,
				user: {
					validateUserInfo({ user, source }) {
						if (source.method !== "oauth") {
							return;
						}
						expect(source.oauth?.providerId).toBe("validate-stateless");
						if (user.email?.endsWith("@blocked.com")) {
							return {
								error: "stateless_blocked",
								errorDescription: "Stateless rejection test",
							};
						}
					},
				},
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "validate-stateless",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
							},
						],
					}),
				],
			});

			const localAuthClient = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});

			const headers = new Headers();
			const res = await localAuthClient.signIn.social({
				provider: "validate-stateless",
				callbackURL: "http://localhost:3000/dashboard",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			const { callbackURL } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);

			expect(callbackURL).toContain("error=stateless_blocked");
			expect(callbackURL).toContain(
				"error_description=Stateless+rejection+test",
			);
		});
	});

	describe("id_token verification", () => {
		// The forged token carries valid iss/aud/exp claims; only its signing
		// key is unknown to the provider JWKS, so a rejection isolates
		// signature verification.
		async function forgeIdToken() {
			const { privateKey } = await generateKeyPair("RS256");
			return new SignJWT({
				email: "forged@test.com",
				email_verified: true,
				name: "Forged User",
			})
				.setProtectedHeader({ alg: "RS256" })
				.setSubject("forged-user")
				.setIssuer(`http://localhost:${port}`)
				.setAudience(clientId)
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);
		}

		it("should reject an id_token not signed by the discovery JWKS", async () => {
			const forged = await forgeIdToken();
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "verify-reject",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
								getToken: async () => ({
									accessToken: "forged-access-token",
									idToken: forged,
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "verify-reject",
				callbackURL: "http://localhost:3000/dashboard",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});
			const { callbackURL } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toContain("?error=");
		});

		it("should use claims from an id_token verified against the discovery JWKS", async () => {
			const addClaims = (token: { payload: Record<string, unknown> }) => {
				Object.assign(token.payload, {
					email: "idtoken-claims@test.com",
					email_verified: true,
					name: "Id Token Claims",
				});
			};
			server.service.on("beforeTokenSigning", addClaims);
			try {
				const headers = new Headers();
				const res = await authClient.signIn.social({
					provider: providerId,
					callbackURL: "http://localhost:3000/dashboard",
					newUserCallbackURL: "http://localhost:3000/new_user",
					fetchOptions: { onSuccess: cookieSetter(headers) },
				});
				const { callbackURL, headers: sessionHeaders } =
					await simulateOAuthFlow(res.data?.url || "", headers);
				expect(callbackURL).toBe("http://localhost:3000/new_user");
				const session = await authClient.getSession({
					fetchOptions: { headers: sessionHeaders },
				});
				expect(session.data?.user.email).toBe("idtoken-claims@test.com");
			} finally {
				server.service.off("beforeTokenSigning", addClaims);
			}
		});

		/**
		 * @see https://github.com/better-auth/better-auth/issues/7571
		 */
		it("should bind a discovery id_token to the authorization request nonce", async () => {
			let authorizationNonce = "";
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "nonce-match",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
								authorizationUrlParams: { nonce: "configured-nonce" },
								getToken: async () => ({
									accessToken: "nonce-match-access-token",
									idToken: await server.issuer.buildToken({
										scopesOrTransform: (_header, payload) => {
											Object.assign(payload, {
												aud: clientId,
												sub: "nonce-match-user",
												email: "nonce-match@test.com",
												email_verified: true,
												name: "Nonce Match",
												nonce: authorizationNonce,
											});
										},
									}),
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "nonce-match",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			authorizationNonce =
				new URL(res.data?.url || "").searchParams.get("nonce") || "";
			expect(authorizationNonce).toBeTruthy();
			expect(authorizationNonce).not.toBe("configured-nonce");

			const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toBe("http://localhost:3000/new_user");

			const session = await client.getSession({
				fetchOptions: { headers: sessionHeaders },
			});
			expect(session.data?.user.email).toBe("nonce-match@test.com");
		});

		/**
		 * @see https://github.com/better-auth/better-auth/issues/7571
		 */
		it("should reject a discovery id_token with a mismatched nonce", async () => {
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "nonce-mismatch",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
								getToken: async () => ({
									accessToken: "nonce-mismatch-access-token",
									idToken: await server.issuer.buildToken({
										scopesOrTransform: (_header, payload) => {
											Object.assign(payload, {
												aud: clientId,
												sub: "nonce-mismatch-user",
												email: "nonce-mismatch@test.com",
												email_verified: true,
												name: "Nonce Mismatch",
												nonce: "different-nonce",
											});
										},
									}),
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "nonce-mismatch",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			expect(
				new URL(res.data?.url || "").searchParams.get("nonce"),
			).toBeTruthy();

			const { callbackURL } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toContain("?error=");
		});

		/**
		 * @see https://github.com/better-auth/better-auth/issues/7571
		 */
		it("should reject a discovery id_token that omits the nonce claim", async () => {
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "nonce-missing",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
								getToken: async () => ({
									accessToken: "nonce-missing-access-token",
									idToken: await server.issuer.buildToken({
										scopesOrTransform: (_header, payload) => {
											Object.assign(payload, {
												aud: clientId,
												sub: "nonce-missing-user",
												email: "nonce-missing@test.com",
												email_verified: true,
												name: "Nonce Missing",
											});
										},
									}),
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "nonce-missing",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			expect(
				new URL(res.data?.url || "").searchParams.get("nonce"),
			).toBeTruthy();

			const { callbackURL } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toContain("?error=");
		});

		it("should not bind a nonce when id_token nonce binding is disabled", async () => {
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "nonce-disabled",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
								disableIdTokenNonceBinding: true,
								getToken: async () => ({
									accessToken: "nonce-disabled-access-token",
									idToken: await server.issuer.buildToken({
										scopesOrTransform: (_header, payload) => {
											Object.assign(payload, {
												aud: clientId,
												sub: "nonce-disabled-user",
												email: "nonce-disabled@test.com",
												email_verified: true,
												name: "Nonce Disabled",
											});
										},
									}),
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "nonce-disabled",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			expect(new URL(res.data?.url || "").searchParams.get("nonce")).toBeNull();

			const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toBe("http://localhost:3000/new_user");

			const session = await client.getSession({
				fetchOptions: { headers: sessionHeaders },
			});
			expect(session.data?.user.email).toBe("nonce-disabled@test.com");
		});

		it("should drop a configured nonce param for providers without nonce binding", async () => {
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "nonce-static",
								authorizationUrl: `http://localhost:${port}/authorize`,
								tokenUrl: `http://localhost:${port}/token`,
								clientId,
								clientSecret,
								pkce: true,
								authorizationUrlParams: { nonce: "configured-nonce" },
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "nonce-static",
				callbackURL: "http://localhost:3000/dashboard",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});

			expect(new URL(res.data?.url || "").searchParams.get("nonce")).toBeNull();
		});

		/**
		 * @see https://github.com/better-auth/better-auth/pull/10095#discussion_r3417330694
		 */
		it("should reject a discovery id_token when state carries no expected nonce", async () => {
			const { customFetchImpl, cookieSetter, auth } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "nonce-skew",
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
								clientId,
								clientSecret,
								pkce: true,
								getToken: async () => ({
									accessToken: "nonce-skew-access-token",
									idToken: await server.issuer.buildToken({
										scopesOrTransform: (_header, payload) => {
											Object.assign(payload, {
												aud: clientId,
												sub: "nonce-skew-user",
												email: "nonce-skew@test.com",
												email_verified: true,
												name: "Nonce Skew",
											});
										},
									}),
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const ctx = await auth.$context;
			const provider = ctx.socialProviders.find((p) => p.id === "nonce-skew")!;
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});

			// Mint state before binding is required, so it carries no expected nonce.
			provider.requiresIdTokenNonce = false;
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "nonce-skew",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});
			expect(new URL(res.data?.url || "").searchParams.get("nonce")).toBeNull();

			// The provider now requires binding, but the in-flight state has none.
			provider.requiresIdTokenNonce = true;
			const { callbackURL } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toContain("error=nonce_binding_missing");
		});

		it("should sign in with a client-submitted id_token for a discovery provider", async () => {
			const token = await server.issuer.buildToken({
				scopesOrTransform: (_header, payload) => {
					Object.assign(payload, {
						aud: clientId,
						sub: "front-channel-user",
						email: "front-channel@test.com",
						email_verified: true,
						name: "Front Channel",
					});
				},
			});
			const res = await authClient.signIn.social({
				provider: providerId,
				idToken: { token },
			});
			expect(res.error).toBeNull();
			expect(res.data).toMatchObject({ token: expect.any(String) });
		});

		it("should keep the decode posture for providers without discovery", async () => {
			const forged = await forgeIdToken();
			const { customFetchImpl, cookieSetter } = await getTestInstance({
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "no-discovery",
								authorizationUrl: `http://localhost:${port}/authorize`,
								tokenUrl: `http://localhost:${port}/token`,
								clientId,
								clientSecret,
								pkce: true,
								getToken: async () => ({
									accessToken: "opaque-access-token",
									idToken: forged,
									tokenType: "bearer",
								}),
							},
						],
					}),
				],
			});
			const client = createAuthClient({
				baseURL: "http://localhost:3000",
				fetchOptions: { customFetchImpl },
			});
			const headers = new Headers();
			const res = await client.signIn.social({
				provider: "no-discovery",
				callbackURL: "http://localhost:3000/dashboard",
				newUserCallbackURL: "http://localhost:3000/new_user",
				fetchOptions: { onSuccess: cookieSetter(headers) },
			});
			const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
				res.data?.url || "",
				headers,
				customFetchImpl,
			);
			expect(callbackURL).toBe("http://localhost:3000/new_user");
			const session = await client.getSession({
				fetchOptions: { headers: sessionHeaders },
			});
			expect(session.data?.user.email).toBe("forged@test.com");
		});

		it("skips a provider when required ID token verification metadata is unavailable", async () => {
			const discoveryServer = createServer((_req, res) => {
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						issuer: `http://localhost:${port}`,
						authorization_endpoint: `http://localhost:${port}/authorize`,
						token_endpoint: `http://localhost:${port}/token`,
					}),
				);
			});
			await new Promise<void>((resolve) => discoveryServer.listen(0, resolve));
			const discoveryPort = (discoveryServer.address() as AddressInfo).port;
			try {
				const { auth } = await getTestInstance(
					{
						plugins: [
							genericOAuth({
								config: [
									{
										providerId: "verified-id-token-required",
										discoveryUrl: `http://localhost:${discoveryPort}/.well-known/openid-configuration`,
										authorizationUrl: `http://localhost:${port}/authorize`,
										tokenUrl: `http://localhost:${port}/token`,
										requireIdTokenVerification: true,
										clientId,
										clientSecret,
									},
								],
							}),
						],
					},
					{ disableTestUser: true },
				);

				const context = await auth.$context;
				expect(
					context.socialProviders.map((provider) => provider.id),
				).not.toContain("verified-id-token-required");
			} finally {
				await new Promise<void>((resolve, reject) =>
					discoveryServer.close((error) => (error ? reject(error) : resolve())),
				);
			}
		});

		it("skips a provider when discovery returns a malformed jwks_uri", async () => {
			const discoveryServer = createServer((_req, res) => {
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						issuer: `http://localhost:${port}`,
						authorization_endpoint: `http://localhost:${port}/authorize`,
						token_endpoint: `http://localhost:${port}/token`,
						userinfo_endpoint: `http://localhost:${port}/userinfo`,
						jwks_uri: "http://[malformed",
						id_token_signing_alg_values_supported: ["RS256"],
					}),
				);
			});
			await new Promise<void>((resolve) => discoveryServer.listen(0, resolve));
			const discoveryPort = (discoveryServer.address() as AddressInfo).port;
			try {
				const { auth } = await getTestInstance(
					{
						plugins: [
							genericOAuth({
								config: [
									{
										providerId: "malformed-jwks",
										discoveryUrl: `http://localhost:${discoveryPort}/.well-known/openid-configuration`,
										clientId,
										clientSecret,
										pkce: true,
									},
								],
							}),
						],
					},
					{ disableTestUser: true },
				);
				const context = await auth.$context;
				expect(
					context.socialProviders.map((provider) => provider.id),
				).not.toContain("malformed-jwks");
			} finally {
				await new Promise<void>((resolve, reject) =>
					discoveryServer.close((err) => (err ? reject(err) : resolve())),
				);
			}
		});
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/10961
	 */
	it.each(["authorization", "token", "both"])(
		"skips discovery missing %s endpoints",
		async (missing) => {
			const discoveryUrl =
				"https://incomplete-idp.test/.well-known/openid-configuration";
			mswServer.use(
				http.get(discoveryUrl, () =>
					HttpResponse.json({
						issuer: "https://incomplete-idp.test",
						...(missing === "token"
							? {
									authorization_endpoint:
										"https://incomplete-idp.test/authorize",
								}
							: {}),
						...(missing === "authorization"
							? { token_endpoint: "https://incomplete-idp.test/token" }
							: {}),
					}),
				),
			);
			const { auth } = await getTestInstance(
				{
					plugins: [
						genericOAuth({
							config: [
								{
									providerId: "incomplete",
									clientId,
									clientSecret,
									discoveryUrl,
								},
							],
						}),
					],
				},
				{ disableTestUser: true },
			);
			expect(
				(await auth.$context).socialProviders.map((provider) => provider.id),
			).not.toContain("incomplete");
		},
	);

	it.each([false, true])(
		"keeps explicit token exchange with incomplete discovery (custom=%s)",
		async (custom) => {
			const discoveryUrl =
				"https://incomplete-idp.test/.well-known/openid-configuration";
			mswServer.use(
				http.get(discoveryUrl, () =>
					HttpResponse.json({ issuer: "https://incomplete-idp.test" }),
				),
			);
			const { auth } = await getTestInstance(
				{
					plugins: [
						genericOAuth({
							config: [
								{
									providerId: "explicit",
									clientId,
									clientSecret,
									discoveryUrl,
									authorizationUrl: "https://incomplete-idp.test/authorize",
									...(custom
										? {
												getToken: async () => ({ accessToken: "custom-token" }),
											}
										: { tokenUrl: "https://incomplete-idp.test/token" }),
								},
							],
						}),
					],
				},
				{ disableTestUser: true },
			);
			expect(
				(await auth.$context).socialProviders.map((provider) => provider.id),
			).toContain("explicit");
		},
	);

	/**
	 * @see https://github.com/better-auth/better-auth/issues/10961
	 */
	it("does not take down the auth API when one provider's discovery is unreachable", async () => {
		mswServer.use(
			http.get(
				"https://broken-idp.test/.well-known/openid-configuration",
				() => new HttpResponse(null, { status: 503 }),
			),
		);
		const { auth } = await getTestInstance(
			{
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "broken-idp",
								clientId: "client",
								clientSecret: "secret",
								discoveryUrl:
									"https://broken-idp.test/.well-known/openid-configuration",
							},
							{
								providerId: "healthy-idp",
								clientId,
								clientSecret,
								discoveryUrl: `http://localhost:${port}/.well-known/openid-configuration`,
							},
						],
					}),
				],
			},
			{ disableTestUser: true },
		);

		const ctx = await auth.$context;
		const providerIds = ctx.socialProviders.map((provider) => provider.id);
		expect(providerIds).toContain("healthy-idp");
		expect(providerIds).not.toContain("broken-idp");

		const signUp = await auth.api.signUpEmail({
			body: {
				email: "isolated@example.test",
				password: "correct-horse-battery-staple",
				name: "Repro",
			},
		});
		expect(signUp.token).toEqual(expect.any(String));
	});;
});
