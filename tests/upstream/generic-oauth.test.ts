// Generated from pinned upstream source; do not edit assertions here.
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
	};;;;;;;;;;;;;;;

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
	});;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

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
	});;;;;;;

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
