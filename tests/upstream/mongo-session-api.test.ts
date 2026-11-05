// Generated from pinned upstream source; do not edit assertions here.
import { afterEach, beforeEach, describe, expect, expectTypeOf, it, test, onTestFinished, vi } from "vitest";
import type { GenericEndpointContext } from "@better-auth/core";
import { runWithEndpointContext, runWithRequestState } from "@better-auth/core/context";
import { parseCookies, parseSetCookieHeader } from "better-auth/cookies";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { jwt, admin, organization } from "../harness/plugins.js";
import { signJWT, verifyJWT } from "better-auth/crypto";
import { memoryAdapter } from "../harness/memory-adapter.js";
import { createAuthEndpoint, freshSessionMiddleware } from "../harness/endpoint.js";
import { getSessionFromCtx, getAuthoritativeSessionFromCtx } from "../harness/session.js";
import { getDate } from "../harness/date.js";
import { getTestInstance } from "../harness/mongo-fixture.js";

const COOKIE_CACHE_JWT_TYPE = "better-auth.session-cache+jwt";

const COOKIE_CACHE_JWT_AUDIENCE = "better-auth:session-cache";

describe("session", async () => {
	const { client, testUser, sessionSetter, cookieSetter, auth } =
		await getTestInstance();

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should set cookies correctly on sign in", async () => {
		const headers = new Headers();
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				onSuccess(context) {
					const header = context.response.headers.get("set-cookie");
					const cookies = parseSetCookieHeader(header || "");
					cookieSetter(headers)(context);
					const cookie = cookies.get("better-auth.session_token");
					expect(cookie).toMatchObject({
						value: expect.any(String),
						"max-age": 60 * 60 * 24 * 7,
						path: "/",
						samesite: "lax",
						httponly: true,
					});
				},
			},
		);
		const { data } = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		const expiresAt = new Date(data?.session.expiresAt || "");
		const now = new Date();

		expect(expiresAt.getTime()).toBeGreaterThan(
			now.getTime() + 6 * 24 * 60 * 60 * 1000,
		);
	});

	it("should return null when not authenticated", async () => {
		const response = await client.getSession();
		expect(response.data).toBeNull();
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/11327
	 */
	it("should keep the store failure as a server-only cause", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			logger: { disabled: true },
		});
		const { headers } = await signInWithTestUser();
		const { adapter } = await auth.$context;
		const findOne = adapter.findOne.bind(adapter);
		const cause = {
			code: "STORE_UNAVAILABLE",
			detail: "Private store details",
		};
		vi.spyOn(adapter, "findOne").mockImplementation(async (input) => {
			if (input.model === "session") throw cause;
			return findOne(input);
		});

		await expect(auth.api.getSession({ headers })).rejects.toMatchObject({
			status: "INTERNAL_SERVER_ERROR",
			body: { code: "FAILED_TO_GET_SESSION", message: "Failed to get session" },
			cause,
		});

		const response = await auth.handler(
			new Request("http://localhost:3000/api/auth/get-session", { headers }),
		);
		expect(response.status).toBe(500);
		await expect(response.json()).resolves.toEqual({
			code: "FAILED_TO_GET_SESSION",
			message: "Failed to get session",
		});
	});

	it("should require a fresh session based on session creation time", async () => {
		vi.useFakeTimers();
		const now = new Date("2026-01-01T00:00:00.000Z");
		vi.setSystemTime(now);

		const freshSessionPlugin = {
			id: "fresh-session-test",
			endpoints: {
				freshSessionCheck: createAuthEndpoint(
					"/fresh-session-check",
					{
						method: "GET",
						use: [freshSessionMiddleware],
					},
					async () => ({ status: true }),
				),
			},
		};
		const { auth, client, signInWithTestUser, db } = await getTestInstance({
			session: {
				freshAge: 60,
			},
			plugins: [freshSessionPlugin],
		});

		const { headers } = await signInWithTestUser();
		const currentSession = await auth.api.getSession({ headers });
		const sessionId = currentSession?.session.id;
		expect(sessionId).toBeDefined();

		await db.update({
			model: "session",
			where: [
				{
					field: "id",
					value: sessionId!,
				},
			],
			update: {
				createdAt: new Date(now.getTime() - 5 * 60 * 1000),
				updatedAt: now,
			},
		});

		const response = await client.$fetch("/fresh-session-check", {
			method: "GET",
			headers,
		});
		expect(response.data).toBeNull();
		expect(response.error).toMatchObject({
			status: 403,
			statusText: "FORBIDDEN",
			code: "SESSION_NOT_FRESH",
		});
	});

	it("should require a fresh session to list sessions", async () => {
		vi.useFakeTimers();
		const now = new Date("2026-01-01T00:00:00.000Z");
		vi.setSystemTime(now);

		const { client, signInWithTestUser, db } = await getTestInstance({
			session: {
				freshAge: 60,
			},
		});

		const { headers } = await signInWithTestUser();
		const currentSession = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		const sessionId = currentSession.data?.session.id;
		expect(sessionId).toBeDefined();

		await db.update({
			model: "session",
			where: [
				{
					field: "id",
					value: sessionId!,
				},
			],
			update: {
				createdAt: new Date(now.getTime() - 5 * 60 * 1000),
				updatedAt: now,
			},
		});

		const response = await client.listSessions({
			fetchOptions: {
				headers,
			},
		});
		expect(response.data).toBeNull();
		expect(response.error).toMatchObject({
			status: 403,
			statusText: "FORBIDDEN",
			code: "SESSION_NOT_FRESH",
		});
	});

	describe("session refresh and expiration", () => {
		const startedAt = new Date("2026-01-01T00:00:00Z").getTime();

		beforeEach(() => {
			vi.setSystemTime(startedAt);
		});

		it.each([
			{ elapsedSeconds: 0, expiresAfterSeconds: 120, cookieMaxAge: undefined },
			{ elapsedSeconds: 59, expiresAfterSeconds: 120, cookieMaxAge: undefined },
			{ elapsedSeconds: 60, expiresAfterSeconds: 180, cookieMaxAge: 120 },
			{ elapsedSeconds: 61, expiresAfterSeconds: 181, cookieMaxAge: 120 },
		])(
			"returns the expected session expiration after $elapsedSeconds seconds",
			async ({ elapsedSeconds, expiresAfterSeconds, cookieMaxAge }) => {
				const { client, signInWithTestUser } = await getTestInstance({
					session: {
						updateAge: 60,
						expiresIn: 120,
					},
				});
				const { headers } = await signInWithTestUser();

				vi.setSystemTime(startedAt + elapsedSeconds * 1000);
				const response = await client.getSession({
					fetchOptions: {
						headers,
						onSuccess(context) {
							const cookies = parseSetCookieHeader(
								context.response.headers.get("set-cookie") || "",
							);
							expect(
								cookies.get("better-auth.session_token")?.["max-age"],
							).toBe(cookieMaxAge);
						},
					},
				});

				expect(response.error).toBeNull();
				expect(response.data).not.toBeNull();
				expect(new Date(response.data!.session.expiresAt).getTime()).toBe(
					startedAt + expiresAfterSeconds * 1000,
				);
			},
		);

		it("persists successive session refreshes beyond the original expiration", async () => {
			const { client, signInWithTestUser } = await getTestInstance({
				session: {
					updateAge: 60,
					expiresIn: 120,
				},
			});
			const { headers } = await signInWithTestUser();
			const initial = await client.getSession({ fetchOptions: { headers } });
			expect(initial.data).not.toBeNull();
			expect(new Date(initial.data!.session.expiresAt).getTime()).toBe(
				startedAt + 120_000,
			);

			for (const elapsedSeconds of [60, 140, 240]) {
				vi.setSystemTime(startedAt + elapsedSeconds * 1000);
				const response = await client.getSession({
					fetchOptions: {
						headers,
						onSuccess(context) {
							const cookies = parseSetCookieHeader(
								context.response.headers.get("set-cookie") || "",
							);
							expect(
								cookies.get("better-auth.session_token")?.["max-age"],
							).toBe(120);
						},
					},
				});

				expect(response.error).toBeNull();
				expect(response.data?.session.id).toBe(initial.data!.session.id);
				expect(new Date(response.data!.session.expiresAt).getTime()).toBe(
					startedAt + (elapsedSeconds + 120) * 1000,
				);
			}

			vi.setSystemTime(startedAt + 361_000);
			const response = await client.getSession({
				fetchOptions: {
					headers,
					onSuccess(context) {
						const cookies = parseSetCookieHeader(
							context.response.headers.get("set-cookie") || "",
						);
						expect(cookies.get("better-auth.session_token")?.["max-age"]).toBe(
							0,
						);
					},
				},
			});

			expect(response.error).toBeNull();
			expect(response.data).toBeNull();
		});

		it("clears an expired session without refreshing it", async () => {
			const { client, signInWithTestUser } = await getTestInstance({
				session: {
					updateAge: 60,
					expiresIn: 120,
				},
			});
			const { headers } = await signInWithTestUser();

			vi.setSystemTime(startedAt + 121_000);
			const response = await client.getSession({
				fetchOptions: {
					headers,
					onSuccess(context) {
						const cookies = parseSetCookieHeader(
							context.response.headers.get("set-cookie") || "",
						);
						expect(cookies.get("better-auth.session_token")?.["max-age"]).toBe(
							0,
						);
					},
				},
			});

			expect(response.error).toBeNull();
			expect(response.data).toBeNull();
		});
	});

	it("should update the session every time when set to 0", async () => {
		const { client, signInWithTestUser } = await getTestInstance({
			session: {
				updateAge: 0,
			},
		});
		const { runWithUser } = await signInWithTestUser();

		await runWithUser(async () => {
			const session = await client.getSession();

			vi.useFakeTimers();
			await vi.advanceTimersByTimeAsync(1000 * 60 * 5);
			const session2 = await client.getSession();
			expect(session2.data?.session.expiresAt).not.toBe(
				session.data?.session.expiresAt,
			);
			expect(
				new Date(session2.data!.session.expiresAt).getTime(),
			).toBeGreaterThan(new Date(session.data!.session.expiresAt).getTime());
		});
	});

	it("should handle 'don't remember me' option", async () => {
		const headers = new Headers();
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
				rememberMe: false,
			},
			{
				onSuccess: cookieSetter(headers),
			},
		);
		const data = await client.getSession({
			fetchOptions: {
				headers,
				throw: true,
			},
		});
		if (!data) {
			throw new Error("No session found");
		}
		const expiresAt = data.session.expiresAt;
		expect(new Date(expiresAt).valueOf()).toBeLessThanOrEqual(
			getDate(1000 * 60 * 60 * 24).valueOf(),
		);
		const response = await client.getSession({
			fetchOptions: {
				headers,
			},
		});

		if (!response.data?.session) {
			throw new Error("No session found");
		}
		// Check that the session wasn't update
		expect(
			new Date(response.data.session.expiresAt).valueOf(),
		).toBeLessThanOrEqual(getDate(1000 * 60 * 60 * 24).valueOf());
	});

	it("should set cookies correctly on sign in after changing config", async () => {
		const headers = new Headers();
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				onSuccess(context) {
					const header = context.response.headers.get("set-cookie");
					const cookies = parseSetCookieHeader(header || "");
					expect(cookies.get("better-auth.session_token")).toMatchObject({
						value: expect.any(String),
						"max-age": 60 * 60 * 24 * 7,
						path: "/",
						httponly: true,
						samesite: "lax",
					});
					cookieSetter(headers)(context);
				},
			},
		);
		const data = await client.getSession({
			fetchOptions: {
				headers,
				throw: true,
			},
		});
		if (!data) {
			throw new Error("No session found");
		}
		const expiresAt = new Date(data?.session?.expiresAt || "");
		const now = new Date();

		expect(expiresAt.getTime()).toBeGreaterThan(
			now.getTime() + 6 * 24 * 60 * 60 * 1000,
		);
	});

	it("should clear session on sign out", async () => {
		const headers = new Headers();
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				onSuccess: cookieSetter(headers),
			},
		);
		const data = await client.getSession({
			fetchOptions: {
				headers,
				throw: true,
			},
		});

		expect(data).not.toBeNull();
		await client.signOut({
			fetchOptions: {
				headers,
			},
		});
		const response = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(response.data);
	});

	it("should list sessions", async () => {
		const headers = new Headers();
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				onSuccess: sessionSetter(headers),
			},
		);

		const response = await client.listSessions({
			fetchOptions: {
				headers,
			},
		});

		expect(response.data?.length).toBeGreaterThan(1);
	});

	it("should revoke session", async () => {
		const headers = new Headers();
		const headers2 = new Headers();
		await client.signIn.email({
			email: testUser.email,
			password: testUser.password,
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});
		await client.signIn.email({
			email: testUser.email,
			password: testUser.password,
			fetchOptions: {
				onSuccess: sessionSetter(headers2),
			},
		});
		const session = await client.getSession({
			fetchOptions: {
				headers,
				throw: true,
			},
		});
		await client.revokeSession({
			fetchOptions: {
				headers,
			},
			token: session?.session?.token || "",
		});
		const newSession = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(newSession.data).toBeNull();
		const revokeRes = await client.revokeSessions({
			fetchOptions: {
				headers: headers2,
			},
		});
		expect(revokeRes.data?.status).toBe(true);
	});

	it("should return session headers", async () => {
		const context = await auth.$context;
		await runWithEndpointContext(
			{
				context,
			} as unknown as GenericEndpointContext,
			async () => {
				const signInRes = await auth.api.signInEmail({
					body: {
						email: testUser.email,
						password: testUser.password,
					},
					returnHeaders: true,
				});

				const signInHeaders = new Headers();
				signInHeaders.set("cookie", signInRes.headers.getSetCookie()[0]!);

				const sessionResWithoutHeaders = await auth.api.getSession({
					headers: signInHeaders,
				});

				const sessionResWithHeaders = await auth.api.getSession({
					headers: signInHeaders,
					returnHeaders: true,
				});

				expect(sessionResWithHeaders.headers).toBeDefined();
				expect(sessionResWithHeaders.response?.user).toBeDefined();
				expect(sessionResWithHeaders.response?.session).toBeDefined();
				expectTypeOf({
					headers: sessionResWithHeaders.headers,
				}).toMatchObjectType<{
					headers: Headers;
				}>();

				// @ts-expect-error: headers should not exist on sessionResWithoutHeaders
				expect(sessionResWithoutHeaders.headers).toBeUndefined();

				const sessionResWithHeadersAndAsResponse = await auth.api.getSession({
					headers: signInHeaders,
					returnHeaders: true,
					asResponse: true,
				});

				expectTypeOf({
					res: sessionResWithHeadersAndAsResponse,
				}).toMatchObjectType<{ res: Response }>();

				expect(sessionResWithHeadersAndAsResponse.ok).toBe(true);
				expect(sessionResWithHeadersAndAsResponse.status).toBe(200);
			},
		);
	});

	/**
   @see https://github.com/better-auth/better-auth/issues/9609
   */
	it("should not exceed the 400-day browser Max-Age ceiling on session refresh", async () => {
		const BROWSER_MAX_AGE_CEILING = 400 * 24 * 60 * 60;
		const { client, testUser, cookieSetter } = await getTestInstance({
			session: {
				expiresIn: BROWSER_MAX_AGE_CEILING,
				updateAge: 30,
			},
		});

		const headers = new Headers();
		await client.signIn.email(
			{ email: testUser.email, password: testUser.password },
			{ onSuccess: cookieSetter(headers) },
		);

		vi.useFakeTimers();
		await vi.advanceTimersByTimeAsync(1000 * 31);

		let refreshedMaxAge: number | undefined;
		await client.getSession({
			fetchOptions: {
				headers,
				onSuccess(context) {
					cookieSetter(headers)(context);
					const parsed = parseSetCookieHeader(
						context.response.headers.get("set-cookie") || "",
					);
					refreshedMaxAge = parsed.get("better-auth.session_token")?.[
						"max-age"
					];
				},
			},
		});

		expect(refreshedMaxAge).toBeDefined();
		expect(refreshedMaxAge).toBeLessThanOrEqual(BROWSER_MAX_AGE_CEILING);
	});
});

const refreshCacheTest = test.extend(
	"cachedSession",
	async ({}, { onCleanup }) => {
		const { auth, client, testUser, cookieSetter } = await getTestInstance({
			session: {
				cookieCache: {
					enabled: true,
					strategy: "jwe",
					maxAge: 300,
					refreshCache: { updateAge: 60 },
				},
			},
		});
		const headers = new Headers();
		await client.signIn.email(
			{ email: testUser.email, password: testUser.password },
			{ onSuccess: cookieSetter(headers), throw: true },
		);
		const context = await auth.$context;
		const findOne = vi.spyOn(context.adapter, "findOne");
		onCleanup(() => findOne.mockRestore());

		return { client, headers, cookieSetter, findOne };
	},
);
