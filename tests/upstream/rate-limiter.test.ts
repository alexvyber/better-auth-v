// Generated from pinned upstream source; do not edit assertions here.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../harness/test-instance.js";

describe("rate-limiter", async () => {
	const { client, testUser } = await getTestInstance({
		rateLimit: {
			enabled: true,
			window: 10,
			max: 20,
		},
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/11463
	 */
	it("should send JSON content type for rate limit responses", async () => {
		const { auth } = await getTestInstance(
			{ rateLimit: { enabled: true, window: 10, max: 1 } },
			{ disableTestUser: true },
		);
		const request = () =>
			new Request("http://localhost:3000/api/auth/get-session", {
				headers: { "x-forwarded-for": "203.0.113.114" },
			});

		const first = await auth.handler(request());
		expect(first.status).toBe(200);

		const limited = await auth.handler(request());
		expect(limited.status).toBe(429);
		expect(limited.headers.get("content-type")).toBe("application/json");
		expect(limited.headers.get("x-retry-after")).toBeTruthy();
		expect(await limited.json()).toEqual({
			message: "Too many requests. Please try again later.",
		});
	});

	it("should return 429 after 3 request for sign-in", async () => {
		for (let i = 0; i < 5; i++) {
			const response = await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
			});
			if (i >= 3) {
				expect(response.error?.status).toBe(429);
			} else {
				expect(response.error).toBeNull();
			}
		}
	});

	it("should reset the limit after the window period", async () => {
		vi.useFakeTimers();
		vi.advanceTimersByTime(11000);
		for (let i = 0; i < 5; i++) {
			const res = await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
			});
			if (i >= 3) {
				expect(res.error?.status).toBe(429);
			} else {
				expect(res.error).toBeNull();
			}
		}
	});

	it("should respond the correct retry-after header", async () => {
		vi.useFakeTimers();
		vi.advanceTimersByTime(3000);
		let retryAfter = "";
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				onError(context) {
					retryAfter = context.response.headers.get("X-Retry-After") ?? "";
				},
			},
		);
		expect(retryAfter).toBe("7");
	});

	it("should rate limit based on the path", async () => {
		const signInRes = await client.signIn.email({
			email: testUser.email,
			password: testUser.password,
		});
		expect(signInRes.error?.status).toBe(429);

		const signUpRes = await client.signUp.email({
			email: "new-test@email.com",
			password: testUser.password,
			name: "test",
		});
		expect(signUpRes.error).toBeNull();
	});

	it("non-special-rules limits", async () => {
		for (let i = 0; i < 25; i++) {
			const response = await client.getSession();
			expect(response.error?.status).toBe(i >= 20 ? 429 : undefined);
		}
	});

	it("query params should be ignored", async () => {
		for (let i = 0; i < 25; i++) {
			const response = await client.listSessions({
				fetchOptions: {
					query: {
						"test-query": Math.random().toString(),
					},
				},
			});

			if (i >= 20) {
				expect(response.error?.status).toBe(429);
			} else {
				expect(response.error?.status).toBe(401);
			}
		}
	});
});

describe("atomic concurrent enforcement", () => {
	for (const storage of ["memory", "database"] as const) {
		describe(`${storage} storage`, async () => {
			const { client, testUser } = await getTestInstance({
				rateLimit: {
					enabled: true,
					storage,
					customRules: {
						"/sign-in/email": { window: 10, max: 1 },
					},
				},
			});

			// The memory backend keeps a process-global store shared across test
			// instances. Fake timers let each case advance the clock far past any
			// prior 10s window so it starts from a clean window for this key. Each
			// case advances by a distinct offset so frozen fake clocks across cases
			// never collide on the same instant.
			afterEach(() => {
				vi.useRealTimers();
			});

			it("lets exactly one of two simultaneous requests through", async () => {
				vi.useFakeTimers();
				vi.advanceTimersByTime(120000);
				const [a, b] = await Promise.all([
					client.signIn.email({
						email: testUser.email,
						password: testUser.password,
					}),
					client.signIn.email({
						email: testUser.email,
						password: testUser.password,
					}),
				]);
				const statuses = [a.error?.status, b.error?.status].sort();
				expect(statuses).toEqual([429, undefined]);
			});

			it("resets the count once the window elapses", async () => {
				vi.useFakeTimers();
				vi.advanceTimersByTime(240000);
				// Exhaust the max=1 budget, confirm the next request is blocked.
				const first = await client.signIn.email({
					email: testUser.email,
					password: testUser.password,
				});
				expect(first.error?.status).not.toBe(429);
				const blocked = await client.signIn.email({
					email: testUser.email,
					password: testUser.password,
				});
				expect(blocked.error?.status).toBe(429);

				vi.advanceTimersByTime(11000);
				const allowed = await client.signIn.email({
					email: testUser.email,
					password: testUser.password,
				});
				expect(allowed.error?.status).not.toBe(429);
			});

			it("resets the count at the exact window boundary", async () => {
				vi.useFakeTimers();
				vi.advanceTimersByTime(360000);
				const first = await client.signIn.email({
					email: testUser.email,
					password: testUser.password,
				});
				expect(first.error?.status).not.toBe(429);
				const blocked = await client.signIn.email({
					email: testUser.email,
					password: testUser.password,
				});
				expect(blocked.error?.status).toBe(429);

				vi.advanceTimersByTime(10000);
				const allowed = await client.signIn.email({
					email: testUser.email,
					password: testUser.password,
				});
				expect(allowed.error?.status).not.toBe(429);
			});
		});
	}
});

describe("should work with custom rules", async () => {
	const { client, testUser } = await getTestInstance({
		rateLimit: {
			enabled: true,
			storage: "database",
			customRules: {
				"/sign-in/*": {
					window: 10,
					max: 2,
				},
				"/sign-up/email": {
					window: 10,
					max: 3,
				},
				"/get-session": false,
			},
		},
	});

	it("should use custom rules", async () => {
		for (let i = 0; i < 4; i++) {
			const response = await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
			});
			if (i >= 2) {
				expect(response.error?.status).toBe(429);
			} else {
				expect(response.error).toBeNull();
			}
		}

		for (let i = 0; i < 5; i++) {
			const response = await client.signUp.email({
				email: `${Math.random()}@test.com`,
				password: testUser.password,
				name: "test",
			});
			if (i >= 3) {
				expect(response.error?.status).toBe(429);
			} else {
				expect(response.error).toBeNull();
			}
		}
	});

	it("should use default rules if custom rules are not defined", async () => {
		for (let i = 0; i < 5; i++) {
			const response = await client.getSession();
			if (i >= 20) {
				expect(response.error?.status).toBe(429);
			} else {
				expect(response.error).toBeNull();
			}
		}
	});

	it("should not rate limit if custom rule is false", async () => {
		let i = 0;
		let response = null;
		for (; i < 110; i++) {
			response = await client.getSession().then((res) => res.error);
		}
		expect(response).toBeNull();
		expect(i).toBe(110);
	});
});
