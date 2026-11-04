// Generated from pinned upstream source; do not edit assertions here.
import type { BetterAuthOptions, GenericEndpointContext } from "@better-auth/core";
import type { SecondaryStorage } from "@better-auth/core/db";
import { createOTP } from "@better-auth/utils/otp";
import { describe, expect, it } from "vitest";
import { symmetricDecrypt } from "better-auth/crypto";
import { convertSetCookieToCookie } from "../harness/two-factor.js";
import { getTestInstance } from "../harness/test-instance.js";
import type { User, Session, Verification } from "better-auth";
import { DEFAULT_SECRET } from "../harness/constants.js";
import { TWO_FACTOR_ERROR_CODES } from "better-auth/plugins/two-factor";
import type { TwoFactorOptions, TwoFactorTable, UserWithTwoFactor } from "better-auth/plugins/two-factor";
import { twoFactor } from "../harness/plugins.js";
const DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS = 5;

function extractSetCookies(res: Response): string[] {
	return res.headers.getSetCookie();
}

function buildCookieHeader(entries: string[], names: string[]): Headers {
	const headers = new Headers();
	const parts = entries
		.filter((entry) => names.some((n) => entry.startsWith(`${n}=`)))
		.filter((entry) => {
			const firstSegment = entry.split(";")[0] ?? "";
			const eq = firstSegment.indexOf("=");
			return eq > 0 && firstSegment.slice(eq + 1).length > 0;
		})
		.map((entry) => entry.split(";")[0]!);
	headers.set("cookie", parts.join("; "));
	return headers;
}

function getCookieValue(entry: string): string {
	const firstSegment = entry.split(";")[0] ?? "";
	const eq = firstSegment.indexOf("=");
	return eq > 0 ? firstSegment.slice(eq + 1) : "";
}

describe("two-factor security: sign-in does not leak session cookies (cookieCache disabled)", async () => {
	const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
		secret: DEFAULT_SECRET,
		plugins: [twoFactor()],
	});

	const { headers } = await signInWithTestUser();
	const enrollment = await auth.api.enableTwoFactor({
		body: { password: testUser.password },
		headers,
	});
	if (enrollment.method !== "totp") {
		throw new Error("expected totp enrollment");
	}
	const dbUser = await db.findOne<User>({
		model: "user",
		where: [{ field: "email", value: testUser.email }],
	});
	const userId = dbUser?.id as string;
	const row = await db.findOne<TwoFactorTable>({
		model: "twoFactor",
		where: [{ field: "userId", value: userId }],
	});
	const secret = await symmetricDecrypt({
		key: DEFAULT_SECRET,
		data: row!.secret,
	});
	const totpCode = await createOTP(secret).totp();
	await auth.api.verifyTOTP({ body: { code: totpCode }, headers });
	const verified = await db.findOne<UserWithTwoFactor>({
		model: "user",
		where: [{ field: "id", value: userId }],
	});
	if (!verified?.twoFactorEnabled) {
		throw new Error("failed to enable 2FA for test user");
	}

	it("response carries no valid signed session_token on 2FA-required sign-in", async () => {
		const res = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(res.status).toBe(200);

		const setCookies = extractSetCookies(res);
		const tokenEntries = setCookies.filter((entry) =>
			entry.startsWith("better-auth.session_token="),
		);
		for (const entry of tokenEntries) {
			expect(getCookieValue(entry)).toBe("");
		}
	});

	it("replaying any cookies captured from the response cannot authenticate", async () => {
		const res = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		const setCookies = extractSetCookies(res);
		const replay = buildCookieHeader(setCookies, [
			"better-auth.session_token",
			"better-auth.session_data",
		]);

		const session = await auth.api.getSession({ headers: replay });
		expect(session).toBeNull();
	});
});

describe("two-factor security: chunked session_data is fully scrubbed on 2FA-required sign-in", async () => {
	// Forces session_data to be chunked by inflating the user payload past 4KB,
	// verifies that the credential sign-in path actually emits chunks, then
	// asserts the 2FA-required sign-in response exposes no valid chunk value.
	// This pins the chunk-prefix branch of removeSetCookieEntries — without it,
	// a future tightening of the match (e.g. exact-only) could silently leak
	// `session_data.N` chunks while passing the non-chunked tests.
	const filler = "x".repeat(2200);
	const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
		secret: DEFAULT_SECRET,
		user: {
			additionalFields: {
				blob1: { type: "string", defaultValue: "" },
				blob2: { type: "string", defaultValue: "" },
			},
		},
		session: { cookieCache: { enabled: true } },
		plugins: [twoFactor()],
	});

	const { headers } = await signInWithTestUser();
	const dbUser = await db.findOne<User>({
		model: "user",
		where: [{ field: "email", value: testUser.email }],
	});
	const userId = dbUser?.id as string;
	await db.update({
		model: "user",
		where: [{ field: "id", value: userId }],
		update: { blob1: filler, blob2: filler },
	});

	const chunkProbeRes = await auth.api.signInEmail({
		body: { email: testUser.email, password: testUser.password },
		asResponse: true,
	});
	const chunkProbeEntries = extractSetCookies(chunkProbeRes).filter((entry) =>
		entry.startsWith("better-auth.session_data."),
	);

	const enrollment = await auth.api.enableTwoFactor({
		body: { password: testUser.password },
		headers,
	});
	if (enrollment.method !== "totp") {
		throw new Error("expected totp enrollment");
	}
	const row = await db.findOne<TwoFactorTable>({
		model: "twoFactor",
		where: [{ field: "userId", value: userId }],
	});
	const secret = await symmetricDecrypt({
		key: DEFAULT_SECRET,
		data: row!.secret,
	});
	const totpCode = await createOTP(secret).totp();
	await auth.api.verifyTOTP({ body: { code: totpCode }, headers });

	it("test setup exercises chunked session_data cookies", () => {
		expect(chunkProbeRes.status).toBe(200);
		expect(chunkProbeEntries.length).toBeGreaterThan(0);
	});

	it("no session_data.N chunk leaks a non-empty value and replay cannot authenticate", async () => {
		const res = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(res.status).toBe(200);

		const setCookies = extractSetCookies(res);

		// Pre-fix, the credential handler emits `session_data.0=<valid>` and
		// `session_data.1=<valid>` (the chunking debug log fires above) and the
		// after-hook only appends an expiring single `session_data=`. The scrub
		// in `removeSetCookieEntries` (chunk-prefix branch) deletes every
		// `session_data.*` entry, so either none survive OR any that do must
		// carry an empty value.
		const chunkEntries = setCookies.filter((entry) =>
			entry.startsWith("better-auth.session_data."),
		);
		for (const entry of chunkEntries) {
			expect(getCookieValue(entry)).toBe("");
		}

		const tokenEntries = setCookies.filter((entry) =>
			entry.startsWith("better-auth.session_token="),
		);
		for (const entry of tokenEntries) {
			expect(getCookieValue(entry)).toBe("");
		}

		// Replay covers the regression case too: even if the chunk-prefix scrub
		// silently regresses and `session_data.N=<valid>` leaks back, the cookie
		// cache would reconstruct a valid session here and this assertion fails.
		const replay = new Headers();
		const parts: string[] = [];
		for (const entry of setCookies) {
			if (
				!entry.startsWith("better-auth.session_token=") &&
				!entry.startsWith("better-auth.session_data=") &&
				!entry.startsWith("better-auth.session_data.")
			) {
				continue;
			}
			const firstSegment = entry.split(";")[0] ?? "";
			const eq = firstSegment.indexOf("=");
			if (eq <= 0) continue;
			const value = firstSegment.slice(eq + 1);
			if (value.length === 0) continue;
			parts.push(firstSegment);
		}
		replay.set("cookie", parts.join("; "));

		const session = await auth.api.getSession({ headers: replay });
		expect(session).toBeNull();
	});
});

describe("two-factor security: 2FA challenge is single-use and expiry-bounded", async () => {
	const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
		secret: DEFAULT_SECRET,
		plugins: [twoFactor()],
	});

	const { headers } = await signInWithTestUser();
	const dbUser = await db.findOne<User>({
		model: "user",
		where: [{ field: "email", value: testUser.email }],
	});
	const userId = dbUser?.id as string;

	const enrollment = await auth.api.enableTwoFactor({
		body: { password: testUser.password },
		headers,
	});
	if (enrollment.method !== "totp") {
		throw new Error("expected totp enrollment");
	}
	const row = await db.findOne<TwoFactorTable>({
		model: "twoFactor",
		where: [{ field: "userId", value: userId }],
	});
	const secret = await symmetricDecrypt({
		key: DEFAULT_SECRET,
		data: row!.secret,
	});
	const enrollCode = await createOTP(secret).totp();
	await auth.api.verifyTOTP({ body: { code: enrollCode }, headers });
	const verified = await db.findOne<UserWithTwoFactor>({
		model: "user",
		where: [{ field: "id", value: userId }],
	});
	if (!verified?.twoFactorEnabled) {
		throw new Error("failed to enable 2FA for test user");
	}

	async function startChallenge(): Promise<Headers> {
		const res = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(res.status).toBe(200);
		return convertSetCookieToCookie(res.headers);
	}

	function countSessions(): Promise<Session[]> {
		return db.findMany<Session>({
			model: "session",
			where: [{ field: "userId", value: userId }],
		});
	}

	it("rejects an expired two-factor sign-in challenge even with a valid TOTP", async () => {
		const challengeHeaders = await startChallenge();
		const challengeRow = await db.findOne<Verification>({
			model: "verification",
			where: [{ field: "value", value: userId }],
		});
		expect(challengeRow).not.toBeNull();

		// Force the challenge past its expiry while leaving the row present, so
		// the only thing standing between a stale cookie and a session is the
		// server-side expiry gate.
		await db.update({
			model: "verification",
			where: [{ field: "id", value: challengeRow!.id }],
			update: { expiresAt: new Date(Date.now() - 60 * 1000) },
		});

		const sessionsBefore = await countSessions();
		const freshCode = await createOTP(secret).totp();
		const res = await auth.api.verifyTOTP({
			body: { code: freshCode },
			headers: challengeHeaders,
			asResponse: true,
		});

		expect(res.status).toBe(401);
		const json = (await res.json()) as { message: string };
		expect(json.message).toBe(
			TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE.message,
		);

		const setCookies = res.headers.getSetCookie();
		const tokenEntries = setCookies.filter((entry) =>
			entry.startsWith("better-auth.session_token="),
		);
		for (const entry of tokenEntries) {
			const firstSegment = entry.split(";")[0] ?? "";
			const eq = firstSegment.indexOf("=");
			expect(eq > 0 ? firstSegment.slice(eq + 1) : "").toBe("");
		}

		const sessionsAfter = await countSessions();
		expect(sessionsAfter.length).toBe(sessionsBefore.length);
	});

	it("two concurrent verifications of the same challenge yield exactly one session", async () => {
		const challengeHeaders = await startChallenge();
		const sessionsBefore = await countSessions();
		const code = await createOTP(secret).totp();

		const [first, second] = await Promise.all([
			auth.api.verifyTOTP({
				body: { code },
				headers: challengeHeaders,
				asResponse: true,
			}),
			auth.api.verifyTOTP({
				body: { code },
				headers: challengeHeaders,
				asResponse: true,
			}),
		]);

		const statuses = [first.status, second.status].sort();
		expect(statuses).toEqual([200, 401]);

		const sessionsAfter = await countSessions();
		expect(sessionsAfter.length).toBe(sessionsBefore.length + 1);
	});
});

describe("two-factor security: OTP attempts are atomic under concurrency", async () => {
	const allowedAttempts = 3;
	let currentOTP = "";

	// A secondary storage whose normal reads of the OTP row are deliberately
	// slow while `getAndDelete` is immediate. Without an atomic consume gate,
	// every concurrent verification could finish a slow read of the same
	// counter before any write lands. The fix consumes the row through the
	// required storage primitive, so each attempt observes a distinct counter.
	const store = new Map<string, { value: string; expiresAt: number }>();
	const isOtpRow = (key: string) => key.includes("2fa-otp");
	const secondaryStorage: SecondaryStorage = {
		async get(key: string) {
			if (isOtpRow(key)) {
				await new Promise((resolve) => setTimeout(resolve, 25));
			}
			const entry = store.get(key);
			if (!entry) return null;
			if (entry.expiresAt < Date.now()) {
				store.delete(key);
				return null;
			}
			return entry.value;
		},
		async getAndDelete(key: string) {
			const entry = store.get(key);
			store.delete(key);
			if (!entry || entry.expiresAt < Date.now()) {
				return null;
			}
			return entry.value;
		},
		async increment(key: string, ttl: number) {
			const entry = store.get(key);
			const count = Number(entry?.value ?? 0) + 1;
			store.set(key, {
				value: String(count),
				expiresAt: Date.now() + ttl * 1000,
			});
			return count;
		},
		async set(key: string, value: string, ttl?: number) {
			store.set(key, {
				value,
				expiresAt: Date.now() + (ttl ?? 60) * 1000,
			});
		},
		async delete(key: string) {
			store.delete(key);
		},
	};

	const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
		secret: DEFAULT_SECRET,
		secondaryStorage,
		plugins: [
			twoFactor({
				otpOptions: {
					allowedAttempts,
					sendOTP({ otp }) {
						currentOTP = otp;
					},
				},
			}),
		],
	});

	const { headers } = await signInWithTestUser();
	const dbUser = await db.findOne<User>({
		model: "user",
		where: [{ field: "email", value: testUser.email }],
	});
	const userId = dbUser?.id as string;

	const enrollment = await auth.api.enableTwoFactor({
		body: { password: testUser.password },
		headers,
	});
	if (enrollment.method !== "totp") {
		throw new Error("expected totp enrollment");
	}
	const row = await db.findOne<TwoFactorTable>({
		model: "twoFactor",
		where: [{ field: "userId", value: userId }],
	});
	const secret = await symmetricDecrypt({
		key: DEFAULT_SECRET,
		data: row!.secret,
	});
	const enrollCode = await createOTP(secret).totp();
	await auth.api.verifyTOTP({ body: { code: enrollCode }, headers });
	const verified = await db.findOne<UserWithTwoFactor>({
		model: "user",
		where: [{ field: "id", value: userId }],
	});
	if (!verified?.twoFactorEnabled) {
		throw new Error("failed to enable 2FA for test user");
	}

	async function startChallengeWithOtp(): Promise<Headers> {
		const signIn = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(signIn.status).toBe(200);
		const challengeHeaders = convertSetCookieToCookie(signIn.headers);
		await auth.api.sendTwoFactorOTP({ headers: challengeHeaders });
		return challengeHeaders;
	}

	function verifyOtp(
		challengeHeaders: Headers,
		code: string,
	): Promise<Response> {
		return auth.api.verifyTwoFactorOTP({
			body: { code },
			headers: challengeHeaders,
			asResponse: true,
		});
	}

	it("counts wrong guesses up to the limit then locks out", async () => {
		const challengeHeaders = await startChallengeWithOtp();

		for (let i = 0; i < allowedAttempts; i++) {
			const res = await verifyOtp(challengeHeaders, "000000");
			expect(res.status).toBe(401);
			const json = (await res.json()) as { message: string };
			expect(json.message).toBe(TWO_FACTOR_ERROR_CODES.INVALID_CODE.message);
		}

		// The budget is spent: even the correct code is locked out.
		const locked = await verifyOtp(challengeHeaders, currentOTP);
		expect(locked.status).toBe(400);
		const lockedJson = (await locked.json()) as { message: string };
		expect(lockedJson.message).toBe(
			TWO_FACTOR_ERROR_CODES.TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE.message,
		);
	});

	it("a concurrent burst of wrong guesses cannot exceed the attempt budget", async () => {
		const challengeHeaders = await startChallengeWithOtp();
		const burst = allowedAttempts * 4;

		const results = await Promise.all(
			Array.from({ length: burst }, () =>
				verifyOtp(challengeHeaders, "111111"),
			),
		);
		const bodies = await Promise.all(
			results.map((res) => res.json() as Promise<{ message?: string }>),
		);

		const invalidCount = bodies.filter(
			(body) => body.message === TWO_FACTOR_ERROR_CODES.INVALID_CODE.message,
		).length;

		// Each wrong guess consumes exactly one counter slot, so no matter how
		// many race in at once the number of accepted guesses is capped by the
		// budget. The remaining racers lose the consume and are rejected.
		expect(invalidCount).toBeLessThanOrEqual(allowedAttempts);
	});

	it("concurrent correct codes mint at most one session", async () => {
		const challengeHeaders = await startChallengeWithOtp();

		const results = await Promise.all([
			verifyOtp(challengeHeaders, currentOTP),
			verifyOtp(challengeHeaders, currentOTP),
			verifyOtp(challengeHeaders, currentOTP),
		]);
		// Only the racer that wins the OTP consume may complete; the others lose
		// the consume and never reach session creation, so at most one 200.
		const successCount = results.filter((res) => res.status === 200).length;
		expect(successCount).toBeLessThanOrEqual(1);
	});
});
