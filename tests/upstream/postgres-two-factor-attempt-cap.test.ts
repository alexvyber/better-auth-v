// Generated from pinned upstream source; do not edit assertions here.
import type { BetterAuthOptions, GenericEndpointContext } from "@better-auth/core";
import type { SecondaryStorage } from "@better-auth/core/db";
import { createOTP } from "@better-auth/utils/otp";
import { describe, expect, it } from "vitest";
import { symmetricDecrypt } from "better-auth/crypto";
import { convertSetCookieToCookie } from "../harness/two-factor.js";
import { getTestInstance } from "../harness/postgres-fixture.js";
import type { User, Session, Verification } from "better-auth";
import { DEFAULT_SECRET } from "../harness/constants.js";
import { TWO_FACTOR_ERROR_CODES } from "better-auth/plugins/two-factor";
import type { TwoFactorOptions, TwoFactorTable, UserWithTwoFactor } from "better-auth/plugins/two-factor";
import { twoFactor } from "../harness/plugins.js";
const DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS = 5;

async function setupTwoFactorChallenge() {
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
	await auth.api.verifyTOTP({
		body: { code: await createOTP(secret).totp() },
		headers,
	});

	async function startChallenge(): Promise<Headers> {
		const signIn = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(signIn.status).toBe(200);
		return convertSetCookieToCookie(signIn.headers);
	}

	return {
		auth,
		db,
		userId,
		secret,
		backupCodes: enrollment.backupCodes,
		startChallenge,
	};
}

describe("two-factor security: TOTP enforces a per-challenge attempt cap", async () => {
	const { auth, db, userId, secret, startChallenge } =
		await setupTwoFactorChallenge();

	function verifyTotp(challengeHeaders: Headers, code: string) {
		return auth.api.verifyTOTP({
			body: { code },
			headers: challengeHeaders,
			asResponse: true,
		});
	}

	it("locks out after the limit and cancels the challenge", async () => {
		const challengeHeaders = await startChallenge();

		for (let i = 0; i < DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS; i++) {
			const res = await verifyTotp(challengeHeaders, "000000");
			expect(res.status).toBe(401);
			const json = (await res.json()) as { message: string };
			expect(json.message).toBe(TWO_FACTOR_ERROR_CODES.INVALID_CODE.message);
		}

		// Budget spent: even the correct code is locked out.
		const locked = await verifyTotp(
			challengeHeaders,
			await createOTP(secret).totp(),
		);
		expect(locked.status).toBe(400);
		const lockedJson = (await locked.json()) as { message: string };
		expect(lockedJson.message).toBe(
			TWO_FACTOR_ERROR_CODES.TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE.message,
		);

		// Lockout cancels the challenge itself, so a further attempt is no longer
		// a code check but an invalid (consumed) cookie.
		const afterLockout = await verifyTotp(challengeHeaders, "000000");
		expect(afterLockout.status).toBe(401);
		const afterJson = (await afterLockout.json()) as { message: string };
		expect(afterJson.message).toBe(
			TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE.message,
		);
	});

	it("a concurrent burst cannot exceed the attempt budget", async () => {
		const challengeHeaders = await startChallenge();
		const burst = DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS * 4;

		const results = await Promise.all(
			Array.from({ length: burst }, () =>
				verifyTotp(challengeHeaders, "111111"),
			),
		);
		const bodies = await Promise.all(
			results.map((res) => res.json() as Promise<{ message?: string }>),
		);
		// No wrong code mints a session.
		expect(results.some((res) => res.status === 200)).toBe(false);
		// The atomic consume gate serializes the burst, so at most the budget is
		// actually spent on guesses; the rest lose the race and are rejected.
		const processed = bodies.filter(
			(body) => body.message === TWO_FACTOR_ERROR_CODES.INVALID_CODE.message,
		).length;
		expect(processed).toBeLessThanOrEqual(DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS);
	});;
});

describe("two-factor security: backup codes enforce a per-challenge attempt cap", async () => {
	const { auth, backupCodes, startChallenge } = await setupTwoFactorChallenge();
	const backupCode = backupCodes?.[0];
	if (!backupCode) {
		throw new Error("expected backup codes from enrollment");
	}

	function verifyBackup(challengeHeaders: Headers, code: string) {
		return auth.api.verifyBackupCode({
			body: { code },
			headers: challengeHeaders,
			asResponse: true,
		});
	}

	it("counts wrong backup codes up to the limit then locks out", async () => {
		const challengeHeaders = await startChallenge();

		for (let i = 0; i < DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS; i++) {
			const res = await verifyBackup(challengeHeaders, "0000-0000");
			expect(res.status).toBe(401);
			const json = (await res.json()) as { message: string };
			expect(json.message).toBe(
				TWO_FACTOR_ERROR_CODES.INVALID_BACKUP_CODE.message,
			);
		}

		// Budget spent: even a real backup code is locked out.
		const locked = await verifyBackup(challengeHeaders, backupCode);
		expect(locked.status).toBe(400);
		const lockedJson = (await locked.json()) as { message: string };
		expect(lockedJson.message).toBe(
			TWO_FACTOR_ERROR_CODES.TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE.message,
		);
	});
});
