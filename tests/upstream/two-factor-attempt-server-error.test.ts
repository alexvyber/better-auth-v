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
	};;

	it("a server error during verification does not spend an attempt slot", async () => {
		const challengeHeaders = await startChallenge();
		const row = await db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: userId }],
		});
		const validSecret = row!.secret;

		// Corrupt the stored secret so verification throws a server error mid-flight
		// (not a wrong-code result); the attempt must actually error.
		await db.update({
			model: "twoFactor",
			where: [{ field: "userId", value: userId }],
			update: { secret: "not-a-valid-encrypted-secret" },
		});
		await expect(verifyTotp(challengeHeaders, "000000")).rejects.toThrow();

		// The slot was restored, so the same challenge still works once the
		// transient failure clears. Without the restore the consumed counter would
		// reject the correct code as an invalid two-factor cookie.
		await db.update({
			model: "twoFactor",
			where: [{ field: "userId", value: userId }],
			update: { secret: validSecret },
		});
		const ok = await verifyTotp(
			challengeHeaders,
			await createOTP(secret).totp(),
		);
		expect(ok.status).toBe(200);
	});
});
