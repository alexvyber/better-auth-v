// Generated from pinned upstream source; do not edit assertions here.
import type { AuthContext, GenericEndpointContext } from "@better-auth/core";
import type { JWTPayload } from "jose";
import { decodeProtectedHeader } from "jose";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../harness/test-instance.js";
import { jwt } from "../harness/plugins.js";
import { getJwksAdapter, signJWT, generateExportedKeyPair } from "../harness/jwt.js";
import type { JWSAlgorithms, Jwk } from "better-auth/plugins/jwt";

type AuthContextShim = AuthContext;

const asShim = (ctx: unknown): AuthContextShim => ctx as AuthContextShim;

async function provisionKey(
	ctx: AuthContextShim,
	alg: JWSAlgorithms,
): Promise<Jwk> {
	// Use the production keypair generator so each test key has a real
	// public/private pair compatible with `importJWK`. `generateExportedKeyPair`
	// fills in sensible `crv`/`modulusLength` defaults from the alg.
	const { publicWebKey, privateWebKey } = await generateExportedKeyPair({
		jwks: { keyPairConfig: { alg } as never },
	});
	return ctx.adapter.create<Omit<Jwk, "id">, Jwk>({
		model: "jwks",
		data: {
			publicKey: JSON.stringify(publicWebKey),
			// Tests run with disablePrivateKeyEncryption so the raw JWK is fine.
			privateKey: JSON.stringify(privateWebKey),
			alg,
			createdAt: new Date(),
		},
	});
}

const jwtOptions = { jwks: { disablePrivateKeyEncryption: true } } as const;

const bootJwt = () =>
	getTestInstance({
		plugins: [jwt(jwtOptions)],
		logger: { level: "error" },
	});

function makeSignCtx(authCtx: AuthContextShim): GenericEndpointContext {
	return { context: authCtx } as unknown as GenericEndpointContext;
}

describe("signJWT — signing key overrides", () => {
	it("uses the latest key when neither signingKeyId nor signingAlgorithm is set", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		const provisioned = await provisionKey(ctx, "EdDSA");

		const token = await signJWT(makeSignCtx(ctx), {
			options: jwtOptions,
			payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
		});
		const header = decodeProtectedHeader(token);
		expect(header.kid).toBe(provisioned.id);
		expect(header.alg).toBe("EdDSA");
	});

	it("signingKeyId routes through getKeyById and overrides latest-key selection", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		// Create two keys in order. Latest would be the second one.
		const older = await provisionKey(ctx, "ES256");
		await new Promise((resolve) => setTimeout(resolve, 5)); // ensure distinct createdAt
		await provisionKey(ctx, "EdDSA");

		const token = await signJWT(makeSignCtx(ctx), {
			options: jwtOptions,
			payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
			signingKeyId: older.id,
		});
		const header = decodeProtectedHeader(token);
		expect(header.kid).toBe(older.id);
		expect(header.alg).toBe("ES256");
	});

	it("signingAlgorithm picks the most recent key with that alg", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		await provisionKey(ctx, "EdDSA");
		await new Promise((resolve) => setTimeout(resolve, 5));
		const newerEdDsa = await provisionKey(ctx, "EdDSA");
		await new Promise((resolve) => setTimeout(resolve, 5));
		await provisionKey(ctx, "ES256"); // newest overall — but wrong alg

		const token = await signJWT(makeSignCtx(ctx), {
			options: jwtOptions,
			payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
			signingAlgorithm: "EdDSA",
		});
		const header = decodeProtectedHeader(token);
		expect(header.kid).toBe(newerEdDsa.id);
		expect(header.alg).toBe("EdDSA");
	});

	it("signingKeyId pointing at a missing key throws (does not silently fall back)", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		await provisionKey(ctx, "EdDSA");

		await expect(
			signJWT(makeSignCtx(ctx), {
				options: jwtOptions,
				payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
				signingKeyId: "nonexistent-kid",
			}),
		).rejects.toThrow(/signingKeyId.*not found/i);
	});

	it("signingAlgorithm with no matching key throws (does not auto-mint)", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		await provisionKey(ctx, "EdDSA");

		await expect(
			signJWT(makeSignCtx(ctx), {
				options: jwtOptions,
				payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
				signingAlgorithm: "ES256",
			}),
		).rejects.toThrow(/no key with alg "ES256"/i);
	});

	it("signingKeyId + mismatched signingAlgorithm throws to surface the conflict", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		const ed = await provisionKey(ctx, "EdDSA");

		await expect(
			signJWT(makeSignCtx(ctx), {
				options: jwtOptions,
				payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
				signingKeyId: ed.id,
				signingAlgorithm: "ES256",
			}),
		).rejects.toThrow(/alg "EdDSA".*signingAlgorithm.*"ES256"/);
	});

	it("signingKeyId + matching signingAlgorithm succeeds", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		const ed = await provisionKey(ctx, "EdDSA");

		const token = await signJWT(makeSignCtx(ctx), {
			options: jwtOptions,
			payload: { sub: "u1", iat: Math.floor(Date.now() / 1000) },
			signingKeyId: ed.id,
			signingAlgorithm: "EdDSA",
		});
		const header = decodeProtectedHeader(token);
		expect(header.kid).toBe(ed.id);
	});
});

describe("JWKS adapter helpers", () => {
	it("getKeyById finds a provisioned key", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		const k = await provisionKey(ctx, "EdDSA");

		const adapter = getJwksAdapter(ctx.adapter);
		const found = await adapter.getKeyById(makeSignCtx(ctx), k.id);
		expect(found?.id).toBe(k.id);
	});

	it("getKeyById returns undefined for an unknown id", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		await provisionKey(ctx, "EdDSA");

		const adapter = getJwksAdapter(ctx.adapter);
		const found = await adapter.getKeyById(makeSignCtx(ctx), "no-such-kid");
		expect(found).toBeUndefined();
	});

	it("getLatestKeyByAlg returns the most recent key matching the algorithm", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		await provisionKey(ctx, "EdDSA");
		await new Promise((resolve) => setTimeout(resolve, 5));
		const newerEd = await provisionKey(ctx, "EdDSA");
		await new Promise((resolve) => setTimeout(resolve, 5));
		await provisionKey(ctx, "ES256");

		const adapter = getJwksAdapter(ctx.adapter);
		const found = await adapter.getLatestKeyByAlg(makeSignCtx(ctx), "EdDSA");
		expect(found?.id).toBe(newerEd.id);
	});

	it("getLatestKeyByAlg returns undefined when no matching key exists", async () => {
		const { auth } = await bootJwt();
		const ctx = asShim(await auth.$context);
		await provisionKey(ctx, "EdDSA");

		const adapter = getJwksAdapter(ctx.adapter);
		const found = await adapter.getLatestKeyByAlg(makeSignCtx(ctx), "ES256");
		expect(found).toBeUndefined();
	});
});
