// Generated from pinned upstream source; do not edit assertions here.
import {describe,expect,it,vi} from "vitest";
import type {SecondaryStorage} from "@better-auth/core/db";
import {DatabaseSync,init,getMigrations} from "../harness/verification-fixture.js";
import type {BetterAuthOptions} from "../harness/verification-fixture.js";

function createStringSecondaryStorage(
	store: Map<string, string>,
	ttlStore?: Map<string, number>,
): SecondaryStorage {
	return {
		set(key, value, ttl) {
			store.set(key, value);
			if (ttl !== undefined) ttlStore?.set(key, ttl);
		},
		get(key) {
			return store.get(key) || null;
		},
		getAndDelete(key) {
			const value = store.get(key) || null;
			store.delete(key);
			ttlStore?.delete(key);
			return value;
		},
		increment(key, ttl) {
			const current = Number(store.get(key) ?? 0);
			const count = Number.isFinite(current) ? current + 1 : 1;
			store.set(key, String(count));
			if (current === 0 && ttl !== undefined) ttlStore?.set(key, ttl);
			return count;
		},
		delete(key) {
			store.delete(key);
			ttlStore?.delete(key);
		},
	};
}

describe("verification token storage", () => {
		it("should hash identifier when storeIdentifier is 'hashed'", async () => {
			const hashedOpts = {
				database: new DatabaseSync(":memory:"),
				verification: {
					storeIdentifier: "hashed" as const,
				},
			} satisfies BetterAuthOptions;

			await (await getMigrations(hashedOpts)).runMigrations();
			const hashedCtx = await init(hashedOpts);
			const hashedAdapter = hashedCtx.internalAdapter;

			const verification = await hashedAdapter.createVerificationValue({
				identifier: "reset-password:my-token-123",
				value: "user-id-123",
				expiresAt: new Date(Date.now() + 60000),
			});

			// Stored identifier should be hashed (not equal to original)
			expect(verification.identifier).not.toBe("reset-password:my-token-123");

			// Should be able to find by original identifier
			const found = await hashedAdapter.findVerificationValue(
				"reset-password:my-token-123",
			);
			expect(found).toBeDefined();
			expect(found?.value).toBe("user-id-123");

			// Should be able to delete by original identifier
			await hashedAdapter.deleteVerificationByIdentifier(
				"reset-password:my-token-123",
			);
			const deleted = await hashedAdapter.findVerificationValue(
				"reset-password:my-token-123",
			);
			expect(deleted).toBeNull();
		});

		it("should use overrides for specific prefixes", async () => {
			const overrideOpts = {
				database: new DatabaseSync(":memory:"),
				verification: {
					storeIdentifier: {
						default: "plain" as const,
						overrides: {
							"reset-password": "hashed" as const,
						},
					},
				},
			} satisfies BetterAuthOptions;

			await (await getMigrations(overrideOpts)).runMigrations();
			const overrideCtx = await init(overrideOpts);
			const overrideAdapter = overrideCtx.internalAdapter;

			// reset-password should be hashed
			const hashedVerification = await overrideAdapter.createVerificationValue({
				identifier: "reset-password:token-abc",
				value: "user-1",
				expiresAt: new Date(Date.now() + 60000),
			});
			expect(hashedVerification.identifier).not.toBe(
				"reset-password:token-abc",
			);

			// other identifiers should be plain
			const plainVerification = await overrideAdapter.createVerificationValue({
				identifier: "magic-link:token-xyz",
				value: "user-2",
				expiresAt: new Date(Date.now() + 60000),
			});
			expect(plainVerification.identifier).toBe("magic-link:token-xyz");
		});

		it("should fallback to plain lookup for old tokens", async () => {
			const database = new DatabaseSync(":memory:");

			// First create with plain storage
			const plainOpts = {
				database,
				verification: { storeIdentifier: "plain" as const },
			} satisfies BetterAuthOptions;

			await (await getMigrations(plainOpts)).runMigrations();
			const plainCtx = await init(plainOpts);
			await plainCtx.internalAdapter.createVerificationValue({
				identifier: "old-token:abc123",
				value: "old-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			// Now switch to hashed storage (simulating config change)
			const hashedOpts = {
				database,
				verification: { storeIdentifier: "hashed" as const },
			} satisfies BetterAuthOptions;

			const hashedCtx = await init(hashedOpts);

			// Should still find old plain token via fallback
			const found =
				await hashedCtx.internalAdapter.findVerificationValue(
					"old-token:abc123",
				);
			expect(found).toBeDefined();
			expect(found?.value).toBe("old-value");
		});
	});

describe("verification secondary storage", () => {
		function createMockStorage() {
			const dataMap = new Map<string, string>();
			const ttlMap = new Map<string, number>();
			return {
				dataMap,
				ttlMap,
				storage: createStringSecondaryStorage(dataMap, ttlMap),
			};
		}

		it("should store verification in secondary storage by default", async () => {
			const { dataMap, ttlMap, storage } = createMockStorage();

			const secondaryOnlyOpts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(secondaryOnlyOpts)).runMigrations();
			const ctx = await init(secondaryOnlyOpts);

			const verification = await ctx.internalAdapter.createVerificationValue({
				identifier: "test-verification",
				value: "test-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			expect(dataMap.has(`verification:${verification.identifier}`)).toBe(true);
			expect(ttlMap.has(`verification:${verification.identifier}`)).toBe(true);
		});

		it("should find verification from secondary storage", async () => {
			const { storage } = createMockStorage();

			const secondaryOnlyOpts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(secondaryOnlyOpts)).runMigrations();
			const ctx = await init(secondaryOnlyOpts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "find-test",
				value: "find-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			const found =
				await ctx.internalAdapter.findVerificationValue("find-test");
			expect(found).not.toBeNull();
			expect(found?.identifier).toBe("find-test");
			expect(found?.value).toBe("find-value");
		});

		it("should NOT store in database when secondary-only mode", async () => {
			const { dataMap, storage } = createMockStorage();

			const secondaryOnlyOpts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(secondaryOnlyOpts)).runMigrations();
			const ctx = await init(secondaryOnlyOpts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "secondary-only-test",
				value: "test-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			expect(dataMap.has("verification:secondary-only-test")).toBe(true);

			dataMap.clear();
			const found = await ctx.internalAdapter.findVerificationValue(
				"secondary-only-test",
			);
			expect(found).toBeNull(); // Proves DB was NOT used
		});

		it("should delete verification from secondary storage", async () => {
			const { dataMap, storage } = createMockStorage();

			const secondaryOnlyOpts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(secondaryOnlyOpts)).runMigrations();
			const ctx = await init(secondaryOnlyOpts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "delete-test",
				value: "delete-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			expect(dataMap.has("verification:delete-test")).toBe(true);

			await ctx.internalAdapter.deleteVerificationByIdentifier("delete-test");

			expect(dataMap.has("verification:delete-test")).toBe(false);
		});

		it("should store in both when storeInDatabase is true", async () => {
			const { dataMap, storage } = createMockStorage();

			const dualStorageOpts = {
				database: new DatabaseSync(":memory:"),
				verification: {
					storeInDatabase: true,
				},
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(dualStorageOpts)).runMigrations();
			const ctx = await init(dualStorageOpts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "both-test",
				value: "both-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			expect(dataMap.has("verification:both-test")).toBe(true);

			dataMap.clear();
			const found =
				await ctx.internalAdapter.findVerificationValue("both-test");
			expect(found).not.toBeNull();
			expect(found?.value).toBe("both-value");
		});

		it("should fallback to database when not in secondary storage", async () => {
			const { dataMap, storage } = createMockStorage();

			const dualStorageOpts = {
				database: new DatabaseSync(":memory:"),
				verification: {
					storeInDatabase: true,
				},
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(dualStorageOpts)).runMigrations();
			const ctx = await init(dualStorageOpts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "fallback-test",
				value: "fallback-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			dataMap.clear();

			const found =
				await ctx.internalAdapter.findVerificationValue("fallback-test");
			expect(found).not.toBeNull();
			expect(found?.value).toBe("fallback-value");
		});

		it("should set correct TTL based on expiresAt", async () => {
			const { ttlMap, storage } = createMockStorage();

			const secondaryOnlyOpts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(secondaryOnlyOpts)).runMigrations();
			const ctx = await init(secondaryOnlyOpts);

			const expiresIn = 300000; // 5 minutes in ms
			const expiresAt = new Date(Date.now() + expiresIn);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "ttl-test",
				value: "ttl-value",
				expiresAt,
			});

			const ttl = ttlMap.get("verification:ttl-test");
			expect(ttl).toBeDefined();
			expect(ttl).toBeGreaterThanOrEqual(298);
			expect(ttl).toBeLessThanOrEqual(300);
		});
	});

describe("safeJSONParse date revival in secondary storage", () => {
		/**
		 * Simulates a Redis client that auto-parses JSON (e.g. ioredis with
		 * certain configurations). The `get` method returns a pre-parsed object
		 * where date fields are still ISO 8601 strings, not Date instances.
		 */
		function createPreParsedStorage() {
			const dataMap = new Map<string, unknown>();
			const ttlMap = new Map<string, number>();
			return {
				dataMap,
				ttlMap,
				storage: {
					set(key: string, value: string, ttl?: number) {
						// Store as pre-parsed object (simulating Redis auto-parse)
						dataMap.set(key, JSON.parse(value));
						if (ttl) ttlMap.set(key, ttl);
					},
					get(key: string) {
						return dataMap.get(key) ?? null;
					},
					getAndDelete(key: string) {
						const value = dataMap.get(key) ?? null;
						dataMap.delete(key);
						ttlMap.delete(key);
						return value;
					},
					increment(key: string, ttl: number) {
						const current = Number(dataMap.get(key) ?? 0);
						const count = Number.isFinite(current) ? current + 1 : 1;
						dataMap.set(key, count);
						if (current === 0) ttlMap.set(key, ttl);
						return count;
					},
					delete(key: string) {
						dataMap.delete(key);
						ttlMap.delete(key);
					},
				},
			};
		}

		it("should return Date objects from findVerificationValue when storage returns pre-parsed objects", async () => {
			const { storage } = createPreParsedStorage();

			const opts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "date-test",
				value: "test-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			const found =
				await ctx.internalAdapter.findVerificationValue("date-test");
			expect(found).not.toBeNull();
			expect(found!.expiresAt).toBeInstanceOf(Date);
			expect(found!.createdAt).toBeInstanceOf(Date);
			expect(found!.updatedAt).toBeInstanceOf(Date);
		});

		it("should correctly detect expired verification when storage returns pre-parsed objects", async () => {
			const { storage } = createPreParsedStorage();

			const opts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "expiry-check",
				value: "test-value",
				expiresAt: new Date(Date.now() + 60000),
			});

			const found =
				await ctx.internalAdapter.findVerificationValue("expiry-check");
			expect(found).not.toBeNull();
			// This comparison would silently fail if expiresAt were a string
			// because string < Date coerces to NaN, making it always false
			expect(found!.expiresAt > new Date()).toBe(true);
			expect(found!.expiresAt < new Date(Date.now() + 120000)).toBe(true);
		});

		it("should return Date objects for all date fields across multiple reads", async () => {
			const { storage } = createPreParsedStorage();

			const opts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);

			const expiresAt = new Date(Date.now() + 60000);
			await ctx.internalAdapter.createVerificationValue({
				identifier: "multi-read-test",
				value: "test-value",
				expiresAt,
			});

			// First read: safeJSONParse receives pre-parsed object from storage
			const first =
				await ctx.internalAdapter.findVerificationValue("multi-read-test");
			expect(first).not.toBeNull();
			expect(first!.expiresAt).toBeInstanceOf(Date);
			expect(first!.createdAt).toBeInstanceOf(Date);
			expect(first!.updatedAt).toBeInstanceOf(Date);

			// Second read: verify consistency (the stored object wasn't mutated)
			const second =
				await ctx.internalAdapter.findVerificationValue("multi-read-test");
			expect(second).not.toBeNull();
			expect(second!.expiresAt).toBeInstanceOf(Date);
			expect(second!.expiresAt.getTime()).toBe(first!.expiresAt.getTime());
		});

		it("should preserve non-date string fields when reviving dates", async () => {
			const { storage } = createPreParsedStorage();

			const opts = {
				database: new DatabaseSync(":memory:"),
				secondaryStorage: storage,
			} satisfies BetterAuthOptions;

			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);

			await ctx.internalAdapter.createVerificationValue({
				identifier: "string-field-test",
				value: "my-token-value-123",
				expiresAt: new Date(Date.now() + 60000),
			});

			const found =
				await ctx.internalAdapter.findVerificationValue("string-field-test");
			expect(found).not.toBeNull();
			// Non-date strings must NOT be converted
			expect(found!.identifier).toBe("string-field-test");
			expect(typeof found!.identifier).toBe("string");
			expect(found!.value).toBe("my-token-value-123");
			expect(typeof found!.value).toBe("string");
			// Date strings MUST be converted
			expect(found!.expiresAt).toBeInstanceOf(Date);
		});
	});
