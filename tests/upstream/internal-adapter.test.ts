// Generated from pinned upstream source; do not edit assertions here.
import { describe, expect, it, vi } from "vitest";
import type { SecondaryStorage } from "@better-auth/core/db";
import { DatabaseSync, init, getMigrations } from "../harness/verification-fixture.js";
import type { BetterAuthOptions } from "../harness/verification-fixture.js";

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

describe("consumeVerificationValue", () => {
		async function makeAdapter(overrides?: Partial<BetterAuthOptions>) {
			const opts = {
				database: new DatabaseSync(":memory:"),
				...overrides,
			} satisfies BetterAuthOptions;
			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);
			return ctx.internalAdapter;
		}

		it("returns the row to the first caller and null to subsequent reads", async () => {
			const adapter = await makeAdapter();
			await adapter.createVerificationValue({
				identifier: "consume:single",
				value: "user-1",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const first = await adapter.consumeVerificationValue("consume:single");
			expect(first).not.toBeNull();
			expect(first!.value).toBe("user-1");

			const second = await adapter.consumeVerificationValue("consume:single");
			expect(second).toBeNull();
		});

		it("yields exactly one winner under concurrent consume", async () => {
			const adapter = await makeAdapter();
			await adapter.createVerificationValue({
				identifier: "consume:race",
				value: "user-2",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const results = await Promise.all([
				adapter.consumeVerificationValue("consume:race"),
				adapter.consumeVerificationValue("consume:race"),
				adapter.consumeVerificationValue("consume:race"),
			]);

			const winners = results.filter((r) => r !== null);
			expect(winners).toHaveLength(1);
			expect(winners[0]!.value).toBe("user-2");
		});

		it("returns null for an unknown identifier", async () => {
			const adapter = await makeAdapter();
			const result = await adapter.consumeVerificationValue("consume:missing");
			expect(result).toBeNull();
		});

		it("returns null when the row exists but has already expired", async () => {
			const adapter = await makeAdapter();
			await adapter.createVerificationValue({
				identifier: "consume:expired",
				value: "user-expired",
				expiresAt: new Date(Date.now() - 1_000),
			});

			const result = await adapter.consumeVerificationValue("consume:expired");
			expect(result).toBeNull();

			// The expired row must still be invalidated so a later replay cannot
			// consume it after a cleanup pass.
			const replay = await adapter.findVerificationValue("consume:expired");
			expect(replay).toBeNull();
		});

		it("aborts the consume when a delete.before hook returns false", async () => {
			const veto = vi.fn().mockReturnValue(false);
			const adapter = await makeAdapter({
				databaseHooks: {
					verification: {
						delete: {
							before: veto,
						},
					},
				},
			});
			await adapter.createVerificationValue({
				identifier: "consume:veto",
				value: "user-3",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const result = await adapter.consumeVerificationValue("consume:veto");
			expect(result).toBeNull();
			expect(veto).toHaveBeenCalledTimes(1);

			const stillThere = await adapter.findVerificationValue("consume:veto");
			expect(stillThere).not.toBeNull();
		});

		it("fires delete.after only for the winning racer", async () => {
			const afterHook = vi.fn();
			const adapter = await makeAdapter({
				databaseHooks: {
					verification: {
						delete: {
							after: afterHook,
						},
					},
				},
			});
			await adapter.createVerificationValue({
				identifier: "consume:after-once",
				value: "user-4",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const results = await Promise.all([
				adapter.consumeVerificationValue("consume:after-once"),
				adapter.consumeVerificationValue("consume:after-once"),
			]);

			expect(results.filter((r) => r !== null)).toHaveLength(1);
			expect(afterHook).toHaveBeenCalledTimes(1);
		});

		it("consumes via the original identifier when storeIdentifier is hashed", async () => {
			const adapter = await makeAdapter({
				verification: { storeIdentifier: "hashed" },
			});
			await adapter.createVerificationValue({
				identifier: "consume:hashed",
				value: "user-5",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const result = await adapter.consumeVerificationValue("consume:hashed");
			expect(result).not.toBeNull();
			expect(result!.value).toBe("user-5");

			const replay = await adapter.consumeVerificationValue("consume:hashed");
			expect(replay).toBeNull();
		});

		it("consumes the latest row and invalidates stale rows for the identifier", async () => {
			const adapter = await makeAdapter();
			await adapter.createVerificationValue({
				identifier: "consume:multi",
				value: "older",
				expiresAt: new Date(Date.now() + 60_000),
			});
			await new Promise((resolve) => setTimeout(resolve, 5));
			await adapter.createVerificationValue({
				identifier: "consume:multi",
				value: "newer",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const consumed = await adapter.consumeVerificationValue("consume:multi");
			expect(consumed).not.toBeNull();
			expect(consumed!.value).toBe("newer");

			const leftover = await adapter.findVerificationValue("consume:multi");
			expect(leftover).toBeNull();
		});

		it("uses secondary storage getAndDelete when verification values are storage-only", async () => {
			const store = new Map<string, string>();
			const getAndDelete = vi.fn((key: string) => {
				const value = store.get(key) ?? null;
				store.delete(key);
				return value;
			});
			const adapter = await makeAdapter({
				verification: { storeInDatabase: false },
				secondaryStorage: {
					set(key, value) {
						store.set(key, value);
					},
					get(key) {
						return store.get(key) ?? null;
					},
					getAndDelete,
					increment(key) {
						const count = Number(store.get(key) ?? 0) + 1;
						store.set(key, String(count));
						return count;
					},
					delete(key) {
						store.delete(key);
					},
				},
			});
			await adapter.createVerificationValue({
				identifier: "consume:secondary",
				value: "secondary-user",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const results = await Promise.all([
				adapter.consumeVerificationValue("consume:secondary"),
				adapter.consumeVerificationValue("consume:secondary"),
			]);

			expect(results.filter((r) => r !== null)).toHaveLength(1);
			expect(results.find((r) => r !== null)?.value).toBe("secondary-user");
			expect(getAndDelete).toHaveBeenCalledWith(
				"verification:consume:secondary",
			);
			expect(store.has("verification:consume:secondary")).toBe(false);
		});

		it("returns null when the secondary storage row has already expired", async () => {
			const store = new Map<string, string>();
			const adapter = await makeAdapter({
				verification: { storeInDatabase: false },
				secondaryStorage: createStringSecondaryStorage(store),
			});

			// Bypass `createVerificationValue`'s TTL gate by writing directly
			// with an `expiresAt` already in the past. This mirrors a row that
			// was valid when written but reached the consume call after expiry.
			store.set(
				"verification:consume:secondary-expired",
				JSON.stringify({
					id: "row-id",
					identifier: "consume:secondary-expired",
					value: "secondary-expired-user",
					expiresAt: new Date(Date.now() - 1_000),
					createdAt: new Date(),
					updatedAt: new Date(),
				}),
			);

			const result = await adapter.consumeVerificationValue(
				"consume:secondary-expired",
			);
			expect(result).toBeNull();
			// The expired row is still consumed (deleted) so it cannot be
			// replayed later.
			expect(store.has("verification:consume:secondary-expired")).toBe(false);
		});

		it("rehydrates string `expiresAt` from secondary storage JSON", async () => {
			const store = new Map<string, string>();
			const adapter = await makeAdapter({
				verification: { storeInDatabase: false },
				secondaryStorage: createStringSecondaryStorage(store),
			});
			await adapter.createVerificationValue({
				identifier: "consume:secondary-hydrate",
				value: "hydrate-user",
				expiresAt: new Date(Date.now() + 60_000),
			});

			const result = await adapter.consumeVerificationValue(
				"consume:secondary-hydrate",
			);
			expect(result).not.toBeNull();
			expect(result!.value).toBe("hydrate-user");
			expect(result!.expiresAt).toBeInstanceOf(Date);
			expect(result!.expiresAt.getTime()).toBeGreaterThan(Date.now());
		});

		it("returns null when secondary storage `expiresAt` cannot be parsed", async () => {
			const store = new Map<string, string>();
			const adapter = await makeAdapter({
				verification: { storeInDatabase: false },
				secondaryStorage: createStringSecondaryStorage(store),
			});

			store.set(
				"verification:consume:secondary-invalid-date",
				JSON.stringify({
					id: "row-id",
					identifier: "consume:secondary-invalid-date",
					value: "bad-row",
					expiresAt: "not-a-date",
					createdAt: new Date(),
					updatedAt: new Date(),
				}),
			);

			const result = await adapter.consumeVerificationValue(
				"consume:secondary-invalid-date",
			);
			expect(result).toBeNull();
		});
	});

describe("reserveVerificationValue", () => {
		async function makeAdapter(overrides?: Partial<BetterAuthOptions>) {
			const opts = {
				database: new DatabaseSync(":memory:"),
				...overrides,
			} satisfies BetterAuthOptions;
			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);
			return ctx.internalAdapter;
		}

		it("returns true the first time and the row is findable", async () => {
			const adapter = await makeAdapter();

			const reserved = await adapter.reserveVerificationValue({
				identifier: "reserve:fresh",
				value: "jti-1",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(reserved).toBe(true);

			const found = await adapter.findVerificationValue("reserve:fresh");
			expect(found).not.toBeNull();
			expect(found!.value).toBe("jti-1");
		});

		it("returns false the second time for the same identifier", async () => {
			const adapter = await makeAdapter();

			const first = await adapter.reserveVerificationValue({
				identifier: "reserve:once",
				value: "jti-2",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(first).toBe(true);

			const second = await adapter.reserveVerificationValue({
				identifier: "reserve:once",
				value: "jti-2-replay",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(second).toBe(false);
		});

		it("yields exactly one winner under concurrent reserve", async () => {
			const adapter = await makeAdapter();

			const results = await Promise.all([
				adapter.reserveVerificationValue({
					identifier: "reserve:race",
					value: "jti-3",
					expiresAt: new Date(Date.now() + 60_000),
				}),
				adapter.reserveVerificationValue({
					identifier: "reserve:race",
					value: "jti-3",
					expiresAt: new Date(Date.now() + 60_000),
				}),
			]);

			expect(results.filter((r) => r === true)).toHaveLength(1);
			expect(results.filter((r) => r === false)).toHaveLength(1);
		});

		it("reserves independently across different identifiers", async () => {
			const adapter = await makeAdapter();

			const first = await adapter.reserveVerificationValue({
				identifier: "reserve:independent-a",
				value: "jti-a",
				expiresAt: new Date(Date.now() + 60_000),
			});
			const second = await adapter.reserveVerificationValue({
				identifier: "reserve:independent-b",
				value: "jti-b",
				expiresAt: new Date(Date.now() + 60_000),
			});

			expect(first).toBe(true);
			expect(second).toBe(true);
		});

		it("fails closed when verification reservation is secondary-storage-only", async () => {
			const adapter = await makeAdapter({
				verification: { storeInDatabase: false },
				secondaryStorage: createStringSecondaryStorage(new Map()),
			});

			await expect(
				adapter.reserveVerificationValue({
					identifier: "reserve:secondary-only",
					value: "jti-secondary",
					expiresAt: new Date(Date.now() + 60_000),
				}),
			).rejects.toThrow(/requires database-backed verification storage/);
		});

		/**
		 * @see https://github.com/better-auth/better-auth/issues/10624
		 */
		describe("with configured id strategies", () => {
			it("yields exactly one winner when ids are uuids", async () => {
				const adapter = await makeAdapter({
					advanced: { database: { generateId: "uuid" } },
				});
				const reserve = () =>
					adapter.reserveVerificationValue({
						identifier: "reserve:uuid-race",
						value: "jti-uuid",
						expiresAt: new Date(Date.now() + 60_000),
					});

				const results = await Promise.all([reserve(), reserve(), reserve()]);
				expect(results.filter((r) => r === true)).toHaveLength(1);
				expect(await reserve()).toBe(false);
			});;
		});
	});

describe("reserveVerificationValue", () => {
		async function makeAdapter(overrides?: Partial<BetterAuthOptions>) {
			const opts = {
				database: new DatabaseSync(":memory:"),
				...overrides,
			} satisfies BetterAuthOptions;
			await (await getMigrations(opts)).runMigrations();
			const ctx = await init(opts);
			return ctx.internalAdapter;
		}

		it("returns true the first time and the row is findable", async () => {
			const adapter = await makeAdapter();

			const reserved = await adapter.reserveVerificationValue({
				identifier: "reserve:fresh",
				value: "jti-1",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(reserved).toBe(true);

			const found = await adapter.findVerificationValue("reserve:fresh");
			expect(found).not.toBeNull();
			expect(found!.value).toBe("jti-1");
		});

		it("returns false the second time for the same identifier", async () => {
			const adapter = await makeAdapter();

			const first = await adapter.reserveVerificationValue({
				identifier: "reserve:once",
				value: "jti-2",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(first).toBe(true);

			const second = await adapter.reserveVerificationValue({
				identifier: "reserve:once",
				value: "jti-2-replay",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(second).toBe(false);
		});

		it("yields exactly one winner under concurrent reserve", async () => {
			const adapter = await makeAdapter();

			const results = await Promise.all([
				adapter.reserveVerificationValue({
					identifier: "reserve:race",
					value: "jti-3",
					expiresAt: new Date(Date.now() + 60_000),
				}),
				adapter.reserveVerificationValue({
					identifier: "reserve:race",
					value: "jti-3",
					expiresAt: new Date(Date.now() + 60_000),
				}),
			]);

			expect(results.filter((r) => r === true)).toHaveLength(1);
			expect(results.filter((r) => r === false)).toHaveLength(1);
		});

		it("reserves independently across different identifiers", async () => {
			const adapter = await makeAdapter();

			const first = await adapter.reserveVerificationValue({
				identifier: "reserve:independent-a",
				value: "jti-a",
				expiresAt: new Date(Date.now() + 60_000),
			});
			const second = await adapter.reserveVerificationValue({
				identifier: "reserve:independent-b",
				value: "jti-b",
				expiresAt: new Date(Date.now() + 60_000),
			});

			expect(first).toBe(true);
			expect(second).toBe(true);
		});
	});
