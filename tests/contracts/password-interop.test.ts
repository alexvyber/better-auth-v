import { scryptSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "../harness/password.js";

describe("scrypt interoperability and Unicode normalization", () => {
  it("emits hashes verified independently by Node's scrypt", async () => {
    const password = "ℌｅ𝔩𝔩𝔬 e\u0301 한글 🔑";
    const encoded = await hashPassword(password);
    const [salt, hash] = encoded.split(":");
    expect(salt).toMatch(/^[a-f0-9]{32}$/);
    const expected = scryptSync(password.normalize("NFKC"), salt, 64, {
      N: 16384,
      r: 16,
      p: 1,
      maxmem: 67108864,
    });
    expect(hash).toBe(expected.toString("hex"));
  });

  it("treats canonically and compatibly equivalent passwords identically", async () => {
    const hash = await hashPassword("Ｆｕｌｌ e\u0301 ﬁ ①");
    expect(await verifyPassword({ hash, password: "Full é fi 1" })).toBe(true);
    expect(await verifyPassword({ hash, password: "Full è fi 1" })).toBe(false);
  });

  it.each(["", "missing-separator", ":no-salt", "no-key:"])(
    "rejects malformed hash %j",
    async (hash) => {
      await expect(
        verifyPassword({ hash, password: "password" }),
      ).rejects.toThrow("Invalid password hash");
    },
  );
});
