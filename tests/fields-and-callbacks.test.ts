import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "./harness/test-instance.js";

const registration = {
  email: "fields@example.com",
  name: "Fields",
  password: "password123",
};

describe("additional user field contracts", () => {
  it("persists typed values, applies defaults, and filters hidden fields from all user responses", async () => {
    const { auth, db, signInWithTestUser, testUser } = await getTestInstance({
      user: {
        additionalFields: {
          nickname: { type: "string", required: false },
          enabled: { type: "boolean", defaultValue: true, input: false },
          privateNote: { type: "string", required: false, returned: false },
        },
      },
    });
    const { headers } = await signInWithTestUser();
    await auth.api.updateUser({
      headers,
      body: { nickname: "Alias", privateNote: "server record" },
    });
    const current = await auth.api.getSession({ headers });
    expect(current!.user.nickname).toBe("Alias");
    expect(current!.user.enabled).toBe(true);
    expect(current!.user).not.toHaveProperty("privateNote");
    expect(
      (await auth.api.signInEmail({ body: testUser })).user,
    ).not.toHaveProperty("privateNote");
    expect((await db.findMany({ model: "user" }))[0].privateNote).toBe(
      "server record",
    );
  });

  it("validates required fields and types before writing records", async () => {
    const { auth, db } = await getTestInstance(
      {
        user: {
          additionalFields: {
            years: { type: "number", required: true },
            tags: { type: "string[]", required: false },
          },
        },
      },
      { disableTestUser: true },
    );
    for (const fields of [{}, { years: "three" }, { years: 3, tags: [1] }]) {
      await expect(
        auth.api.signUpEmail({ body: { ...registration, ...fields } as any }),
      ).rejects.toMatchObject({ statusCode: 400 });
    }
    expect(await db.findMany({ model: "user" })).toEqual([]);
    const result = await auth.api.signUpEmail({
      body: { ...registration, years: 3, tags: ["v", "auth"] },
    });
    expect(result.user.years).toBe(3);
    expect(result.user.tags).toEqual(["v", "auth"]);
  });

  it("ignores protected input in favor of the configured creation default", async () => {
    const { auth } = await getTestInstance(
      {
        user: {
          additionalFields: {
            privileged: { type: "boolean", input: false, defaultValue: false },
          },
        },
      },
      { disableTestUser: true },
    );
    const created = await auth.api.signUpEmail({
      body: { ...registration, privileged: true } as any,
    });
    expect(created.user.privileged).toBe(false);
  });

  it("rejects protected updates and preserves the previous record", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({
      user: {
        additionalFields: {
          privileged: { type: "boolean", input: false, defaultValue: false },
        },
      },
    });
    const { headers } = await signInWithTestUser();
    await expect(
      auth.api.updateUser({ headers, body: { privileged: true } }),
    ).rejects.toMatchObject({ body: { code: "FIELD_NOT_ALLOWED" } });
    expect((await auth.api.getSession({ headers }))!.user.privileged).toBe(
      false,
    );
  });

  it("rejects field schemas that collide with core identity fields", async () => {
    await expect(
      getTestInstance(
        { user: { additionalFields: { emailVerified: { type: "boolean" } } } },
        { disableTestUser: true },
      ),
    ).rejects.toThrow("reserved name");
  });

  it("rolls invalid profile changes back without losing other fields", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({
      user: {
        additionalFields: { count: { type: "number", defaultValue: 1 } },
      },
    });
    const { headers } = await signInWithTestUser();
    await expect(
      auth.api.updateUser({
        headers,
        body: { name: "Should roll back", count: "invalid" },
      }),
    ).rejects.toThrow();
    const result = await auth.api.getSession({ headers });
    expect(result!.user.name).toBe("test user");
    expect(result!.user.count).toBe(1);
  });

  it("does not copy credential input into a same-named additional field", async () => {
    const { auth, db } = await getTestInstance(
      {
        user: {
          additionalFields: {
            password: { type: "string", required: false },
          },
        },
      },
      { disableTestUser: true },
    );
    const result = await auth.api.signUpEmail({ body: registration });
    expect(result.user).not.toHaveProperty("password");
    expect((await db.findMany({ model: "user" }))[0]).not.toHaveProperty(
      "password",
    );
  });
});

describe("callbacks execute inside V operations", () => {
  it("passes the stored custom hash into verify and propagates its result", async () => {
    const hash = vi.fn(async (password: string) => `custom:${password}`);
    const verify = vi.fn(
      async (input: { hash: string; password: string }) =>
        input.hash === `custom:${input.password}`,
    );
    const { auth, testUser } = await getTestInstance({
      emailAndPassword: { password: { hash, verify } },
    });
    expect((await auth.api.signInEmail({ body: testUser })).token).toBeTypeOf(
      "string",
    );
    expect(verify).toHaveBeenCalledWith({
      hash: `custom:${testUser.password}`,
      password: testUser.password,
    });
    await expect(
      auth.api.signInEmail({ body: { ...testUser, password: "incorrect" } }),
    ).rejects.toMatchObject({ statusCode: 401 });
  });

  it("rolls back when a configured hasher throws", async () => {
    const { auth, db } = await getTestInstance(
      {
        emailAndPassword: {
          password: {
            hash: async (password: string) => {
              if (password === registration.password)
                throw new Error("hash failure");
              return password;
            },
            verify: async () => true,
          },
        },
      },
      { disableTestUser: true },
    );
    await expect(
      auth.api.signUpEmail({ body: registration }),
    ).rejects.toMatchObject({ statusCode: 500 });
    expect(await db.findMany({ model: "user" })).toEqual([]);
  });

  it("returns a server error when custom verification throws", async () => {
    const { auth, testUser } = await getTestInstance({
      emailAndPassword: {
        password: {
          hash: async (password: string) => password,
          verify: async () => {
            throw new Error("private verifier error");
          },
        },
      },
    });
    await expect(
      auth.api.signInEmail({ body: testUser }),
    ).rejects.toMatchObject({
      statusCode: 500,
      message: "Internal server error",
    });
  });

  it("awaits email delivery and rolls registration back on callback failure", async () => {
    const sendVerificationEmail = vi.fn(async () => {
      throw new Error("delivery callback failure");
    });
    const { auth, db } = await getTestInstance(
      { emailVerification: { sendOnSignUp: true, sendVerificationEmail } },
      { disableTestUser: true },
    );
    await expect(
      auth.api.signUpEmail({ body: registration }),
    ).rejects.toMatchObject({ statusCode: 500 });
    expect(sendVerificationEmail).toHaveBeenCalledTimes(1);
    expect(await db.findMany({ model: "user" })).toEqual([]);
  });

  it("does not leak a stored profile in generic duplicate responses", async () => {
    const { auth } = await getTestInstance(
      { emailAndPassword: { autoSignIn: false } },
      { disableTestUser: true },
    );
    const first = await auth.api.signUpEmail({ body: registration });
    const second = await auth.api.signUpEmail({
      body: { ...registration, name: "New request" },
    });
    expect(second.user.id).not.toBe(first.user.id);
    expect(second.user.name).toBe("New request");
    expect(second.token).toBeNull();
    expect(Object.keys(second.user)).toEqual(Object.keys(first.user));
  });

  it("counts password lengths in UTF-16 units before invoking a hasher", async () => {
    const hash = vi.fn(async (password: string) => password);
    const verify = vi.fn(async () => true);
    const { auth } = await getTestInstance(
      { emailAndPassword: { password: { hash, verify } } },
      { disableTestUser: true },
    );
    hash.mockClear();
    await expect(
      auth.api.signUpEmail({
        body: { ...registration, password: "🙂".repeat(65) },
      }),
    ).rejects.toMatchObject({ body: { code: "PASSWORD_TOO_LONG" } });
    expect(hash).not.toHaveBeenCalled();
  });
});
