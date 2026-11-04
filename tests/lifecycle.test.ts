import { describe, expect, it, vi, afterEach } from "vitest";
import { getTestInstance } from "./harness/test-instance.js";

afterEach(() => vi.useRealTimers());

describe("V account lifecycle", () => {
  it("works through the unmodified Better Auth TypeScript client", async () => {
    const { client, testUser } = await getTestInstance();
    const result = await client.signIn.email(testUser);
    expect(result.error).toBeNull();
    expect(result.data?.user.email).toBe(testUser.email);
    expect(result.data?.token).toMatch(/^[a-f0-9]{64}$/);
  });

  it("verifies email and prevents verification-token replay", async () => {
    const sendVerificationEmail = vi.fn();
    const { auth, testUser, emails } = await getTestInstance({
      emailAndPassword: { requireEmailVerification: true },
      emailVerification: { sendVerificationEmail },
    });
    await expect(
      auth.api.signInEmail({ body: testUser }),
    ).rejects.toMatchObject({ statusCode: 403 });
    expect(emails).toHaveLength(1);
    const token = emails[0].token;
    const result = await auth.api.verifyEmail({ query: { token } });
    expect(result.user.emailVerified).toBe(true);
    await expect(
      auth.api.verifyEmail({ query: { token } }),
    ).rejects.toMatchObject({ statusCode: 400 });
    expect((await auth.api.signInEmail({ body: testUser })).token).toBeTypeOf(
      "string",
    );
  });

  it("keeps the verification token sent after a rejected sign-in usable", async () => {
    const { auth, testUser, emails } = await getTestInstance({
      emailAndPassword: { requireEmailVerification: true },
      emailVerification: { sendOnSignIn: true, sendVerificationEmail: vi.fn() },
    });
    await expect(auth.api.signInEmail({ body: testUser })).rejects.toThrow();
    expect(emails).toHaveLength(2);
    expect(
      (await auth.api.verifyEmail({ query: { token: emails[1].token } }))
        .status,
    ).toBe(true);
  });

  it("resets a password once, revokes sessions, and rejects the old password", async () => {
    const { auth, testUser, emails, signInWithTestUser } =
      await getTestInstance({
        emailAndPassword: { sendResetPassword: vi.fn(), revokeSessionsOnPasswordReset: true },
      });
    const { headers } = await signInWithTestUser();
    await auth.api.requestPasswordReset({
      body: { email: testUser.email, redirectTo: "/reset" },
    });
    const token = emails.at(-1).token;
    await auth.api.resetPassword({
      body: { token, newPassword: "replacement123" },
    });
    expect(await auth.api.getSession({ headers })).toBeNull();
    await expect(auth.api.signInEmail({ body: testUser })).rejects.toThrow();
    await expect(
      auth.api.resetPassword({
        body: { token, newPassword: "replacement456" },
      }),
    ).rejects.toThrow();
    expect(
      (
        await auth.api.signInEmail({
          body: { ...testUser, password: "replacement123" },
        })
      ).token,
    ).toBeTypeOf("string");
  });

  it("allows only one competing reset-token redemption", async () => {
    const { auth, testUser, emails } = await getTestInstance({
      emailAndPassword: { sendResetPassword: vi.fn() },
    });
    await auth.api.requestPasswordReset({ body: { email: testUser.email } });
    const token = emails.at(-1).token;
    const results = await Promise.allSettled([
      auth.api.resetPassword({
        body: { token, newPassword: "replacement123" },
      }),
      auth.api.resetPassword({
        body: { token, newPassword: "replacement456" },
      }),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual([
      "fulfilled",
      "rejected",
    ]);
  });

  it("does not consume a reset token when new-password validation fails", async () => {
    const { auth, testUser, emails } = await getTestInstance({
      emailAndPassword: { sendResetPassword: vi.fn() },
    });
    await auth.api.requestPasswordReset({ body: { email: testUser.email } });
    const token = emails.at(-1).token;
    await expect(
      auth.api.resetPassword({ body: { token, newPassword: "short" } }),
    ).rejects.toThrow();
    expect(
      (
        await auth.api.resetPassword({
          body: { token, newPassword: "replacement123" },
        })
      ).status,
    ).toBe(true);
  });

  it("returns the same reset response for existing and unknown accounts", async () => {
    const { auth, testUser, emails } = await getTestInstance({
      emailAndPassword: { sendResetPassword: vi.fn() },
    });
    const existing = await auth.api.requestPasswordReset({
      body: { email: testUser.email },
    });
    const missing = await auth.api.requestPasswordReset({
      body: { email: "missing@example.com" },
    });
    expect(existing).toEqual(missing);
    expect(emails).toHaveLength(1);
  });

  it("expires reset tokens using the V clock", async () => {
    vi.useFakeTimers();
    const { auth, testUser, emails } = await getTestInstance({
      emailAndPassword: { sendResetPassword: vi.fn(), resetPasswordTokenExpiresIn: 10 },
    });
    await auth.api.requestPasswordReset({ body: { email: testUser.email } });
    vi.advanceTimersByTime(10000);
    await expect(
      auth.api.resetPassword({
        body: { token: emails[0].token, newPassword: "replacement123" },
      }),
    ).rejects.toThrow();
  });

  it("refreshes sessions and rejects them at their exact expiry", async () => {
    vi.useFakeTimers();
    const { auth, signInWithTestUser } = await getTestInstance({
      session: { expiresIn: 30, updateAge: 10 },
    });
    const { headers } = await signInWithTestUser();
    const first = await auth.api.getSession({ headers });
    vi.advanceTimersByTime(10000);
    const refreshed = await auth.api.getSession({ headers });
    expect(
      refreshed!.session.expiresAt.getTime() - first!.session.expiresAt.getTime(),
    ).toBe(10000);
    vi.advanceTimersByTime(30000);
    expect(await auth.api.getSession({ headers })).toBeNull();
  });

  it("revokes another device using its listed revocation handle", async () => {
    const { auth, signInWithTestUser } = await getTestInstance();
    const first = await signInWithTestUser();
    const second = await signInWithTestUser();
    const sessions = await auth.api.listSessions({ headers: first.headers });
    const target = sessions.find(
      (session: any) => session.id === second.session.id,
    );
    await auth.api.revokeSession({
      headers: first.headers,
      body: { token: target.token },
    });
    expect(await auth.api.getSession({ headers: second.headers })).toBeNull();
    expect(
      await auth.api.getSession({ headers: first.headers }),
    ).not.toBeNull();
  });

  it("cannot revoke another user's session", async () => {
    const { auth, signInWithTestUser, cookieSetter } = await getTestInstance();
    const first = await signInWithTestUser();
    const otherHeaders = new Headers();
    cookieSetter(otherHeaders)({
      response: await auth.api.signUpEmail({
        body: {
          email: "other@example.com",
          password: "password123",
          name: "Other",
        },
        asResponse: true,
      }),
    });
    const other = await auth.api.getSession({ headers: otherHeaders });
    await auth.api.revokeSession({
      headers: first.headers,
      body: { token: other!.session.id },
    });
    expect(await auth.api.getSession({ headers: otherHeaders })).not.toBeNull();
  });

  it("requires fresh authentication for sensitive operations", async () => {
    vi.useFakeTimers();
    const { auth, testUser, signInWithTestUser } = await getTestInstance({
      session: { freshAge: 5 },
    });
    const { headers } = await signInWithTestUser();
    vi.advanceTimersByTime(5000);
    await expect(
      auth.api.changePassword({
        headers,
        body: {
          currentPassword: testUser.password,
          newPassword: "replacement123",
        },
      }),
    ).rejects.toMatchObject({ body: { code: "SESSION_NOT_FRESH" } });
  });

  it("changes a password and optionally revokes other sessions", async () => {
    const { auth, testUser, signInWithTestUser } = await getTestInstance();
    const first = await signInWithTestUser();
    const second = await signInWithTestUser();
    await auth.api.changePassword({
      headers: first.headers,
      body: {
        currentPassword: testUser.password,
        newPassword: "replacement123",
        revokeOtherSessions: true,
      },
    });
    expect(await auth.api.getSession({ headers: second.headers })).toBeNull();
    expect(
      await auth.api.getSession({ headers: first.headers }),
    ).not.toBeNull();
    await expect(auth.api.signInEmail({ body: testUser })).rejects.toThrow();
  });

  it("updates profile fields and rejects protected fields", async () => {
    const { auth, signInWithTestUser } = await getTestInstance();
    const { headers } = await signInWithTestUser();
    await auth.api.updateUser({
      headers,
      body: { name: "Updated", image: "https://example.com/avatar.png" },
    });
    expect((await auth.api.getSession({ headers }))!.user.name).toBe("Updated");
    await expect(
      auth.api.updateUser({ headers, body: { emailVerified: true } }),
    ).rejects.toThrow();
    await auth.api.updateUser({ headers, body: { image: null } });
    expect((await auth.api.getSession({ headers }))!.user.image).toBeNull();
  });

  it("deletes a user and cascades account and session removal", async () => {
    const { auth, testUser, signInWithTestUser } = await getTestInstance();
    const { headers } = await signInWithTestUser();
    await auth.api.deleteUser({
      headers,
      body: { password: testUser.password },
    });
    expect(await auth.api.getSession({ headers })).toBeNull();
    await expect(auth.api.signInEmail({ body: testUser })).rejects.toThrow();
  });

  it("supports bearer authentication only when the plugin is enabled", async () => {
    const { auth, testUser } = await getTestInstance();
    const { token } = await auth.api.signInEmail({ body: testUser });
    expect(
      (
        await auth.api.getSession({
          headers: { authorization: `Bearer ${token}` },
        })
      )!.user.email,
    ).toBe(testUser.email);
  });

  it("rolls registration back when email delivery fails", async () => {
    const { auth, testUser } = await getTestInstance(
      { emailVerification: { sendOnSignUp: true } },
      { disableTestUser: true, failDelivery: true },
    );
    await expect(
      auth.api.signUpEmail({ body: testUser }),
    ).rejects.toMatchObject({ statusCode: 500 });
    await expect(
      auth.api.signInEmail({ body: testUser }),
    ).rejects.toMatchObject({ statusCode: 401 });
  });

  it("rejects fixture options that cannot be represented faithfully", async () => {
    await expect(
      getTestInstance({ user: { unsupported: true } }),
    ).rejects.toThrow("Unsupported V fixture option");
  });
});

describe("V HTTP boundary", () => {
  it("rejects tampered cookies", async () => {
    const { auth, signInWithTestUser } = await getTestInstance();
    const { headers } = await signInWithTestUser();
    headers.set(
      "cookie",
      headers.get("cookie")!.replace(/session_token=./, "session_token=z"),
    );
    expect(await auth.api.getSession({ headers })).toBeNull();
  });

  it("rejects methods and malformed request bodies", async () => {
    const { auth } = await getTestInstance();
    for (const body of ["[]", "null", "false", "{", '{"email":12}']) {
      const response = await auth.handler(
        new Request("http://localhost:3000/api/auth/sign-in/email", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
        }),
      );
      expect(response.status, body).toBe(400);
    }
    expect(
      (
        await auth.handler(
          new Request("http://localhost:3000/api/auth/sign-in/email"),
        )
      ).status,
    ).toBe(405);
  });

  it("rejects unsafe redirect targets", async () => {
    const { auth, testUser } = await getTestInstance();
    for (const callbackURL of [
      "https://evil.example",
      "//evil.example",
      "/\\evil.example",
      "javascript:alert(1)",
      "http://localhost:3000@evil.example",
    ]) {
      await expect(
        auth.api.signInEmail({ body: { ...testUser, callbackURL } }),
      ).rejects.toMatchObject({ statusCode: 403 });
    }
  });

  it("uses Secure cookies on HTTPS and omits Max-Age for nonpersistent sessions", async () => {
    const { auth, testUser } = await getTestInstance({
      baseURL: "https://auth.example.com",
    });
    const response = await auth.api.signInEmail({
      body: { ...testUser, rememberMe: false },
      asResponse: true,
    });
    const cookie = response.headers.get("set-cookie");
    expect(cookie).toContain("__Secure-better-auth.session_token=");
    expect(cookie).toContain("; Secure");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).not.toContain("Max-Age");
  });

  it("does not refresh or persist a nonpersistent session", async () => {
    vi.useFakeTimers();
    const { auth, testUser, cookieSetter } = await getTestInstance({
      session: { updateAge: 10 },
    });
    const headers = new Headers();
    cookieSetter(headers)({
      response: await auth.api.signInEmail({
        body: { ...testUser, rememberMe: false },
        asResponse: true,
      }),
    });
    const before = await auth.api.getSession({ headers });
    vi.advanceTimersByTime(10000);
    const response = await auth.api.getSession({ headers, asResponse: true });
    const session = await response.json();
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(session.session.expiresAt).toBe(
      before!.session.expiresAt.toISOString(),
    );
    expect(
      Date.parse(session.session.expiresAt) - Date.now(),
    ).toBeLessThanOrEqual(86400000);
    expect(session.session).not.toHaveProperty("persistent");
  });

  it("enforces and expires rate limits in the V process", async () => {
    vi.useFakeTimers();
    const { auth, testUser } = await getTestInstance({
      rateLimit: { enabled: true, max: 2, window: 10 },
    });
    const request = () =>
      auth.handler(
        new Request("http://localhost:3000/api/auth/sign-in/email", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(testUser),
        }),
      );
    expect((await request()).status).toBe(200);
    expect((await request()).status).toBe(200);
    expect((await request()).status).toBe(429);
    vi.advanceTimersByTime(10000);
    expect((await request()).status).toBe(200);
  });

  it("exercises a real plugin: magic link, redirect, and replay rejection", async () => {
    const { auth, testUser, emails } = await getTestInstance(
      {},
      { magicLink: true },
    );
    const response = await auth.handler(
      new Request("http://localhost:3000/api/auth/sign-in/magic-link", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: testUser.email,
          callbackURL: "/dashboard",
        }),
      }),
    );
    expect(response.status).toBe(200);
    const url = emails.at(-1).url;
    const verified = await auth.handler(new Request(url));
    expect(verified.status).toBe(302);
    expect(verified.headers.get("location")).toBe("/dashboard");
    expect(verified.headers.get("set-cookie")).toContain("session_token=");
    expect((await auth.handler(new Request(url))).status).toBe(400);
  });
});
