import { afterEach, describe, expect, it, vi } from "vitest";
import { getTestInstance } from "./harness/test-instance.js";

afterEach(() => vi.useRealTimers());

describe("session refresh policy", () => {
  it("defers writes until POST and returns a read-only GET refresh hint", async () => {
    vi.useFakeTimers();
    const { auth, signInWithTestUser } = await getTestInstance({ session: { deferSessionRefresh: true, updateAge: 10, expiresIn: 60 } });
    const { headers } = await signInWithTestUser();
    const first = await auth.api.getSession({ headers });
    // The pinned runtime returns this hint; the published API type omits it.
    expect((first as unknown as { needsRefresh: boolean }).needsRefresh).toBe(false);
    vi.advanceTimersByTime(11000);
    const read = await auth.api.getSession({ headers, asResponse: true });
    const readBody = await read.json();
    expect(readBody.needsRefresh).toBe(true);
    expect(readBody.session.expiresAt).toBe(first!.session.expiresAt.toISOString());
    expect(read.headers.get("set-cookie")).toBeNull();
    const written = await auth.api.getSession({ headers, method: "POST", returnHeaders: true });
    expect(written.response).not.toHaveProperty("needsRefresh");
    expect(written.response!.session.expiresAt.getTime() - first!.session.expiresAt.getTime()).toBe(11000);
    expect(written.headers.get("set-cookie")).toContain("session_token");
  });

  it.each(["global", "query"])("respects %s refresh suppression", async (mode) => {
    vi.useFakeTimers();
    const { auth, signInWithTestUser } = await getTestInstance({ session: { updateAge: 0, disableSessionRefresh: mode === "global" } });
    const { headers } = await signInWithTestUser();
    const query = mode === "query" ? { disableRefresh: true } : {};
    const first = await auth.api.getSession({ headers, query });
    vi.advanceTimersByTime(10000);
    const next = await auth.api.getSession({ headers, query, asResponse: true });
    expect((await next.json()).session.expiresAt).toBe(first!.session.expiresAt.toISOString());
    expect(next.headers.get("set-cookie")).toBeNull();
  });

  it("limits persistent cookies to the browser's 400-day ceiling", async () => {
    const { auth, testUser } = await getTestInstance({ session: { expiresIn: 86400 * 1000 } });
    const response = await auth.api.signInEmail({ body: testUser, asResponse: true });
    expect(response.headers.get("set-cookie")).toContain("Max-Age=34560000");
  });

  it("requires a fresh session before listing devices", async () => {
    vi.useFakeTimers();
    const { auth, signInWithTestUser } = await getTestInstance({ session: { freshAge: 10 } });
    const { headers } = await signInWithTestUser();
    vi.advanceTimersByTime(10000);
    await expect(auth.api.listSessions({ headers })).rejects.toMatchObject({ statusCode: 403, body: { code: "SESSION_NOT_FRESH" } });
  });

  it("preserves hidden session data while restricting protected fields", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({ session: { additionalFields: {
      theme: { type: "string", defaultValue: "light" },
      internalNote: { type: "string", defaultValue: "internal", input: false, returned: false },
    } } });
    const { headers } = await signInWithTestUser();
    await expect(auth.api.updateSession({ headers, body: { internalNote: "override" } })).rejects.toThrow();
    const updated = await auth.api.updateSession({ headers, body: { theme: "dark", token: "ignored-core-field" } });
    expect(updated.session.theme).toBe("dark");
    expect(updated.session).not.toHaveProperty("internalNote");
    expect((await auth.api.getSession({ headers }))!.session.theme).toBe("dark");
  });
});
