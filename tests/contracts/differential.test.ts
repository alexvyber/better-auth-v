import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getTestInstance } from "../harness/test-instance.js";

type Handler = (request: Request) => Promise<Response>;
let vHandler: Handler;
let tsHandler: Handler;
let db: DatabaseSync;

beforeAll(async () => {
  const instance = await getTestInstance({}, { disableTestUser: true });
  vHandler = instance.auth.handler;
  db = new DatabaseSync(":memory:");
  const options = {
    baseURL: "http://localhost:3000",
    secret: "better-auth-secret-that-is-long-enough-for-validation-test",
    database: db,
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    advanced: { disableCSRFCheck: false, disableOriginCheck: false },
    logger: { disabled: true },
  };
  await (await getMigrations(options)).runMigrations();
  const upstream = betterAuth(options);
  tsHandler = (request) => upstream.handler(request);
});

afterAll(() => db?.close());

async function request(
  handler: Handler,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  return handler(
    new Request(`http://localhost:3000/api/auth${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

function cookie(response: Response) {
  return response.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
}

function identity(body: any) {
  return {
    email: body.user.email,
    name: body.user.name,
    emailVerified: body.user.emailVerified,
  };
}

describe("HTTP behavior against better-auth@1.7.15", () => {
  it("matches registration, login, session lookup, and logout", async () => {
    const snapshots = [];
    for (const handler of [tsHandler, vHandler]) {
      const user = {
        email: "differential@example.com",
        password: "password123",
        name: "Differential",
      };
      const signup = await request(handler, "/sign-up/email", user);
      const signupBody = await signup.json();
      expect(signupBody.token).toBeTypeOf("string");
      const signin = await request(handler, "/sign-in/email", user);
      const signinBody = await signin.json();
      const cookies = cookie(signin);
      const session = await request(handler, "/get-session", undefined, {
        cookie: cookies,
      });
      const sessionBody = await session.json();
      const signout = await request(
        handler,
        "/sign-out",
        {},
        { cookie: cookies, origin: "http://localhost:3000" },
      );
      const after = await request(handler, "/get-session", undefined, {
        cookie: cookies,
      });
      snapshots.push({
        signup: [signup.status, identity(signupBody)],
        signin: [signin.status, identity(signinBody), signinBody.redirect],
        session: [
          session.status,
          identity(sessionBody),
          sessionBody.session.userId === signupBody.user.id,
        ],
        cookie: ["HttpOnly", "SameSite=Lax", "Path=/"].map((attribute) =>
          signin.headers
            .get("set-cookie")!
            .toLowerCase()
            .includes(attribute.toLowerCase()),
        ),
        signout: [signout.status, await signout.json()],
        after: [after.status, await after.json()],
      });
    }
    expect(snapshots[1]).toEqual(snapshots[0]);
  });

  it.each([
    [
      "wrong password",
      "/sign-in/email",
      { email: "differential@example.com", password: "wrong-password" },
    ],
    [
      "unknown account",
      "/sign-in/email",
      { email: "missing@example.com", password: "password123" },
    ],
    [
      "short password",
      "/sign-up/email",
      { email: "short@example.com", password: "short", name: "Short" },
    ],
    [
      "long password",
      "/sign-up/email",
      { email: "long@example.com", password: "x".repeat(129), name: "Long" },
    ],
    [
      "duplicate registration",
      "/sign-up/email",
      {
        email: "differential@example.com",
        password: "password123",
        name: "Duplicate",
      },
    ],
  ])("matches errors for %s", async (_name, path, body) => {
    const results = [];
    for (const handler of [tsHandler, vHandler]) {
      const response = await request(handler, path as string, body);
      results.push({ status: response.status, body: await response.json() });
    }
    expect(results[1]).toEqual(results[0]);
  });

  it.each([
    ["untrusted origin", { origin: "https://evil.example" }],
    [
      "cross-site navigation",
      {
        origin: "https://evil.example",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "navigate",
      },
    ],
    ["null origin", { origin: "null" }],
  ])("matches rejection of %s", async (_name, headers) => {
    const results = [];
    for (const handler of [tsHandler, vHandler]) {
      const response = await request(
        handler,
        "/sign-in/email",
        { email: "differential@example.com", password: "password123" },
        headers as Record<string, string>,
      );
      results.push({ status: response.status, body: await response.json() });
    }
    expect(results[1]).toEqual(results[0]);
  });

  it("matches an unauthenticated session lookup", async () => {
    const results = [];
    for (const handler of [tsHandler, vHandler]) {
      const response = await request(handler, "/get-session");
      results.push([response.status, await response.json()]);
    }
    expect(results[1]).toEqual(results[0]);
  });
});
