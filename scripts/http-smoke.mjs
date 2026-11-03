import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

const directory = mkdtempSync(join(tmpdir(), "better-auth-http-"));
const executable = resolve("build/auth-server");
const listener = createServer();
await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
const port = listener.address().port;
await new Promise((resolve) => listener.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const env = {
  ...process.env,
  AUTH_DB: join(directory, "auth.db"),
  AUTH_SECRET: randomBytes(32).toString("hex"),
  AUTH_BASE_URL: origin,
  AUTH_LISTEN: `127.0.0.1:${port}`,
};
let child;
let stderr = "";
function stop() {
  if (!child || child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    child.once("exit", resolve);
    child.kill();
  });
}
async function start() {
  child = spawn(executable, [], { env, stdio: ["ignore", "ignore", "pipe"] });
  child.stderr.on("data", (data) => {
    stderr = (stderr + data).slice(-4096);
  });
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`Server exited: ${stderr}`);
    try {
      if (
        (
          await fetch(`${origin}/api/auth/ok`, {
            signal: AbortSignal.timeout(500),
          })
        ).ok
      )
        return;
    } catch {}
    await delay(50);
  }
  throw new Error(`Server did not start: ${stderr}`);
}
async function post(path, body, cookie = "") {
  return fetch(`${origin}/api/auth${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin, cookie },
    body: JSON.stringify(body),
  });
}
try {
  const migration = spawnSync(executable, ["--migrate"], {
    env,
    encoding: "utf8",
  });
  assert.equal(migration.status, 0, migration.stderr);
  await start();
  const user = {
    email: "http@example.com",
    name: "HTTP User",
    password: "correct-horse-battery-staple",
  };
  const signup = await post("/sign-up/email", user);
  assert.equal(signup.status, 200, await signup.clone().text());
  assert.equal((await signup.json()).user.email, user.email);
  const cookie = signup.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  assert.ok(cookie.startsWith("better-auth.session_token="));
  const session = await fetch(`${origin}/api/auth/get-session`, {
    headers: { cookie },
  });
  assert.equal((await session.json()).user.email, user.email);
  const rejected = await fetch(`${origin}/api/auth/sign-out`, {
    method: "POST",
    headers: {
      cookie,
      origin: "https://evil.example",
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(rejected.status, 403);
  assert.equal((await post("/sign-out", {}, cookie)).status, 200);
  assert.equal(
    await (
      await fetch(`${origin}/api/auth/get-session`, { headers: { cookie } })
    ).json(),
    null,
  );
  await stop();
  await start();
  const signin = await post("/sign-in/email", user);
  assert.equal(signin.status, 200, await signin.clone().text());
  console.log(
    "Native HTTP smoke passed: migration, real scrypt credentials, cookies, sessions, CSRF, logout, persistence after restart.",
  );
} finally {
  await stop();
  rmSync(directory, { recursive: true, force: true });
}
