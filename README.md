# Better Auth for V

An independent, standalone V reimplementation of selected Better Auth contracts.
The implementation lives in V. TypeScript is used for upstream conformance tests,
the official client, and comparisons with the upstream server.

This is an initial implementation, not full Better Auth parity. The implemented
and missing behavior is listed in [the compatibility contract](docs/compatibility.md).
There is no dependency on a web framework.

## Implemented

- Email/password registration and login, configurable password hashing, and an
  upstream-compatible scrypt default with Unicode 17 NFKC normalization. Argon2id
  remains available as an explicit alternative.
- Additional user fields with scalar/array/date/JSON types, defaults, required
  fields, protected input, hidden output, and persistent storage.
- Registration-policy validation, duplicate-account enumeration protection,
  existing-user signup callbacks, and structured logger events.
- Signed HTTP-only session cookies, refresh, expiration, freshness checks, device
  listing/revocation, logout, and an opt-in bearer plugin.
- Deferred GET/POST refresh, refresh suppression, nonpersistent sessions, a
  400-day cookie ceiling, and configurable session fields with update support.
- Email verification, password reset/change, profile updates, and account deletion.
- SQLite storage, explicit versioned migrations, transactions, and a typed storage
  interface for additional adapters.
- Secondary session storage with database fallback, TTLs, and an in-memory
  implementation; database mutation hooks and after-commit callbacks.
- Sealed database session tokens and migration-aware account-column aliases.
- Compact, JWT, and JWE cookie caching with versioning, bounded cookie chunks,
  stateless cache refresh, and a native map-based storage adapter.
- A JWT/JWKS plugin supporting Ed25519, RSA/PSS, and ECDSA, with sealed persisted keys, rotation, session-cache
  signing, authenticated token issuance, and trusted signing/verification APIs.
- Plugin user/session schemas, protected authority fields, creation defaults,
  synthetic-user callbacks, and native endpoint freshness checks.
- HTTP method/body validation, origin and Fetch Metadata checks, exact trusted
  origins, redirect validation, CORS responses, and a per-instance route limiter.
- A plugin endpoint interface and an existing-user magic-link plugin.
- OAuth authorization-code orchestration with PKCE and browser-bound state, a
  provider interface, and a GitHub provider using verified email addresses.
- A JSON-lines test process and TypeScript facade that execute selected original
  Better Auth tests against V.

## Requirements and verification

Tested with V 0.5.2, Node.js 24, and pnpm 12. RSA/ECDSA support requires OpenSSL 3
development headers and libraries, discovered through V's `net.openssl` module.
SQLite uses V's `db.sqlite` binding
and its native SQLite dependency. The library itself has no V package dependencies.

```sh
pnpm install --frozen-lockfile
make check
```

`make check` runs V storage/security tests, Vitest conformance/lifecycle tests,
TypeScript checking, and a native HTTP test using actual scrypt passwords and a
temporary SQLite file. The HTTP test verifies persistence across a server restart.
Native normalization tests run all 20,034 Unicode 17 conformance vectors.
All checked-in tests run without contacting OAuth providers or sending email.

Use `make V=/absolute/path/to/v check` for a different V executable.

## Run the standalone server

```sh
make build/auth-server
./build/auth-server --migrate
AUTH_SECRET="$(openssl rand -hex 32)" ./build/auth-server
```

The example listens on `127.0.0.1:3000` and stores data in `auth.db`. `AUTH_DB`,
`AUTH_LISTEN`, and `AUTH_BASE_URL` configure it. Set a stable secret when restarting
an application whose existing session cookies should remain valid. `--migrate`
is an explicit schema operation; normal server startup does not migrate.

```sh
curl -i http://localhost:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"a-long-example-password","name":"User"}'
```

The minimal server has no email delivery or OAuth credentials configured. Configure
those in a V application through `Config` before using the corresponding flows.

## Embed in V

```v
import better_auth

mut storage := better_auth.open_sqlite('auth.db')!
storage.migrate()! // Usually a separate deployment step.
mut auth := better_auth.new(better_auth.Config{
    base_url: 'https://auth.example.com'
    secret: application_secret
    require_email_verification: true
    send_email: fn (message better_auth.EmailMessage) ! {
        // Send message.url to message.user.email using your delivery service.
        deliver_email(message.user.email, message.url)!
    }
}, storage)!
defer { auth.close() or {} }

// Your HTTP integration converts its request into this transport-neutral DTO.
response := auth.handle(better_auth.Request{
    method: 'POST'
    url: 'https://auth.example.com/api/auth/sign-in/email'
    headers: {'content-type': 'application/json', 'origin': 'https://auth.example.com'}
    body: '{"email":"user@example.com","password":"a-long-example-password"}'
})
```

`handle()` applies HTTP security checks. `call()` and typed methods such as
`sign_in_email()` are for trusted server-side callers and bypass HTTP CSRF and
content-type checks. They retain validation, authorization, and transactions.
Do not let an HTTP client select that bypass.

Preserve separate response header entries, particularly multiple `Set-Cookie`
values. `examples/server` demonstrates the native `net.http` integration.

## OAuth and plugins

```v
config := better_auth.Config{
    base_url: 'https://auth.example.com'
    secret: application_secret
    social_providers: [better_auth.OAuthProvider(better_auth.GitHubProvider{
        client_id: github_client_id
        client_secret: github_client_secret
    })]
    plugins: [better_auth.Plugin(better_auth.BearerPlugin{}), better_auth.MagicLinkPlugin{}]
}
```

Register `https://auth.example.com/api/auth/callback/github` with GitHub. The OAuth
orchestration is tested with a deterministic provider; live GitHub sign-in has not
been exercised with real credentials. Existing email/password accounts are never
automatically linked by matching a provider email. Explicit account linking is not
implemented yet.

Plugin endpoints receive an `EndpointContext` with session lookup, authentication,
and session-creation methods that use the enclosing transaction. They run inside
the auth mutex. A callback must not recursively call the same auth instance's
public API. Email callbacks should deliver or enqueue
messages without reentering authentication. External delivery cannot be rolled
back if a later database commit fails; durable delivery needs an application
outbox.

## Upstream tests

Upstream test source is pinned to commit
`0e75ddcf36489aa3a191ea902a82d1892034dc74`. The original source, SHA-256, selected
test inventory, and exclusions are checked in under `tests/upstream`.

```sh
pnpm upstream:fetch
pnpm upstream:import
pnpm upstream:inventory
pnpm test
```

The archive checksum is pinned in `upstream.lock.json`. The importer changes
imports and the test fixture. Sign-in and password test files are included in full;
sign-up and session suite selections and remaining exclusions are recorded in
their manifests.
Selected test bodies and assertions remain unchanged. `tests/upstream/corpus.json`
inventories the full pinned source test corpus, including currently unported files.
The separately pinned npm package `better-auth@1.7.15` supplies the real client,
error classes, cookie utilities, and server used in differential tests. The source
commit and published package are distinct baselines; version equality alone does
not establish source identity.

The bridge is a test executable, not a production endpoint. It has isolated
in-memory databases, an injectable clock, email capture, and a deliberately fast
test-only hasher. Bidirectional callbacks execute while V holds the transaction:
password hash/verify, email delivery, registration policy, and existing-user
notifications can return results or fail before commit. Logger events and user
record inspection are available to the fixture. Unsupported fixture configuration
fails explicitly. The TypeScript facade translates calls and errors; it does not
implement auth policy. Recursive calls into the same auth instance remain unsupported.

MIT licensed. Upstream test code is covered by [UPSTREAM_LICENSE](UPSTREAM_LICENSE).
Unicode data is covered by [the Unicode license](normalization/data/UNICODE_LICENSE).
This project is independent of Better Auth.
