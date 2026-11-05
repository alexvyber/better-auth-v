# Better Auth for V

An independent, standalone V reimplementation of selected Better Auth contracts.
The implementation lives in V. TypeScript is used for upstream conformance tests,
the official client, and comparisons with the upstream server.

This is an initial implementation, not full Better Auth parity. The implemented
and missing behavior is listed in [the compatibility contract](docs/compatibility.md).
There is no dependency on a web framework.

## Install with VPM

The package is being prepared for registration as `alexvyber.better_auth`, version
`0.1.0`. It is not published to VPM yet. After registration:

```sh
v install alexvyber.better_auth
```

```v
import alexvyber.better_auth
```

Use V 0.5.2 and a C compiler. The default module links OpenSSL 3, SQLite and
PostgreSQL's libpq, including when using the memory or SQLite store. Install their
development headers/libraries first:

```sh
# macOS / Homebrew
brew install pkg-config openssl@3 sqlite libpq

# Ubuntu / Debian
sudo apt-get install build-essential pkg-config libssl-dev libsqlite3-dev libpq-dev
```

Node.js, pnpm, database servers and the upstream TypeScript tests are development
tools; they are not needed to import or run the default V package. MongoDB needs
an additional native driver build; see [the package guide](docs/publishing.md).

From a checkout, `make check-package` verifies both installed import layouts in
isolated consumers, including Unicode password hashing, SQLite restart/login and
RSA JWT signing/verification. It requires Node.js for the verification script but
does not install npm packages or use checkout build artifacts.

## Implemented

- Email/password registration and login, configurable password hashing, and an
  upstream-compatible scrypt default with Unicode 17 NFKC normalization. Argon2id
  remains available as an explicit alternative.
- UUID and model-aware custom record ID generators, plus deterministic reservation IDs.
- Additional user fields with scalar/array/date/JSON types, defaults, required
  fields, protected input, hidden output, input validators/transforms, functional
  creation defaults, unique values
  and persistent storage; PostgreSQL additional-field column aliases.
- Registration-policy validation, duplicate-account enumeration protection,
  existing-user signup callbacks, and structured logger events.
- Signed HTTP-only session cookies, refresh, expiration, freshness checks, device
  listing/revocation, logout, and an opt-in bearer plugin. Custom cookie names,
  prefixes, secure overrides, and cross-subdomain domains are supported.
- Deferred GET/POST refresh, refresh suppression, nonpersistent sessions, a
  400-day cookie ceiling, and configurable session fields with update support.
- Email verification, password reset/change, profile updates, opt-in account deletion
  with one-use verification links, and a server-only password-setting API.
- Native MongoDB replica-set storage with ObjectId/UUID IDs, explicit indexes and
  session TTL expiry; compile with `-d mongodb` after `pnpm mongo:setup`.
- SQLite storage with versioned migrations, native PostgreSQL physical-column
  storage with explicit migrations, UUIDs and mapped schemas, plus a typed adapter interface.
- Trusted core-model adapter queries with validated predicates, sorting, pagination,
  projections, user/session/account joins and raw mutation operations. Portable query
  execution uses native storage scans, with indexed session-token authentication.
- Secondary session storage with database fallback, TTLs, and an in-memory
  implementation; database mutation hooks and after-commit callbacks.
- Sealed database session tokens and migration-aware account-column aliases.
- Compact, JWT, and JWE cookie caching with versioning, bounded cookie chunks,
  stateless cache refresh, and a native map-based storage adapter.
- A JWT/JWKS plugin supporting Ed25519, RSA/PSS, and ECDSA, persisted keys,
  rotation, signing pins, remote signing, session-cache signing, payload/subject
  callbacks, authenticated token issuance, per-call options/stores, pre-resolved
  signing material, and trusted signing/verification APIs.
- Upstream-compatible symmetric encryption, ordered versioned secrets, retained
  encryption-key reads, and isolated OAuth-purpose keys. Cookie signatures use
  the current secret.
- Plugin user/session schemas, protected authority fields, creation defaults,
  synthetic-user callbacks, and native endpoint freshness checks.
- HTTP method/body validation, origin and Fetch Metadata checks, exact trusted
  origin patterns and request-scoped allowlists, safe relative/custom-scheme redirects,
  CORS responses, explicit CSRF/origin options, and memory/atomic database rate limits.
- Native request hooks with trust snapshots resolved before callbacks, request
  replacement/short-circuiting, and prepare/complete APIs for trusted transports.
- A plugin endpoint interface and an existing-user magic-link plugin.
- One-time session handoffs and trusted verification APIs, including hashed
  identifiers, atomic consumption, reservation gates and update/delete operations.
- Email OTP verification, sign-in, reset and email changes with hashed/encrypted
  storage, resend policies and attempt limits; anonymous users and guest merge hooks.
- Two-factor TOTP enrollment and verification, delivered OTPs, recovery codes,
  trusted-device rotation, per-challenge attempt caps and account lockout; native
  memory/SQLite/PostgreSQL factor storage and mapped PostgreSQL columns.
- Admin user management, roles and permission checks, bans, password setting and
  session revocation and impersonation/restoration, with current-store authorization
  and mapped plugin fields.
- Organization creation, metadata, membership, active-organization selection and
  update/delete permissions, with protected review fields, lifecycle hooks and
  mapped PostgreSQL/MongoDB persistence, invitation delivery/acceptance/rejection,
  cancellation, resend and expiry policies; dynamic role CRUD, grant checks and
  member-role updates with live authorization, member pagination/filtering/sorting,
  removal and leaving with last-owner checks. Transaction-enabled organization
  mutations serialize aggregate limits, last-owner changes and role assignment
  against deletion across independent database connections.
- Generic OIDC discovery, signature/nonce verification, profile policy callbacks,
  verified-local-email linking gates, implicit-link switches and provisioned-user
  signup controls.
- Native Redis secondary storage with GETDEL/Lua atomics, fixed counter TTLs,
  prefix-safe scans and an authenticated RESP2 TCP client.
- OAuth authorization-code orchestration with PKCE and browser-bound state, a
  provider interface, and a GitHub provider using verified email addresses. Form/JSON
  POST callbacks redirect to the cookie-bound GET. Explicit
  provider logout supports linked ID tokens, redirects, state, and provider fallback.
- OpenAPI 3.1 model/core-route, email-OTP and organization schemas, declarative custom
  endpoint input schemas, explicit metadata and an optional Scalar reference page with custom path, theme and nonce settings.
- A public HTML error endpoint with escaped descriptions and validated error codes.
- A JSON-lines test process and TypeScript facade that execute selected original
  Better Auth tests against V.

## Requirements and verification

Tested with V 0.5.2, Node.js 24, and pnpm 12. RSA/ECDSA support requires OpenSSL 3
development headers and libraries, discovered through V's `net.openssl` module.
SQLite uses V's `db.sqlite` binding
and its native SQLite dependency. The full test suite also requires `redis-server`
and `redis-cli` on PATH; its isolated Redis process disables persistence. The
PostgreSQL adapter uses V's `db.pg`/libpq binding (development headers and libraries
must be installed). PostgreSQL conformance tests start isolated temporary clusters;
provide PostgreSQL server tools on PATH or set `BETTER_AUTH_PG_BIN` to their directory.
`pnpm postgres:setup` builds a checksum-pinned PostgreSQL 18.4 under ignored
`build/deps`, requiring a C compiler and make. No global installation is performed.
MongoDB support is optional in the native library. `pnpm mongo:setup` builds the
checksum-pinned C driver 2.5.8 locally with CMake and OpenSSL 3, and prepares MongoDB
8.0.6 on macOS arm64. On other platforms set `BETTER_AUTH_MONGO_BIN` to a local
`mongod` executable. MongoDB conformance tests start a temporary replica set; they
never connect to Brand Map or Nabu databases. The full suite requires this setup.
The library itself has no V package dependencies.

```sh
pnpm install --frozen-lockfile
pnpm postgres:setup # optional when PostgreSQL server tools are already available
pnpm mongo:setup
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

For the installed VPM package, use the namespaced import below. Examples within
this repository use `import better_auth` for the local checkout.

```v
import alexvyber.better_auth

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
node scripts/import-adapter-suites.mjs
pnpm upstream:inventory
pnpm test
```

The archive checksum is pinned in `upstream.lock.json`. The importer changes
imports and the test fixture. Sign-in, email verification, crypto password,
core password reset/verification,
sign-up, session, JWT rotation,
JWT signing-override/multi-algorithm, crypto secret-rotation, and encryption-purpose
files are included in full, including the main JWT file. Its two pure TS client
type checks are identified separately and backed by native HTTP client integration
coverage. Per-file manifests record these boundaries.
Selected test bodies and assertions remain unchanged. `tests/upstream/corpus.json`
inventories the full pinned source test corpus, including currently unported files.
The shared `auth-flow.ts` and `transactions.ts` adapter suites are also preserved
in full and run against native SQLite, PostgreSQL and MongoDB. Their eight object
entries are tracked separately in `adapter-suites.imports.json`, outside the
test/spec corpus denominator. Source-preservation audits run as part of `make check`.
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
