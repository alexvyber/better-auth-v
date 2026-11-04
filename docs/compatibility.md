# Compatibility contract

The target is observable Better Auth behavior with explicit V APIs. This release
implements a subset, not a drop-in replacement for all Better Auth configurations.
Neither shared databases nor shared cookies with a TypeScript server are supported.

## HTTP surface

The default base path is `/api/auth`.

| Method | Path                       | Behavior                                                  |
| ------ | -------------------------- | --------------------------------------------------------- |
| GET    | `/ok`                      | Health response                                           |
| POST   | `/sign-up/email`           | User, credential account, optional initial session        |
| POST   | `/sign-in/email`           | Password verification and cookie session                  |
| GET/POST | `/get-session`           | Current user/session; optional deferred refresh on POST   |
| POST   | `/sign-out`                | Revoke current session and expire cookie                  |
| GET    | `/list-sessions`           | Active devices and their session tokens                   |
| POST   | `/revoke-session`          | Revoke one owned session                                  |
| POST   | `/revoke-sessions`         | Revoke all owned sessions                                 |
| POST   | `/revoke-other-sessions`   | Revoke all other devices                                  |
| POST   | `/update-user`             | Update name/image; protected fields rejected              |
| POST   | `/update-session`          | Update configured session fields; protect core fields    |
| POST   | `/change-password`         | Verify current password; optional other-device revocation |
| POST   | `/delete-user`             | Verify password where present; cascade accounts/sessions  |
| POST   | `/request-password-reset`  | Send a single-use reset link                              |
| GET    | `/reset-password/:token`   | Validate link and redirect to trusted callback            |
| POST   | `/reset-password`          | Consume reset token, change password, revoke sessions     |
| POST   | `/send-verification-email` | Send a single-use verification link                       |
| GET    | `/verify-email`            | Consume token and verify email                            |
| POST   | `/sign-in/social`          | Start configured OAuth provider flow                      |
| GET    | `/callback/:provider`      | Complete bound OAuth code/PKCE flow                       |
| POST   | `/sign-in/magic-link`      | Plugin: email a link to an existing user                  |
| GET    | `/magic-link/verify`       | Plugin: consume link and create session                   |
| GET    | `/jwks`                   | JWT plugin: publish public signing keys                   |
| GET    | `/token`                  | JWT plugin: issue a JWT for an authenticated session       |

Core HTTP responses include `Cache-Control: no-store`; plugin endpoints control
their own cache headers. Mutations require JSON, except
email signup/signin also accept form-urlencoded data. Cookie and request headers
must be preserved by the embedding HTTP integration. CORS is explicit-origin and
credential-aware. Forwarded origin and IP headers are independently opt-in.

## Deliberate differences and current limits

- Password hashing now matches upstream scrypt parameters and encoded format,
  including NFKC normalization. Unicode data is pinned to 17.0.0, matching the
  verified Node runtime. Length limits count JS UTF-16 units. Argon2id is opt-in.
- IDs and tokens are random 32-byte hex values. Database session lookup uses token
  digests; AES-GCM seals recoverable tokens with a purpose-derived key and binds
  them to the session/user identity. Listings return actual tokens for new rows.
  Legacy rows without sealed tokens retain their session-ID revocation handles.
  Secondary storage holds live session tokens and user snapshots.
- Optional images are emitted as null, including synthetic registration responses.
- SQLite tables use typed indexed identity columns plus JSON record payloads;
  they do not match upstream's physical schema. Schema v4 is owned by this project;
  migrations preserve v1 rows. Account identity columns support actual SQL aliases.
- Email verification/reset tokens are opaque, purpose-bound, expiring records,
  not upstream's encoded token format. Reset always revokes existing sessions.
- Magic links sign in existing users only. Registration through a magic link is
  not implemented.
- OAuth currently has a GitHub provider. The provider interface supports other
  implementations, but Google/OIDC validation is not supplied. Account linking,
  provider-token persistence/refresh, and upstream OAuth error redirects are absent.
- Plugin extension covers endpoint registration, session/freshness requirements,
  user/session schema contributions, and user-creation defaults. V database hooks support mutation
  cancellation/patches and after-commit callbacks with trusted internal operations.
  Exact partial-update payloads, full hook context, arbitrary JS plugins, new-model
  schemas, request hooks, and inferred client extensions remain incomplete.
- `AdminSchemaPlugin` and `OrganizationSchemaPlugin` supply creation defaults and
  protected authority fields. Admin operations, ban enforcement, organization/team
  operations, memberships, and RBAC remain unimplemented. The schema types do not
  register those endpoints. Custom synthetic-user callbacks support enumeration
  protection with plugin fields and receive only user-defined additional inputs.
- Secondary storage supports primary sessions, optional database copies, database
  fallback, preserved expired rows, TTLs, and atomic token consumption/counters in
  the built-in memory implementation. Database-authoritative session mirroring runs
  after commit. Secondary writes are not a distributed transaction: rollback
  cleanup is best effort, and existing cache updates/deletes are not reversible.
- Cookie caches support compact HMAC, HS256 JWT, and HKDF/A256CBC-HS512 JWE.
  JWE decoding also accepts legacy A256GCM. Cache reads bind the payload to the
  signed session token, check version/expiry, filter hidden fields, bypass storage
  on a hit, and fall back to storage on invalid/expired data. Large values use
  bounded chunks; replacing a value expires stale chunks. The JWT plugin can sign
  cache JWTs with local asymmetric keys, enforcing dedicated type/audience and binding
  issuer, subject, and session-token claims.
- The JWT plugin supports Ed25519, RSA (RS/PS 256/384/512), and ECDSA
  (P-256/P-384/P-521) signing/verification, authenticated token issuance,
  automatic `set-auth-jwt` headers, configurable JWKS paths, persisted keys,
  rotation, and publication grace periods. Signing and verification are trusted
  server APIs, not HTTP routes. New private keys use upstream-compatible
  XChaCha20-Poly1305 ciphertext; older native AES-GCM key envelopes remain readable. Custom key-store reads and creates can override either or both native
  operations; callbacks run in the current context. Newly encrypted keys remain
  usable when the store assigns IDs, and older ID-bound records remain readable.
  RSA/ECDSA operations use OpenSSL 3 through a native C interface; policy remains
  in V. RSA generation currently accepts 2048–8192-bit keys. Remote URL mode
  disables local JWKS publication. Custom signing callbacks receive complete native
  claims without minting local keys; cookie caches require local signing. JWT
  expiration options accept absolute numeric values, dates, and upstream duration
  strings; an explicit payload `exp` wins. Remote
  public-key fetching is not implemented (matching the pinned verifier, which reads
  the configured local key store). Trusted signing supports key-ID and algorithm
  pins, configured extra-algorithm lazy minting, and protected profile headers.
  Resolved alg/kid override caller header fields; custom signers receive all three
  callback arguments. Session JWTs support payload and subject callbacks, including
  null-subject fallback to the user ID. An empty configured base URL resolves from
  the current request; direct calls remain unresolved and emit upstream warnings.
  Per-call option replacement and the two client type declarations in the main
  JWT test file remain unported.
- Symmetric crypto supports upstream XChaCha20-Poly1305, versioned key envelopes,
  retired-key lookup, explicit legacy keys, JWE key rotation, and isolated OAuth
  purpose derivation. Secret environment/configuration helpers execute in V.
  These helpers do not yet enable full rotation of authentication cookies or
  all persisted native credentials through the main auth configuration.
- `stateless_sessions` treats the signed cookie as authoritative when no secondary
  store is configured. Native defaults enable JWE caching and refresh; refreshing
  cache/token cookies preserves the original session expiry. State-dependent
  account/user operations still need an application-owned adapter. The memory
  adapter stores these records in process; they disappear when it closes.
- `open_memory()` implements the current V storage contract with map records,
  transaction snapshots, foreign/unique-key checks, and cascades. This establishes
  coverage of the current native contract, not all upstream adapter operations,
  query filters, joins, schema options, or concurrency semantics.
- Rate limiting is per-instance/per-route and in memory, not distributed or per-IP.
  Authentication work is serialized per instance/connection. The native HTTP
  transport buffers request bodies before the library can enforce its body limit.
- There is no automatic expiration-record garbage collector or durable email outbox.
  Email callback failure rolls back database writes, but delivered email cannot be
  recalled on a subsequent commit failure.
- An empty `base_url` resolves an origin from each HTTP request. Explicit trusted
  origins remain exact strings; wildcard/dynamic allowlists, cross-subdomain
  cookie sharing, and secret rotation are not implemented.

## Remaining Better Auth scope

PostgreSQL/MySQL/MongoDB adapters, schema generation/introspection, full secondary
storage parity, full stateless/account-cookie behavior, complete JWT/JWKS plugin parity,
custom-field validators/transforms,
general database-column mapping, richer hooks,
username/email OTP/phone authentication, TOTP/recovery codes, passkeys, admin,
organizations/teams/RBAC, API keys, JWT/JWKS, OAuth/OIDC provider functionality,
SSO/SAML/SCIM, and payment/integration plugins remain unimplemented.

Unsupported capabilities are not advertised as working endpoints. Source test
exclusions are listed in the per-file manifests under `tests/upstream`. The full
source inventory is `tests/upstream/corpus.json`. Passing the selected
tests establishes only their covered behavior, not complete upstream parity.

## Test boundaries

- Original upstream sign-in, password, sign-up, and session files run in full with
  replaced fixtures/imports and unchanged assertions. Their per-file manifests
  record the pinned source and declaration inventory. Passing these four files
  does not establish coverage of the separate plugin/adapter/client suites.
- The original JWT rotation, signing-override, and multi-algorithm files run in full.
  The main JWT file runs every runtime declaration, including the native SQLite
  transaction/migration regression; its two client type declarations are unported. The JWT plugin file is
  partially imported: its algorithm matrix, general signing, custom-store/path,
  key-algorithm authority, remote-signing/URL, expiration utility, and unresolved-origin suites run, with remaining declarations explicitly
  unported in its manifest. Key generation in its utility tests also runs in V.
- The complete upstream crypto secret-rotation and OAuth purpose-isolation files
  also run with native crypto helpers. Independent TS crypto exchanges ciphertext,
  JWEs, and encrypted private JWKs with V.
- Differential tests compare the published TS server and V on supported scenarios,
  ignoring inherently random IDs/tokens/timestamps and documented record-format
  differences.
- Additional Vitest tests exercise the real official client, lifecycle/security
  scenarios, deterministic time, and token replay. Independent Node HMAC and JOSE
  checks validate V-issued cookies; V accepts independently encrypted CBC/GCM
  cache payloads.
- V tests cover real Argon2, Unicode NFKC conformance, transaction failure/rollback,
  safe SQL parameters, sealed/hashed session storage, secondary-store TTLs and
  atomic consumption, lifecycle hooks, column aliases, migrations, file persistence,
  and OAuth state binding.
- The memory-adapter fixture descriptor selects V maps; it does not instantiate
  a TS database. Upstream endpoint-context helpers transport requests to V, which
  decides cache policy, strictness, persistence, and forwarded cookie headers.
- Plugin endpoint descriptors run session/freshness checks in V before invoking
  their JS business callback within the native context. Unsupported middleware,
  constructor options, and endpoint schema features fail explicitly.
- Raw auth/dialect descriptors in the transaction fixture select V SQLite with
  explicit migrations. Transaction callbacks execute in V; currently only the
  token endpoint and internal operations are exposed inside that fixture scope.
  Nested transaction wrappers share the existing native transaction.
- Native HTTP integration runs a real V server and checks credentials, cookies,
  CSRF, revocation, and persistence after restart.

The fixture captures email events and logger output. Bidirectional callback frames
execute password hash/verify, delivery, registration policy, and existing-user
callbacks inside the V operation; callback failures can roll database writes back.
Database hooks and internal-adapter spies can invoke nested V operations in their
existing context. The fixture exposes only explicitly implemented internal methods;
arbitrary upstream internals remain unported. V timer tests receive the test's
current time on each request. This does
not simulate a background scheduler.
