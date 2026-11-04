# Compatibility contract

The target is observable Better Auth behavior with explicit V APIs. This release
implements a subset, not a drop-in replacement for all Better Auth configurations.
Neither shared databases nor shared cookies with a TypeScript server are supported.

## HTTP surface

The default base path is `/api/auth`.

| Method | Path                       | Behavior                                                  |
| ------ | -------------------------- | --------------------------------------------------------- |
| GET    | `/error`                   | Escaped HTML error details with validated codes            |
| GET    | `/ok`                      | Health response                                           |
| POST   | `/sign-up/email`           | User, credential account, optional initial session        |
| POST   | `/sign-in/email`           | Password verification and cookie session                  |
| GET/POST | `/get-session`           | Current user/session; optional deferred refresh on POST   |
| POST   | `/sign-out`                | Best-effort revocation, cookie expiry, optional provider logout                  |
| GET    | `/list-sessions`           | Active devices and their session tokens                   |
| POST   | `/revoke-session`          | Revoke one owned session                                  |
| POST   | `/revoke-sessions`         | Revoke all owned sessions                                 |
| POST   | `/revoke-other-sessions`   | Revoke all other devices                                  |
| POST   | `/update-user`             | Update name/image; protected fields rejected              |
| POST   | `/update-session`          | Update configured session fields; protect core fields    |
| POST   | `/change-password`         | Verify current password; optional full revocation/replacement |
| POST   | `/delete-user`             | Opt-in fresh/password/token flow; cascade accounts/sessions  |
| GET    | `/delete-user/callback`    | Consume a deletion token using an authoritative session    |
| POST   | `/request-password-reset`  | Send a single-use reset link                              |
| GET    | `/reset-password/:token`   | Validate link and redirect to trusted callback            |
| POST   | `/reset-password`          | Consume reset token, change password, optional revocation |
| POST   | `/verify-password`         | Verify the current session user's password                |
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
- Record dates and session/freshness/refresh/cache timing retain milliseconds.
  `clock` supplies NumericDate seconds; optional `clock_millis` supplies exact time
  (custom seconds-only clocks still work). New opaque-token records have optional
  millisecond deadlines; legacy seconds-based rows remain readable. Database
  sessions and opaque tokens accept equality at expiry and reject later times;
  JWT expiry uses JOSE's separate NumericDate rule. Secondary TTLs are whole seconds
  floored from the remaining millisecond duration. The native memory KV supports
  `memory_secondary_storage_with_millis` for precise test/application clocks.
- IDs and tokens are random 32-byte hex values. Database session lookup uses token
  digests; AES-GCM seals recoverable tokens with a purpose-derived key and binds
  them to the session/user identity. Listings return actual tokens for new rows.
  Legacy rows without sealed tokens retain their session-ID revocation handles.
  Secondary storage holds live session tokens and user snapshots.
- Optional images are emitted as null, including synthetic registration responses.
- SQLite tables use typed indexed identity columns plus JSON record payloads;
  they do not match upstream's physical schema. Schema v4 is owned by this project;
  migrations preserve v1 rows. Account identity columns support actual SQL aliases.
- Email verification uses upstream-compatible HS256 JWTs; repeated verification
  is idempotent. Old native opaque verification links remain readable until their
  original expiry. Password-reset tokens remain opaque expiring records. Reset
  has an independent TTL; session revocation is opt-in. Token consumption, revocation, and password writes share
  a transaction. Password-policy rejection leaves the link reusable, and a
  post-reset callback failure occurs after the successful reset has committed.
  Reset-email delivery failures retain enumeration-resistant success responses.
  Password verification requires an authoritative session and enforces length
  limits before calling the verifier. Verification supports before/after callbacks,
  optional sign-in, a timing floor on unauthenticated email lookup, and current
  session refresh. Email changes support old-address confirmation followed by
  target-address verification, enumeration-resistant responses, and canonical
  credential identity preservation.
- Password changes use an authoritative session and validate both password length
  limits before hashing. Optional revocation removes all old sessions and returns
  a fresh session token and cookies. Database/account writes roll back together;
  database-backed secondary revocation and replacement caching wait for commit.
  Secondary-only stores cannot restore deleted sessions after later failures.
- Deletion is disabled by default. `delete_user_enabled` opts in to fresh-session
  deletion, password-confirmed deletion, or expiring verification links through
  `send_delete_verification`. Tokens are consumed before destructive callbacks;
  wrong-owner attempts burn them, and after-hook failures do not restore the user.
  Callback routes require an authoritative session on stateful configurations.
  Server-only `EndpointContext.set_password` runs through `Auth.with_internal` and
  preserves existing passwordless credential account identity; it has no HTTP route.
- Magic links sign in existing users only. Registration through a magic link is
  not implemented.
- OAuth currently has a GitHub provider. The provider interface supports other
  implementations, but Google/OIDC validation is not supplied. Account linking,
  access/refresh-token persistence and refresh, and upstream OAuth error redirects
  are absent. Explicit logout providers can construct end-session URLs from stored
  account ID tokens; generic logout config supports callback/client/state parameters,
  latest-account ordering, and provider fallback. Local sign-out succeeds and clears
  cookies even if session persistence or provider URL creation fails. Generic OAuth
  discovery and sign-in are not supplied by this logout support.
- The HTML error endpoint validates error codes and escapes descriptions. Default
  page styling, custom themes, production redirects, and `onAPIError.errorURL`
  behavior remain unimplemented.
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
  Trusted `JWTSigningConfig.options` replaces the option set for one operation;
  per-call verification/key lookup can use independent stores too. The TS server
  facade mirrors shallow top-level `overrideOptions` replacement. Helper defaults
  remain independent of configured plugin options. Empty issuer/audience settings,
  fractional NumericDates, nullable claim defaults, and Date expirations are
  preserved. Key encryption settings govern interpretation of selected records.
  Explicit pins accept a key exactly at expiry and reject it one millisecond later;
  automatic lookup excludes expired/equal timestamps. `resolved_key` accepts trusted
  pre-resolved native key material without another storage lookup or expiry check.
  Schema/model aliases and complete provider/client integration remain unimplemented.
- Symmetric crypto supports upstream XChaCha20-Poly1305, versioned key envelopes,
  retired-key lookup, explicit legacy keys, JWE key rotation, and isolated OAuth
  purpose derivation. Secret environment/configuration helpers execute in V.
  Main auth configuration accepts ordered versioned `secrets`; the first secret
  signs new cookies and encrypts new data. Retained versions read encrypted JWKs,
  native sealed session tokens, and JWE caches. Unversioned upstream ciphertext
  requires an explicit legacy `secret`. Session-token/compact/HS256 cookies use
  only the current secret, matching pinned upstream; retained encryption keys do
  not silently widen cookie-signature acceptance.
- `stateless_sessions` treats the signed cookie as authoritative when no secondary
  store is configured. Native defaults enable JWE caching and refresh; refreshing
  cache/token cookies preserves the original session expiry. State-dependent
  account/user operations still need an application-owned adapter. The memory
  adapter stores these records in process; they disappear when it closes.
- `open_memory()` implements the current V storage contract with map records,
  transaction snapshots, foreign/unique-key checks, and cascades. This establishes
  coverage of the current native contract, not all upstream adapter operations,
  query filters, joins, schema options, or concurrency semantics.
- Adapters can explicitly disable native transactions. Operations then retain
  already-written records on failure and after-write hooks run immediately,
  matching nontransactional adapter semantics. Secondary-cache changes still
  cannot be rolled back as distributed transactions.
- Rate limiting is per-instance/per-route and in memory, not distributed or per-IP.
  Authentication work is serialized per instance/connection. The native HTTP
  transport buffers request bodies before the library can enforce its body limit.
- There is no automatic expiration-record garbage collector or durable email outbox.
  Email callback failure rolls back database writes, but delivered email cannot be
  recalled on a subsequent commit failure.
- An empty `base_url` resolves an origin from each HTTP request. Explicit trusted
  origin patterns support host/protocol wildcards and request-scoped callback
  allowlists. `BETTER_AUTH_TRUSTED_ORIGINS` adds environment entries. Custom schemes
  compare authorities exactly and normalize pinned paths; relative redirects reject
  ambiguous slashes, controls, and encoded path separators. `Auth.is_trusted_origin`
  and endpoint contexts share the matcher. A standalone native helper expands
  dynamic allowed-host/protocol lists; live dynamic baseURL resolution remains
  unimplemented. Plugin init supports origin contributions in the fixture, while
  general init context overrides and full response-hook parity remain unported.
  Native `RequestHookPlugin` can replace or short-circuit an HTTP request after
  trust resolution and before serialized storage execution. `prepare_request` /
  `handle_prepared` allow a trusted server transport to await application callbacks
  while preserving the trust snapshot; never accept prepared contexts from clients.
  CSRF and redirect-policy bypasses are explicit config options, and path exemptions
  match exact paths or slash-boundary children. Origin bypass also bypasses CSRF
  for upstream compatibility; when CSRF was not explicitly configured, its
  deprecation warning deduplicates per Auth instance. Structural redirect CR/LF/NUL
  rejection stays active even when origin policy is bypassed.
  Cookie names/prefixes, explicit secure overrides, and cross-subdomain domains are
  configurable and consistent across issuance/expiry, including cache chunks,
  remember markers, and OAuth state. Cross-subdomain domains default to the
  configured hostname. Per-cookie/default attributes beyond these options remain
  unimplemented; the fixture rejects them. Native storage formats still prevent
  general cookie/database sharing with an upstream server.

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

- Original upstream sign-in, email-verification, crypto password, password-reset/
  verification, sign-up, and session files run in full with
  replaced fixtures/imports and unchanged assertions. Their per-file manifests
  record the pinned source and declaration inventory. Passing these files
  does not establish coverage of the separate plugin/adapter/client suites.
- All four original JWT plugin source files run in full, including the native SQLite
  transaction/migration regression and key-generation helpers. The two pure TS
  client type declarations are labeled separately in the manifest and backed by
  an additional typed-client test exercising signup, optional/null field updates,
  sessions, JWKS retrieval, and JWT issuance against V. They validate the supported
  official TS client pairing, not a claim that V has TS compile-time generics.
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
