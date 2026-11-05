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
| POST   | `/callback/:provider`      | Redirect form/JSON provider callbacks to the bound GET    |
| POST   | `/sign-in/magic-link`      | Plugin: email a link to an existing user                  |
| GET    | `/magic-link/verify`       | Plugin: consume link and create session                   |
| GET    | `/one-time-token/generate` | Plugin: issue a token bound to the authenticated session |
| POST   | `/one-time-token/verify` | Plugin: consume once and return the existing session |
| POST   | `/email-otp/send-verification-otp` | Plugin: send a rotating or reusable email code |
| POST   | `/email-otp/check-verification-otp` | Plugin: check a code without consuming it |
| POST   | `/email-otp/verify-email` | Plugin: consume a code and verify email |
| POST   | `/sign-in/anonymous` | Plugin: create a protected anonymous identity and session |
| POST   | `/delete-anonymous-user` | Plugin: delete the authenticated guest and revoke access |
| POST   | `/sign-in/email-otp` | Plugin: consume a code and sign in or register |
| POST   | `/email-otp/request-password-reset` | Plugin: send a password-reset code |
| POST   | `/email-otp/reset-password` | Plugin: consume a code and reset the password |
| POST   | `/email-otp/request-email-change` | Plugin: request an authenticated email change |
| POST   | `/email-otp/change-email` | Plugin: consume the email-change proof |
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
- New record IDs default to 32 alphanumeric characters; session/opaque tokens remain
  random 32-byte hex values. UUID and application generators are supported for
  users, sessions, accounts, JWKs and trusted verification records. UUID reservation
  IDs deterministically format the digest with version-five/variant bits; user
  callbacks receive logical model names. New opaque reset/OAuth/deletion records
  use the trusted verification APIs; legacy digest-keyed records remain readable. Persisted serial
  and database-generated ID strategies remain unsupported. Database session lookup uses token
  digests; AES-GCM seals recoverable tokens with a purpose-derived key and binds
  them to the session/user identity. Listings return actual tokens for new rows.
  Legacy rows without sealed tokens retain their session-ID revocation handles.
  Secondary storage holds live session tokens and user snapshots.
- Optional images are emitted as null, including synthetic registration responses.
- SQLite tables use typed indexed identity columns plus JSON record payloads;
  they do not match upstream's physical schema. Schema v6 is owned by this project;
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
  not implemented. Successful mailbox proof strips accounts and sessions attached
  before email verification, then issues session-cache cookies and OTT headers
  through the normal session pipeline.
- OAuth supplies GitHub and a Google authorization-code provider. Google constructs
  PKCE grants, exchanges through a redirect-refusing native HTTP transport, decodes
  the profile from the authenticated token response, and enforces hosted-domain
  restrictions. The test transport delegates only HTTP bytes to Node/MSW; provider
  decisions and persistence stay in V. The shared authorization builder handles
  PKCE, reserved parameters, endpoint/redirect overrides and ordered form-encoded
  query updates. Google accepts per-request scopes, login hints and additional
  parameters, rejects reserved/malformed input, preserves repeated scopes and
  sets Location for redirect responses. Full WHATWG URL normalization and the
  remaining state/account/provider options are still incomplete.
  Google also supports direct ID-token
  credentials with RS256 pinning, trusted Google key retrieval, required claims,
  issuer/audience/nonce checks, hosted-domain policy, 30-second clock tolerance and
  a one-hour maximum age. Client-ID arrays and disabling ID-token sign-in are
  supported. The direct branch creates sessions/account cookies without code-flow
  state and persists the pinned branch's access/ID-token fields. Google preserves
  unverified email claims under its default policy. Broader provider options/
  callbacks and email-verification policies, general account linking, automatic token
  refresh and complete upstream OAuth error redirects remain incomplete. OAuth
  identities can supply access/refresh/ID tokens, precise token expiries and scopes;
  code exchanges persist them, retain omitted refresh tokens and union granted scopes.
  Access/refresh token encryption is optional and migration-aware. Account hooks
  cannot change the selected OAuth identity binding. Explicit logout providers can construct end-session URLs from stored
  account ID tokens; generic logout config supports callback/client/state parameters,
  latest-account ordering, and provider fallback. Local sign-out succeeds and clears
  cookies even if session persistence or provider URL creation fails. Generic OAuth
  discovery and sign-in are not supplied by this logout support.
- Standalone native token helpers build authorization-code, refresh-token and
  client-credentials requests with public, secret-post, secret-Basic, private-key
  JWT and custom callback authentication. They enforce credential/assertion
  conflicts, preserve repeated resource indicators, protect refresh-owned keys,
  refuse redirects and normalize returned scopes/deadlines. Native assertion
  signing accepts JWK and unencrypted PKCS#8 inputs. These helpers do not yet supply
  account-refresh APIs, refresh scheduling or complete provider integration;
  broader response coercion and transport/error-shape parity remain incomplete.
- Native generic OAuth/OIDC supports discovery, explicit endpoint overrides, PKCE,
  token-endpoint Basic/body authentication, application token/profile callbacks,
  JWKS signatures, issuer/audience/time/nonce checks, direct ID tokens and safe
  missing-metadata/provider handling. Signup and implicit-signup gates, trusted
  same-email linking and new-user/error redirects support Nabu's configuration.
  Public password signup can be disabled independently of provisioned login.
  The full ID-token verification suite and selected discovery/signup source cases
  run unchanged. Nabu integration tests cover verified pre-provisioned identity,
  unprovisioned/unverified rejection, Basic/PKCE and replay prevention, including
  a real MongoDB provisioning callback and login. Discovery retry/cache, provider refresh callbacks,
  full linking/options behavior and actual Nabu application integration remain open.
- Rate limiting supports per-instance memory and atomic database backends. SQLite
  schema v5 persists rolling count/lastRequest values behind an immediate transaction
  so independent connections cannot overrun a shared budget. Default sensitive-path
  rules, email-OTP overrides, ordered static wildcard/disabled rules, exact window
  boundaries and JSON 429/X-Retry-After responses are covered by upstream cases.
  Counters survive failed authentication transactions; trusted API calls bypass
  HTTP quotas. Static longest-window retention protects longer-lived database rows.
  Distributed secondary counters, dynamic/custom stores, environment
  defaults and complete IP/proxy normalization/policy remain open.
- The native one-time-token plugin supports precise expiry, custom generation,
  plain/SHA256/custom hashed token storage, client-request restrictions, optional
  cookie suppression and OTT headers when a session cookie is set. Tokens redeem
  the existing session, expire with it and stay burned after failed session lookup.
  Public V generation/redemption APIs and trusted verification create/find/consume
  operations are available. Verification APIs support ordered plain/hashed prefix
  policies, metadata, hook patches/vetoes, latest-record selection/stale cleanup,
  atomic secondary consumption and optional DB copies. Custom identifier hashing and default-string-ID reservation
  gates support UUID IDs too. Persisted serial IDs remain unsupported. Verification
  settings also govern native reset, OAuth state, deletion, magic-link, OTT and
  email-OTP records; legacy digest-keyed rows are read as a migration fallback. Update/delete-by-identifier APIs are also available.
  A native Redis secondary store is now available; application-specific fallback
  wrappers and complete database integration remain separate work.
- The native email-OTP plugin implements code creation/read APIs, delivery, checking,
  verification, sign-in/signup, password reset and authenticated email changes.
  Plain, SHA256, encrypted and application-provided codecs, resend rotation/reuse,
  attempt budgets, plugin rate limits and default-verification overrides are covered
  by the complete upstream email-OTP source file. Brand Map's hashed/rotating/five-
  attempt configuration has independent coverage. Unverified account promotion coordinates through database reservation keys and
  re-reads before deleting old account links and sessions. Complete callback contexts
  and additional database adapters remain open.
- Native Redis secondary storage supports prefixed get/set/delete, GETDEL with
  cached Lua fallback only for unknown-command errors, atomic INCR/EXPIRE counters,
  SCAN-based listing/deduplication and non-atomic clearing with literal glob prefixes.
  A Redis client interface supports application transports; the built-in RESP2 TCP
  client supports AUTH/ACL names, database selection, fresh connections, bounded
  replies and read/write deadlines without replaying interrupted mutations. TCP
  dialing follows the V runtime timeout; TLS, pooling and Brand Map's application-
  specific tolerant/strict wrapper behavior remain open. All upstream Redis source
  cases run unchanged, plus real-server cross-instance session/OTT checks.
- The native anonymous plugin supports protected guest identities, custom email/name
  generators, explicit deletion and guest-to-account callbacks before cleanup.
  Email/password, email verification, email OTP and Google OAuth flows are covered,
  including recovering the guest from server-owned OAuth state on a cookie-less
  callback and rejecting client-supplied guest IDs. Disabling cleanup preserves the
  guest. Generic-OIDC cookie-less callback integration is now covered too; two
  direct middleware-object unit fixtures remain unported; schema aliases still use the native JSON payload schema.
- The HTML error endpoint validates error codes and escapes descriptions. Default
  page styling, custom themes, production redirects, and `onAPIError.errorURL`
  behavior remain unimplemented.
- Plugin extension covers endpoint registration, session/freshness requirements,
  user/session schema contributions, and user-creation defaults. V database hooks support mutation
  cancellation/patches and after-commit callbacks with trusted internal operations.
  Exact partial-update payloads, full hook context, arbitrary JS plugins, new-model
  schemas, request hooks, and inferred client extensions remain incomplete.
- `AdminSchemaPlugin` and `OrganizationSchemaPlugin` supply creation defaults and
  protected authority fields. `AdminPlugin` now supplies native admin operations and
  ban enforcement as described below. `OrganizationPlugin` supplies the scoped
  organization and membership foundation and invitation APIs described below; teams and remaining integration contracts remain open. The schema-only types do not register those endpoints. Custom synthetic-user callbacks support enumeration
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
- Native cookie utilities parse request/response cookie headers, preserve last-value
  precedence and insertion order, validate wire octets before percent-decoding, and
  re-encode semantic values when merging headers. Public session selection prefers
  secure cookies, supports legacy separators, and distinguishes empty secure values
  from absence. Canonical chunk reconstruction and pending-cookie cleanup are
  available separately. Response attribute parsing supports HTTP dates; full
  JavaScript Date-string coercion (including nonstandard numeric strings and exact
  local-time/two-digit-year rules) remains incomplete.
- Account cookies support rotated-secret JWE, configurable attributes/lifetimes,
  bounded chunks, stale-chunk cleanup and logout expiry. Session-cache writes bind
  account data to the current user when an account store is configured, refreshing
  matching data and expiring another user's stale data. Pending fresh account
  cookies take precedence over stale request cookies during a user switch. Native
  callers can select the binding policy explicitly; the default follows the native
  stateless setting. This coverage does not establish complete stateless OAuth,
  account APIs, token refresh, or every provider integration.
- `get_cookie_cache` reads standalone snapshots without database access or a
  separate session-token cookie. It verifies compact HMAC, HS256/384/512 JWT,
  native/upstream JWE, and supported asymmetric or symmetric public JWKS profiles.
  Public-JWKS reads enforce profile type, issuer/audience and subject/token binding;
  the first matching key wins. Schema defaults and unknown fields are retained.
  Literal/callback versions run before final cache/session expiry checks. Missing
  secrets throw only when a snapshot exists; invalid snapshots miss the cache.
  ISO dates are validated natively and reconstructed as Dates by the TS facade.
  Full exotic JavaScript coercion and Date normalization remain separate work.
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
- Rate limiting supports per-instance memory and atomic SQLite/PostgreSQL/MongoDB storage;
  route keys include resolved client IP when supplied by the trusted integration.
  Authentication work is serialized per instance/connection. Body limits are opt-in
  (`max_body_bytes > 0`); the default zero imposes no library cap, matching upstream.
  The native HTTP transport buffers bodies before this optional limit is enforced.
- There is no background expiration-record garbage collector or durable email outbox.
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
  configured hostname, preserving IPv6 brackets. A native `CookieFactory` supports
  secure/default/domain policy and default/per-cookie attribute precedence; its
  descriptors also understand explicit dynamic protocols, although live dynamic
  baseURL resolution remains unimplemented. Without a configured static base URL,
  auth captures its production fallback at initialization. Request HTTPS alone does
  not change that choice, except when cross-domain cookies rebuild for the resolved
  base URL. HTTP output supports custom paths, domains, HttpOnly, SameSite, Secure,
  Partitioned, expiry dates and prefix invariants. Session token lifetimes override
  descriptor Max-Age; cache lifetimes use per-cookie configuration and rememberMe.
  Malformed/unsafe attributes and oversized Max-Age are rejected at initialization.
  Cache durations, refresh thresholds and per-cookie lifetime overrides retain
  fractions. Compact expiry applies Date's millisecond clipping; JWT/JWE expiry
  preserves fractional NumericDates, while HTTP Max-Age is floored. Existing integer
  crypto APIs remain available alongside explicit fractional-lifetime APIs. General
  HMAC verification supports explicit algorithm allowlists, fractional times and
  numeric iat types. The general crypto-helper facade accepts HS256/384/512;
  email verification remains pinned to HS256. Session
  token TTL configuration still uses whole seconds, and exact invalid-option/error
  timing remains incomplete. Native storage
  formats still prevent general cookie/database sharing with an upstream server.

## Remaining Better Auth scope

Complete PostgreSQL/MongoDB query/plugin-schema support, a MySQL adapter,
schema generation/introspection, full secondary
storage parity, full stateless/account-cookie behavior, complete JWT/JWKS plugin parity,
remaining output field transforms/validators and default/transform combinations,
remaining database-column mapping options, richer hooks,
username/phone authentication, remaining two-factor integration details, passkeys, remaining admin integration,
remaining organization operations, teams, API keys, OAuth/OIDC server functionality,
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
- The complete cookies source is imported: 97 declarations run as 115 cases against
  native helpers and auth flows. Field filtering, sensitive-session cache bypass,
  account-cookie user switching, and all chunking tests
  are included, including oversized-cache fallback and actual serialized-line budgets.
  Native standalone readers report schema warnings through a supplied logger;
  the fixture forwards native events to the active endpoint logger. Broader logger
  context/metadata parity, including chunking debug metadata, remains incomplete.
- The complete OAuth token-utility source runs 13 native-backed cases, covering
  encryption, null/undefined representation, and plaintext-token migration. Nine
  independent Google/account cases verify grants, storage/encryption, token dates,
  scope union, refresh-token retention, hook binding, redirect refusal and chunks.
- The complete Google provider source runs 15 native-backed cases. A native ID-token
  verification kernel and ten additional integration cases cover required claims,
  forgery/algorithm rejection, clock/age boundaries, nonce, audience arrays, disabled
  sign-in, JWK metadata, critical headers and direct-session issuance. Standalone
  verification iterates matching keys; the provider resolver selects the first,
  matching their separate source contracts. A shared native provider policy and
  standalone ID-token verification profiles also support Apple, Cognito, Facebook
  and Microsoft trust/key-selection rules, callback precedence and tenant binding.
  These profiles do not supply the providers' complete OAuth/account flows;
  Facebook remote-key caching remains incomplete. The complete shared verifier
  source runs 25 native-backed cases, including supplied override/custom/key/claim
  callbacks and fail-closed behavior. Another 22 independent cases verify real
  signatures for all five profiles, tenant binding, callback order/context,
  algorithm/header rejection before key retrieval, CryptoKey hash/type/usage
  preservation and the RSA 2048-bit minimum, plus nine additional signing algorithms.
  Other provider and OAuth/account source
  files remain unported; these cases do not establish full Google/OAuth parity.
  Four independent helper contracts compare V with the published TS implementation
  on malformed encodings, attribute metadata, ordered merging, and secure selection.
  Another 14 standalone reader cases use independent HMAC/JOSE/upstream ciphertext
  and compare schema/defaults, expiry, async versions, key selection and profile
  binding with the published reader.
  Another 22 factory/configuration cases compare descriptors with a fresh official
  process and check actual issuance/expiry, captured security defaults, prefix rules,
  and cache lifetimes across all supported formats.
- Complete shared authorization-URL (4) and Basic-credential (13) source cases run
  against V. Five social source cases cover Google's includeGrantedScopes options;
  its remaining 80 declarations are explicitly unported. Another 28 independent
  helper/HTTP cases cover ordered queries, native PKCE, async options callbacks,
  Unicode/malformed encodings, reserved parameters and Google request integration.
  Eight more ID-token cases compare empty issuer lists and JOSE duration boundaries.
- Three complete token/assertion source files run all 41 cases against V. Eight
  independent cases verify PEM signatures with JOSE, real HTTP grant requests,
  response-time clocks, resource indicators and callback context/errors. The full
  corpus now contains 406 unported files and two partial imports.
- All 14 one-time-token source cases and all 12 internal-adapter consumption cases
  run against V. The other 58 declarations in the internal-adapter source remain
  unported. Nine independent cases and two native tests cover hashing, typed APIs,
  race/burn/expiry behavior, hook patches, identifier policies and cookie/header
  lifecycle. These cases do not establish complete internal-adapter parity.
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


## Native PostgreSQL adapter

`open_postgres(PostgresOptions{...})` opens one libpq connection. Pass it to `new`
and explicitly call `auth.migrate_storage()` for schema creation. Auth initialization
configures additional/plugin user and session fields before migrations. Existing
application schemas may be used without running migrations.

Options include `connection_string`, `schema`, `uuid_ids`, per-model `tables`, logical
to physical `fields` maps, and whitelisted `column_types` overrides. Configure auth
`id_strategy: 'uuid'` when PostgreSQL IDs are UUID columns. Core users, sessions,
accounts, verifications, JWKS and rate limits occupy physical columns. Quoted
identifiers, snake-case mappings, UTC timestamps and extra user/session fields are
supported; inserts omit application-owned columns so database defaults apply.
Updates patch changed configured fields and read back user records before hooks
or session-cache mirroring, retaining concurrent changes to untouched fields.

Session rows contain plaintext tokens, as in the pinned upstream schema. Proof
consumption uses `DELETE ... RETURNING`, reservations rely on primary-key conflicts,
and database rate limits use atomic guarded upserts across connections. These
contracts are tested using separate native bridge processes. Backend copies of
original sign-in, sign-up, core-session, one-time-token, email-OTP and reset tests
preserve their assertions and record their execution surface in manifests. These
copies add backend coverage, not unique imported upstream files.

This is a foundational adapter, not verified Brand Map database interchange. Full
Prisma schema/migration equivalence, arbitrary query/filter/join APIs, plugin-owned
tables, introspection, pooling/reconnect policy, serial IDs and live TypeScript/V
coexistence remain unverified or unimplemented. No tests connect to Brand Map or
Nabu databases. Native MongoDB coverage is described below.


## Two-factor authentication

`TwoFactorPlugin` contributes protected `twoFactorEnabled` and implements enable,
disable, TOTP URI/verification, backup-code generation/verification, and delivered
OTP send/verification routes under `/two-factor/`. `TwoFactorOptions` configures
issuer, TOTP digits/period, passwordless handling, optional immediate enrollment,
OTP storage/delivery/expiry/attempts, recovery-code storage/generation and device/
challenge lifetimes. Plain, hashed, encrypted and supplied OTP codecs are supported;
recovery codes support plain/encrypted/supplied storage. Secrets use native symmetric
encryption with the configured retained keys. Imported `base32:` secrets decode
before HMAC-SHA1 verification. Native vectors cover RFC 4226 and RFC 6238.

Email/password sign-in creates a signed, expiring challenge and removes the pending
session before any JWT/OTT issuance. Valid TOTP/recovery submissions consume a
per-challenge gate, and completion atomically burns the challenge before creating
a session. Recovery codes are persisted as used before session creation. Failed
attempts persist across requests; factor records carry shared account lockout state.
PostgreSQL locks factor rows across independent connections. OTP-only accounts
without a factor row use the OTP attempt cap, matching upstream's current limit.
Trusted devices require live server records and rotate on use. Disabling removes
factor records, rotates the current session and revokes the supplied device record.
HTTP two-factor routes use the upstream three-per-ten-second rule when rate limiting
is enabled; trusted calls bypass HTTP limits. The typed `AuthResult` exposes a
`two_factor_redirect` flag, methods and response headers for pending sign-ins.

TOTP generation and viewing recovery codes are trusted-only routes; HTTP requests
receive 404. `call_result` preserves unexpected native server errors for trusted
transports; `call`/HTTP handling still return sanitized responses. Authenticated
re-verification does not issue a replacement session or clear account lockout state.

All 71 main upstream cases pass. Additional imported attempt/security/lockout cases
bring coverage to 91 runtime cases, repeated on PostgreSQL. The server-error attempt
case runs unchanged in its own fixture: the serialized bridge can spend all allowed
concurrent guesses in the earlier test, exhausting the shared account budget. The
original shared-account suite ordering remains unverified, so that file remains a
partial import. Legacy JavaScript adapter fallbacks, direct atomic-method injection,
username/phone sign-in probes and JavaScript `newSession` middleware probes remain
explicit exclusions. The other selected cases cover cookie/chunk scrubbing, stale
replays, expiry, concurrency and mixed-factor account limits. Three integration
contracts cover JWT/OTT ordering, application fixed-code storage and cross-process
PostgreSQL redemption; another checks the HTTP plugin rate rule. This does not prove
all plugin/framework/database combinations or live Brand Map integration.


## Additional-field input rules and uniqueness

`AdditionalField.validate_input` and `transform_input` accept/return native JSON
values through `FieldInputResult`. V applies validator precedence, validation
messages and the synchronous Standard Schema restriction. Validators run before
native type checks so they may produce the typed stored value. Defaults and
protected input follow the existing create/update policy. The TypeScript fixture
invokes supplied Standard Schema schemas or application transforms; it does not
implement the authentication/field decision flow.

`unique` configures native map checks and SQLite/PostgreSQL unique indexes for
user/session additional fields. Optional absent/null values remain distinct from
owned values. SQLite unique indexes require an explicit `auth.migrate_storage()`
after configuration; writes fail closed until configured indexes exist. Migrations
are idempotent. PostgreSQL supports `field_name` (`fieldName` metadata in fixtures)
as a fallback column alias when no explicit adapter field mapping is supplied.
Existing application schemas remain the application's migration responsibility.

Provider profile input now filters protected fields, applies validators/transforms
and preserves create-time defaults. Google and generic provider mapping retain
configured additional fields. Optional `update_user_info_on_link` syncs allowed
fields on implicit account linking and seeds the new session with the updated row;
identity email/verification remain separate. Invalid profile updates do not cancel
the link. PostgreSQL wraps this optional sync in a savepoint so a constraint error
does not abort the new account binding. It does not update every subsequent login.

Five original upstream profile-input/linking cases pass unchanged on SQLite and
PostgreSQL. Seven independent cases cover Brand Map username validation, input
transform precedence, async rejection, map/SQLite uniqueness, concurrent PostgreSQL
uniqueness/aliases and failed profile-sync recovery. Output transformations,
remaining default/transform combinations, complete schema/query support and exhaustive index/type/error
mapping remain open. These tests do not establish full linking or provider parity.


## Implicit account-linking policy

With account linking enabled, an existing unbound local account must have verified
email by default, including when the identity provider is trusted. Linking is
permitted when the local policy passes and either the provider is trusted or the
provider reports verified email. `disable_implicit_linking` blocks these automatic
bindings while leaving new-user registration controlled separately. Existing bound
provider accounts continue to use their canonical provider subject.

The pinned upstream `requireLocalEmailVerified: false` legacy opt-out has an explicit
native counterpart, `require_local_email_verified: false`; verified provider email
then promotes the local flag after the new account binding passes validation.
Google callback rejections use the account-not-linked redirect, as generic OIDC
callbacks already did. Explicit linkSocial endpoints remain unimplemented.

Ten original upstream linking-policy cases run unchanged on SQLite and PostgreSQL
text-ID schemas (those cases deliberately supply non-UUID IDs). Existing UUID
PostgreSQL profile and two-factor matrices remain separate. Four new Nabu contracts
cover rejection of an unverified provisioned local account, the explicit opt-out,
the implicit-link switch and an application callback verifying the row in PostgreSQL
before native linking. Native MongoDB provisioning and storage/index/TTL contracts
are now covered as described below; deployment in the Nabu application is still open.


OTP resends replace the earlier purpose/email or challenge proof before persisting
the new value, including when both requests share exactly the same millisecond.
Frozen-clock SQLite and PostgreSQL contracts retain the latest delivered hashed
code and reject its predecessor. Proof deletion hook timing therefore occurs on
replacement; exhaustive source hook-sequencing parity remains open.


## Native MongoDB adapter

`open_mongo(MongoOptions{uri: ..., database: ...})` provides typed core storage
using the official C driver. Build the optional backend with `-d mongodb` after
`pnpm mongo:setup`. Its BSON encoder is written in V; arbitrary JSON objects that
look like Extended JSON remain ordinary objects. ObjectIds, binary UUID subtype 04
and BSON dates are introduced only at known model fields. Custom ID generators
preserve string IDs, even if they look like ObjectIds. Mapped collection names,
core field names and additional-field `field_name` aliases are supported; paths
containing dots or starting with `$` are rejected. IDs always use `_id`.

Call `auth.migrate_storage()` explicitly after configuring Auth. Migrations create
core collections, unique email/token/provider-subject/rate-limit-key indexes,
session expiry TTL and reference/identifier indexes. Scalar additional-field
uniqueness uses partial indexes so absent values do not collide. Migrations can
fail on existing duplicates and do not clean application data. No application DB
was accessed during verification.

Auth serializes each client. Replica-set transactions commit/roll back core
writes and application callback failures; independent Auth instances need separate
connections. Indexed plain-token lookups avoid scanning sessions. Consumption uses
MongoDB `findAndModify` deletion; reservation insertion uses `$setOnInsert` so an
existing reservation does not abort its transaction. The shared HTTP limiter uses
an atomic guarded aggregation update. Cursor handles retain exact 64-bit values
through the JSON bridge, including `getMore` pagination.

284 unchanged selected upstream auth cases repeat on a temporary MongoDB replica
set: sign-in, sign-up, core sessions, one-time tokens, email OTP, password reset and
the main two-factor suite. These are repeated cases, not newly ported source files.
Independent contracts check BSON types, mapped fields and uniqueness, preservation
of application columns, rollback, shared quotas, TTL deletion, pagination and
Nabu's provisioning callback plus signed OIDC login/replay rejection.

This is not complete MongoDB adapter parity. The original MongoDB adapter source
suite remains unported: generic queries/joins, configured compound-index factories,
introspection, lazy index creation, driver/session mocks, transient transaction body
retries and exhaustive ambiguous-commit/abort semantics need further work. The C
driver handles its own protocol-level retries; Auth does not replay application
callbacks on transaction conflicts. Conflicts fail closed. Optional OAuth profile
sync has no MongoDB savepoint and can roll back the enclosing binding if a database
error aborts the transaction. Two-factor contention relies on transactions; atomic
guarded factor updates without transactions remain open. No general MongoDB
pooling facade, nested field mapping, arbitrary plugin schema or actual Nabu
application migration is claimed.


## Native admin operations (partial)

`AdminPlugin{options: AdminOptions{...}}` supplies user creation/get/update/removal,
role changes, banning/unbanning, password setting, user/session listing, individual
and bulk session revocation, permission checks and impersonation/restoration. The existing `AdminSchemaPlugin`
continues to supply only schema/default contributions. Default admin/user grants,
custom role permission statements, comma-separated roles, configured admin IDs,
custom ban messages, default ban reasons/durations and millisecond expiry are
supported. Role/ban/email changes require their separate permissions; passwords and
primary IDs cannot be written through profile updates. Protected plugin fields
support explicit column aliases. Uniqueness/type constraints still belong to the
configured storage adapter and its migration.

Privileged requests check the current stored session and user rather than trusting
a cached role. Primary secondary-storage sessions are checked for revocation too.
HTTP callers need a valid session; trusted headerless creation and permission
checks can provision/inspect users without one. The native trusted API distinguishes
such calls from HTTP requests; full upstream header-presence/error precedence and
stateless admin behavior remain incomplete. Bans revoke sessions through native
storage/cache paths. Session creation also checks bans outside HTTP contexts,
clearing expired bans before proceeding. Admin-created users run the provisioning
gate and receive configured scalar additional-field defaults.

90 unchanged upstream cases pass on SQLite, PostgreSQL UUID columns and MongoDB
ObjectIds (270 repeated runtime cases), including the complete 70-case main admin
suite. The fixtures supply the upstream test-instance Google/linking defaults. Thirteen independent contracts cover Brand
Map's `platform-admin`/curator grants, stale cookie snapshots, primary secondary
revocation, trusted provisioning versus HTTP access, empty role/action tables,
individual session revocation, password provisioning, mapped ban columns and precise
default ban durations. Twelve additional impersonation contracts check persistence
markers, custom cookie prefixes, expiry, filtering, deletion/replay, forged cookies,
revoked original sessions and role demotion on all three adapters. Five native
functions cover permission composition, constructor/schema checks, internal bans,
creation-hook overrides/ID isolation and failed OAuth binding rollback.

Impersonation requires the user impersonation grant and a separate admin-target
grant (or the explicit legacy opt-in). The temporary session expires independently,
has no persistent browser cookie and carries a protected owner ID. A signed
`admin_session` cookie references the original session and remember preference.
Restoration checks that reference and owner, deletes the temporary session, clears
the reference cookie and returns the current stored user. Ordinary user session
listing excludes impersonation sessions. Banned OAuth callbacks consume state,
roll back pending account writes and redirect to the validated error callback with
`BANNED_USER` and the configured message; query parameters and fragments survive.
Direct ID-token sign-in continues to return a JSON error.

General endpoint hook composition, original hook-preloaded revocation tests,
numeric-ID/username variants, pure client/constructor-only source probes and the
remaining source cases are still unported. Native list filtering/sorting currently
uses typed adapter scans rather than a complete database query API; collation,
array/number filter coercion, arbitrary additional-field transform sequencing and
complete validation/error timing still need work. No organization membership/RBAC
or application migration is implied by the admin feature set.


## Organization foundation

`OrganizationPlugin` implements create/update/delete, slug checks, organization
metadata/full views, membership lists, active organization selection and trusted
server-only member creation. Authorization loads current membership; static role
grants require one role to satisfy the complete requested permission set.
Brand Map's disabled public creation, creator hook and protected review defaults
are covered on SQLite, PostgreSQL and MongoDB. Lifecycle hook failures roll back
organization and membership writes. PostgreSQL updates preserve external review
changes and return the current stored row. MongoDB organization/member references
use ObjectIds and creation timestamps use BSON dates.

Four scoped model schemas support additional fields, validation and mapped
PostgreSQL/MongoDB tables/collections and fields. SQLite migration 7 adds payload
organization/member/invitation/role tables, constraints and configured unique indexes;
it does not implement upstream physical column aliases or a generic query API.
24 unchanged organization CRUD source cases run on each backend (72 repeated
cases), with nine owned foundation integration cases and four native test functions.
The CRUD PostgreSQL fixture keeps UUID references and explicitly uses a text
invitation primary key for the upstream hook-supplied custom ID case. The
source fixture explicitly translates upstream test-context defaults that skip
origin/CSRF checks; production defaults and independent HTTP contracts stay strict.

Teams, generic hook composition and
full organization source coverage remain open. Application databases are untouched.

Mongo fixtures with simulated upstream dates disable the background TTL worker,
while retaining production indexes. The independent expiry contract uses a separate
server with the worker enabled and verifies actual deletion. Production MongoDB
storage does not disable TTL cleanup.


Organization invitations now support delivery callbacks, protected extra fields,
custom expiry, static and callback invitation limits, resend retaining the ID and
refreshing expiry, optional cancel-on-reinvite, recipient reads, acceptance,
rejection (including expired invitations), cancellation, organization lists and
verified-recipient pending lists. Headerless trusted calls can enumerate an explicit
email; HTTP callers cannot. ID-based calls match the current stored user's email
and apply explicit verification policy, defaulting to required for custom ID
callbacks. The source's database-owned numeric-ID variant remains unported.
Acceptance uses a guarded pending-to-accepted update on each adapter and creates
membership/active-session changes in the enclosing transaction. A failed callback
rolls back writes; external email delivery itself cannot be rolled back.

Eight unchanged recipient-ownership cases and ten invitation lifecycle cases run
on each backend (54 repeated cases). Eleven independent contracts cover Brand Map
callback data/aliases, protected review defaults, tenant isolation, failed delivery,
acceptance rollback/retry, membership limits and concurrent acceptance through
independent PostgreSQL/MongoDB connections. One new native function tests stale
status claims and transaction rollback in memory/SQLite. Team-linked invitations,
complete callback context, atomic cross-request aggregate limits and generic
upstream adapter query contracts remain open.


## Dynamic organization roles

Dynamic role create/read/list/update/delete and live permission checks are native.
Roles are scoped to organization and current user membership. Database permissions
merge with the same static role's grants, preserving existing resources/actions.
A role grant cannot exceed the caller's per-action authority; structured errors
include missing permissions. Predefined names and assigned roles cannot be deleted,
unknown resources are rejected, role names normalize to lowercase on writes, and
an optional numeric role cap is enforced. Additional role fields apply input/default/
output policies and mapped PostgreSQL/MongoDB schemas. Member role updates validate
known static/dynamic names after authorization, enforce creator-role restrictions
and last-owner checks, and invoke before/after hooks within the transaction.

24 unchanged dynamic-role runtime source cases run on each backend (72 cases).
The pure TypeScript statement-type probe is explicitly excluded. Two unchanged
source merge cases also run on each backend. Nine owned integration cases verify
live membership/grant edits with cookie caching, mapped role schemas, malformed
persisted permissions failing closed, role caps and Brand Map policy. In that app,
`accessControl` grants do not imply Better Auth's `ac` grants: upstream role-management
APIs remain denied unless the configured role grants `ac`. App-provisioned native
storage records can still contribute domain permissions. No application policy is
changed to make those endpoints succeed.

Role-count, last-owner and role-assignment aggregate races are not serialized across
all concurrent requests. Generic adapter queries/hooks, functional role caps, empty
permission-map edge cases and complete error/context timing still need coverage.


Organization member listing supports organization ID/slug, pagination, known-field
filters, repeated query arrays and sorting, with totals computed before paging and
complete user joins above 100 members. Active-member-role lookup checks the caller's
membership before returning another member's role. Removal by ID/email, leaving,
creator/last-owner guards and before/after removal hooks are native. Leaving clears
the current session's active organization and cookies. Organization deletion now
returns the deleted organization and clears the caller's active selection.

22 unchanged member source cases run on each backend (66 cases), including the
official client's role-hook invalidation after logout. The source's adapter-mock
case above 100 members is explicitly excluded because generic JS adapter interception
is not implemented. Nine independent native integration cases verify 111 complete
user joins, paging/filter totals, tenant and owner guards, failed hook rollback and
cached active-selection cleanup. Generic database filtering/coercion/collation,
functional membership limits and aggregate owner races still require work; typed list scans are not a generic query API.


## Initial OpenAPI support

`OpenAPIPlugin` supplies `/open-api/generate-schema` and a configurable Scalar
reference page, including disabling the page, theme and nonce options. Generation
uses native configuration/model/endpoint definitions and invokes no auth handler,
storage query or user callback. It documents known model fields, protected/read-only
fields, scalar/array/date/JSON types, static defaults, required fields, writable user
request fields and selected core request/response shapes. Logical schema names stay
independent of physical database aliases. Runtime credentials and users are absent.
Native endpoints can provide JSON OpenAPI metadata and hide themselves from docs;
operation IDs remain unique. Internal endpoints and the reference page are omitted.
Embedded schema/settings and nonce attributes are escaped without changing values.

28 unchanged upstream cases verify model/request fields, nested social token input,
optional/default types, nullable sessions, operation IDs, serialization, custom body
intersections/unions/records, query length constraints, wrapper requiredness, dynamic callback path parameters
and independent operations across methods.
Six owned contracts verify explicit metadata, hidden paths, ID collisions, safe
reference embedding, custom path, disabled reference, live OTP signup and custom
schema boundaries. Only the phone-number fixture remains omitted; original selected
test bodies/assertions are preserved.

Native endpoints can supply `body_schema` and `query_schema` JSON descriptor trees.
Each node has `kind` (for example `object`, `string`, `optional`, `intersection`),
optional `description`, and optional input metadata `optional: true`. Objects contain
`properties`, wrappers contain `inner`, intersections contain `left`/`right`, unions
contain `options`, arrays contain `element`, records contain `key`/`value`, and pipes
contain `input`/`output`. Strings can include `minLength`/`maxLength`; enums/literals
contain `values`. Explicit `openapi_metadata.requestBody`/`parameters` override these
trees. Unknown kinds and nesting beyond 64 fail explicitly. These descriptors document
input shapes; they do not install runtime request validators.

The fixture translates Zod structure and optional-input metadata into this IR. V
projects JSON Schema, merges compatible object intersections, preserves conflicting
intersections as `allOf`, and distinguishes optional properties from whole-body
acceptance of undefined. Default/catch factories, preprocessors and endpoint handlers
are never evaluated for documentation. Native functions independently check conflicting
schemas, structural equality and malformed/deep descriptors.

Email-OTP documentation includes all nine public POST request bodies, required
fields, purpose enums, extensible signup fields and the deprecated reset alias.
Trusted OTP creation/read APIs remain absent from HTTP documentation. A native
integration contract also exercises the documented OTP signup flow.

This is not full OpenAPI parity. The full upstream endpoint snapshot, automatic
remaining plugin request/response schemas, remaining schema kinds/constraints, complete
security/tag metadata and the remaining source cases are open. Unknown plugin inputs are not fabricated: supply
explicit native endpoint metadata to document their shapes. Native JSON fields use
an unconstrained JSON Schema rather than the upstream model generator's `json` type.


Denied organization metadata/full reads and activation now clear the current
session's active selection while returning 403, matching upstream's intentional
state change. Native request transactions commit that cleanup and refresh session
cookies so cached selection agrees. Missing organization reads preserve an existing
selection; missing-ID activation clears it before denying membership. Twelve owned
cases across the three adapters verify persistent/cached state and unchanged
membership. Other endpoint errors retain normal transaction rollback semantics.


## Functional additional-field defaults

`AdditionalField.default_factory` supplies synchronous native creation defaults;
static `default_value` remains available and takes precedence if both are given.
Factories run for missing create values, including trusted user/session creation
and organization model defaults. Explicit optional nulls and supplied values survive;
ordinary reads/updates do not regenerate existing values. Protected session defaults
retain precedence unless a trusted caller requests full overrides. Factory failures
roll back creation, including users/accounts already written before session creation.
OpenAPI generation does not call factories or publish their runtime values, and
function-defaulted request fields do not become required solely for having a factory.

The unchanged upstream runtime-default case runs on three adapters. Nine owned
contracts and two native functions verify per-create values, explicit values/nulls,
trusted creates, session overrides, schema generation and failed-factory retries.
The TypeScript boundary restores configured date fields to Date objects while
preserving configured JSON fields as literal data. The original upstream SDK type
requirements remain unchanged; omitted/null runtime inputs are independently tested
through JSON HTTP. Asynchronous defaults, exhaustive undefined/legacy-row behavior,
update-value factories and default/transform sequencing remain open.


Additional-field integration now imports six unchanged native runtime cases on
SQLite/PostgreSQL and five on MongoDB (17 repeated cases), covering official-client
profile updates, two-factor coexistence and defaults with primary/secondary sessions.
Four SDK/constructor/type probes run separately through the native constructor
facade and official SDK, with their own execution-surface label. The SQL-specific
absent column assertion is excluded from the MongoDB repeat because missing Mongo fields
remain absent. SQLite's payload adapter now reads missing ordinary configured user/session
fields as null across single, email, ID and list lookups. This read normalization
runs no default factory and leaves stored payloads unchanged, as one native test
verifies. Missing credential/transport-reserved user names are not synthesized. SQLite still does not share the upstream physical column schema.


The additional-fields source file is now preserved in full across the native
integration/runtime imports and a separately labelled four-case SDK/type import.
A synchronous constructor fixture lazily starts the existing V bridge for API,
HTTP and context calls; metadata retains upstream TypeScript inference. Unsupported
API names fail explicitly, including prototype names. It does not call the
TypeScript server implementation. Two native integration contracts verify protected
session updates through this constructor and additional-field sign-in data through
the official React client. React and its type package are pinned to versions in the
upstream lockfile for these client tests. This is a test fixture, not a production
TypeScript server facade or a claim of complete constructor/client parity.


The source inventory unions complementary imports by original AST position under
matching source checksums. Backend repeats count once, duplicate titles retain
separate identities and malformed source metadata fails the audit. Every manifest
records original positions/lines. Six audit tests run through `make check`. The
current 33 complete/16 partial/387 unported source-file counts and 1,204 preserved
static declarations describe source coverage, including separately labelled SDK
probes; they are not equivalent to native runtime or feature parity.


OAuth callbacks accept form-urlencoded or JSON POSTs and redirect to a canonical
same-origin GET. Known callback fields must be strings; query fields take precedence
over body fields, unknown fields are discarded, and state is not consumed until GET.
The POST sets no session/state cookies and performs no token exchange. Cookie-less
provider POSTs can redirect across origins; cookie-bearing POSTs retain origin checks.
A native test verifies durable proof retention, required browser binding, login and
replay rejection. Three signed Nabu OIDC contracts repeat the flow on SQLite,
PostgreSQL and MongoDB, checking Basic/PKCE and provisioned account linking. A separate
HTTP contract covers malformed/type/duplicate/media inputs and CSRF boundaries.
Two unchanged upstream OpenAPI cases now verify both callback methods/path parameters;
they are documentation tests, not upstream OAuth-proxy or SAML conformance coverage.


Fourteen additional unchanged internal-adapter tests now exercise native verification
identifier hashing/prefix overrides, legacy plain-token fallback after switching to
hashed storage, secondary-only/dual persistence, database fallback, cache deletion,
TTLs and pre-parsed cache date revival. The fixture uses native SQLite files in managed
temporary directories; reusing a database descriptor shares actual rows across separate
V auth instances/configurations. It does not open a JavaScript database. The focused
38-case verification/reservation/consumption matrix, type checking and inventory audit
pass. These additions verify existing native behavior; general adapter/session/hook
conformance and database-owned numeric IDs remain incomplete.


Core OAuth GET callbacks redirect missing/empty state to `state_not_found` and
repeated known query fields to `invalid_callback_request`, without authenticating or
consuming a proof. Browser-bound provider denials preserve their error/description;
missing codes redirect with `no_code` after state consumption. A nonempty callback
`iss` must exactly match the generic provider's discovered issuer before token exchange.
The native provider context exposes that public discovery value. Session creation
API errors roll back user/account/session writes and redirect the original code and
message to the trusted error callback. Three unchanged upstream generic-OAuth tests
cover missing state, discovery metadata and cross-origin session-hook errors; six
Nabu contracts exercise issuer rejection/success and hook rollback across SQLite,
PostgreSQL and MongoDB. A native function checks provider denial, missing code,
browser binding, proof retention/consumption and replay. IdP-initiated flows, complete
callback error mappings and custom global error-URL configuration remain open.


OAuth user-policy and database-hook API errors retain application code casing and
messages in trusted error redirects. The marker distinguishing application errors
from native callback errors is omitted from HTTP/JSON representations. Rejected
identity/account creation rolls back pending user/account writes and queued effects;
the previously consumed OAuth state stays consumed. Two unchanged upstream policy
cases cover provider/source metadata, raw profiles, descriptions and stateless
rejection. Nine signed OIDC contracts repeat returned policy errors, thrown API
errors and before-account hook failures on SQLite, PostgreSQL and MongoDB. One
native function independently checks rollback, replay and marker privacy on ordinary
HTTP signup errors. Post-commit hooks cannot roll back already committed writes;
external application side effects and nontransactional stores retain their existing
limits.


OAuth now issues the canonical `state` cookie with the default root path and clears
it on completion. Earlier native `oauth_state` cookies at the old auth-base path
remain readable and are cleared too. A present canonical cookie takes precedence,
including an invalid/empty one; it never downgrades to a legacy cookie. Factory
prefixes, secure naming and cookie overrides apply. Native OAuth continues to use
its server-side opaque verification record; this is not cookie-only/JWE state-format
compatibility.

Account linking is enabled by default, matching upstream. It still requires the
configured local-email and incoming-provider verification/trust checks; explicit
`enabled: false` prevents new implicit bindings. The fixture and public V configuration
share that default. Trusted account JSON output now emits null for missing nullable
token/scope fields without expanding sparse hook input or storage patches. Five
additional unchanged upstream generic-OAuth cases verify state-cookie cleanup,
complete sign-in/session data, new-user account data, linked sign-in and provider
failure. Three Nabu-style backend cases verify default verified linking, explicit
opt-out and null expiry output. A native function verifies legacy cookie acceptance,
canonical precedence, proof retention and replay; direct Google ID-token coverage
also asserts that neither state-cookie name is issued.


OAuth error handling now distinguishes token exchange, provider profile mapping,
identity creation/linking and session creation. Token/custom-token failures redirect
with `invalid_code`; ordinary creation/linking failures use `unable_to_create_user`
or `unable_to_link_account` without private messages. Profile-mapping API errors
retain their HTTP status, optional code and message, matching Nabu's HTTP 403
provisioning/verified-email rejection. Policy/session API errors without a code keep
their HTTP status; coded policy errors retain the existing error redirect. Unexpected
session failures return private HTTP 500 responses. Successfully consumed state
cookies expire on HTTP errors as well as redirects, while failed state binding leaves
the proof and cookie alone. Unknown sign-in provider IDs return HTTP 404.

The bridge preserves API-error identity (including explicit 5xx API errors and absent
codes) through nested calls; it does not invent callback error codes or convert
ordinary exceptions into API rejections. Two more unchanged upstream cases cover
unknown providers and custom token failure. Forty-five backend policy/error contracts
and three additional Nabu linking-failure contracts cover these boundaries, rollback,
private messages, cookie cleanup and replay. Nabu's older owned profile-rejection
expectations were corrected from redirects to HTTP 403 after checking pinned source
and the installed upstream runtime; imported upstream assertions are unchanged.


Native OAuth providers can expose display names through `OAuthNamedProvider.name()`.
Generic OAuth uses its configured name, preserving an explicit empty string and
falling back to the provider ID only when absent; Google/GitHub expose their names.
Native provider context metadata carries the value. The unchanged custom-name source
case, Nabu's configured label across its backend contracts and an owned omitted/empty
name contract pass (61 focused cases, type checking and six inventory audits).
This provider-name change affects metadata rather than authentication or persistence.


Organization OpenAPI metadata now covers all 16 public POST and 11 GET routes, with
stable operation IDs, organization tags, request bodies, member-list query shapes,
role permission records and response containers/model references. Protected Brand Map
review fields stay read-only in models and are absent from writable bodies. Model
metadata/permission fields describe their normalized JSON output. Body extra fields
respect input/default flags without evaluating factories; nested role additional
fields follow the same rule. Trusted member creation and server-only invitation email
selection stay absent from HTTP docs. Disabled dynamic-role routes are hidden while
static member-role operations remain documented.

Four owned contracts inspect the schemas and execute documented role, member,
invitation and acceptance requests across SQLite, PostgreSQL and MongoDB. They also
check factory/lifecycle/email isolation during generation and exact default-factory
calls during creation. The unchanged CRUD/dynamic-role/OpenAPI regressions are included
in the 191-case focused matrix; the new organization documentation assertions are
owned contracts, not newly imported upstream OpenAPI cases. Complete snapshots,
all metadata/security/error details and exhaustive endpoint schema validation remain
incomplete.

The live contracts exposed an organization-default evaluation bug: an existing field
still evaluated its fallback factory. Default resolution now short-circuits supplied
values. Missing values evaluate a factory once, reads/docs leave it alone, and a native
regression verifies a throwing factory cannot reject an explicit supplied value.

### Existing application schema gate

The application gate now creates Brand Map's auth-side PostgreSQL migration before
V connects, seeds existing credentials/sessions, disables V migrations and uses
the official client over loopback HTTP. The snapshot preserves all ten auth tables,
their enum/UUIDv7 defaults, indexes, checks and auth-side foreign keys; the external
file-service table is an explicit minimal fixture stub. An operation-level schema
fingerprint stays unchanged. Existing session renewal/revocation, restart, JWT
key creation, mapped fields, protected input, user-update effects, member joins,
externally provisioned role grants, invitations, hashed OTP and one-time tokens
are exercised. Current Brand Map source includes admin and one-time-token plugins;
older observations of the application's plugin list no longer describe that source.

Nabu's password-mode gate installs its index definitions and raw ObjectId/BSON-date
documents before V connects. Existing upstream-signed cookies and scrypt credentials,
session renewal, restart/revocation and application-owned data preservation pass.
The existing signed-OIDC matrix remains a separate gate. See
[application compatibility](application-compatibility.md) for exact scope and limits.
These checks do not run either complete application or establish deployment parity.

The gate found and fixed a native session-cookie restriction to 64-character
tokens: signed upstream tokens with other lengths now authenticate, retaining HMAC
verification. Bearer processing also accepts scheme casing/whitespace, encoded or
decoded signatures and valid cookies when a signed bearer value is invalid.
`set-auth-token` now contains the signed, URL-encoded session cookie value and is
exposed to browser clients, matching upstream. All seven original bearer declarations
(eleven runtime cases) are imported unchanged and run on each of three backends;
backend copies add seven unique source declarations, not twenty-one.
