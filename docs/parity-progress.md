# Full-parity work log

The objective is full Better Auth parity, including the remaining features
and upstream tests. The project is not complete while the compatibility contract
or corpus inventory contains unimplemented behavior.

## Fixed baselines

- Source commit: `0e75ddcf36489aa3a191ea902a82d1892034dc74`.
- Published reference implementation/client: `better-auth@1.7.15`.
- V toolchain: 0.5.2. Test runner: Node 24 / Vitest 5.0.0.
- Unicode normalization: Unicode 17.0.0, matching the verified Node runtime.
- `upstream.lock.json` pins the source archive checksum. Per-file manifests pin
  imported source hashes and enumerate selected/unported declarations.
- `tests/upstream/corpus.json` covers the entire repository, including demos,
  tooling, adapters, plugins, browser E2E, and type-only files. Its 436 files and
  6,817 static declarations are an inventory, not a passing runtime-case count.
  Named `test.extend` fixture declarations are now included; this discovered 22
  previously uncounted declarations without changing the source baseline.

## Brand Map and Nabu priority

The user resumed implementation on 2026-11-04, prioritizing the actual configured
features in `/Users/alexs/bm/server`, including Nabu, while retaining the full
pinned-upstream parity objective. Commit and push each verified batch.

1. Persistence and identity foundations: PostgreSQL with the existing auth/plugin
   schemas, UUID IDs and mappings; Redis verification/session behavior; trusted
   verification/session APIs used by application handoffs.
2. Authentication plugins: one-time tokens, email OTP (hashed, rotating, attempts,
   email changes), anonymous users/link callbacks, and two-factor/TOTP/backup codes.
3. Authorization: admin users/roles/bans/impersonation and organizations, invitations,
   memberships, active organization, dynamic permissions and organization hooks.
4. Nabu: MongoDB, generic OIDC discovery/verification/profile policy, trusted
   account linking and database-backed rate limiting.
5. Integration completion: field validators/uniqueness, OpenAPI, schema generation,
   logger/hook contracts and application-level verification of the above. Do not
   infer passkey/API-key/phone/team requirements from unused UI dependencies.

Foundational plugin batches can proceed before complete database adapters, but
this does not remove PostgreSQL/MongoDB/schema integration from the requirements.
Each plugin must retain original upstream assertions and accurately report gaps.

## Implemented since the initial core

- Removed all exclusions from the original sign-in test file.
- Added all original password tests, running against V scrypt, with independent
  Node verification and legacy `@noble/hashes` compatibility.
- Implemented Unicode NFKC and passed all 20,034 official conformance vectors.
- Switched the default hasher to upstream-compatible scrypt; kept explicit Argon2.
- Matched password length limits to UTF-16 units and avoided unnecessary hashing
  at auth initialization. Credential lookup selects the canonical account.
- Added persistent user fields: required/default/type validation, protected input,
  hidden output, flat JSON, and native typed API round trips.
- Added transaction-time callback RPC for hashing, verification, email delivery,
  registration policy, and existing-user signup notifications. Failures can roll
  database writes back. Logger events and user-record inspection reach the fixture.
- Implemented generic duplicate responses that reflect the new request, preserve
  response shape, and do not reveal the stored profile. Registration policy also
  applies to new OAuth users.
- Added all 37 original sign-up cases covering policy validation, enumeration
  protection, verification-email options, forms, CSRF, session caching/rollback,
  custom fields, and account-column mapping.
- Added deferred refresh, POST refresh, refresh suppression, read-only GET
  transactions, nonpersistent-session refresh suppression, fresh device listing,
  browser cookie Max-Age limits, and persistent custom session fields/update APIs.
- Added all 80 original session cases, plus native read-only SQLite verification and
  direct V API checks. Session/helper coverage now includes `returnHeaders`, method
  overrides, official client plugins, and request-local user headers.
- Added primary secondary-store sessions, optional database copies/fallback,
  preserved-row revocation, cached user refresh, TTLs, and atomic consumption and
  counters in the native memory implementation.
- Added transaction-aware database mutation hooks and after-commit tasks. Nested
  hook and internal-adapter calls execute in V through a correlated callback
  protocol; private session metadata survives callbacks without entering HTTP JSON.
- Added purpose-bound AES-GCM token storage so database session listings return
  actual tokens while database lookup continues to use digests. Legacy rows remain
  readable; their tokens cannot be recovered retroactively.
- Added schema-v3 migrations and real SQLite account identity-column aliases,
  including quoted names. The adapter fixture can inspect users/accounts and
  update session rows by ID without changing hooks or caches.
- Added compact HMAC, HS256 JWT, and HKDF/A256CBC-HS512 JWE cache codecs, plus
  legacy A256GCM decoding. Independent HMAC/JOSE tests verify emitted tokens and
  independently encrypted tokens accepted by V.
- Added cache version strings/callbacks, hidden-field filtering, token binding,
  cache bypass/expiry/fallback, bounded cookie chunks, and stale-chunk cleanup.
  Corrected ECMAScript number serialization for compact signatures and cookie-jar
  merging in the fixture.
- Added native stateless defaults/refresh, preserved session expiry, nonpersistent
  cache cookies, strict stateful revocation checks, and endpoint-context session
  lookup/header forwarding. Stateless updates can use their signed cookie when
  the ephemeral adapter has no session row.
- Added a V map-based primary adapter with transaction rollback and key constraints.
  Explicit upstream memory-adapter fixtures select this adapter without executing
  a TS database. Adapter `findOne` observations reach real native reads; store
  failures are sanitized for HTTP and preserve callback causes for direct TS calls.
- Added an Ed25519 JWT/JWKS plugin, persisted signing keys, native AES-GCM private
  key protection, schema-v4 migration, rotation/grace periods, local cache signing,
  strict cache-JWT identity claims, authenticated token issuance, automatic JWT
  response headers, and trusted server signing/verification APIs.
- Added plugin field contributions, creation defaults, protected admin/organization
  authority fields, and custom synthetic-user callbacks. These schema plugins are
  partial foundations; admin/organization operations and permission enforcement
  remain unimplemented and their endpoints are not registered.
- Added native endpoint session/freshness requirements and fixture descriptors for
  JS business callbacks. Removed the final sign-up/session exclusions: both source
  files run in full, including original JWKS/rotation and plugin-dependent cases.
- Added custom JWK-store get/create overrides and imported the complete upstream
  rotation file. Added ID-independent encrypted key envelopes while preserving
  older ID-bound records, plus missing-algorithm fallback and primary-key preference.
- Added OpenSSL 3 RSA/PSS and ECDSA key generation, JWK import, signing, verification,
  ECDSA JOSE signature encoding, and public/private key checks. The JWT algorithm
  matrix and general signing now run against V, including their key-generator
  helper. Node-generated keys/tokens are tested in both directions across nine
  RSA/PSS/ECDSA algorithms, including signature tampering rejection.
- Extended the importer to recognize top-level parameterized suites; the partial
  JWT plugin manifest records all selected/unported declarations. Added custom
  adapter/path and stored-algorithm authority suites. The JWT plugin source file
  is now imported in full; passing it does not establish full JWT plugin parity.

- Added remote JWKS URL configuration and native custom signing callbacks. Remote
  configuration disables local JWKS publication, while token issuance and session
  headers remain available. Custom signing receives V-built claims and does not
  mint local keys. Native configuration rejects missing remote algorithms, custom
  signers without a remote URL, and custom signing for cookie-cache JWTs. All 11
  declarations in the original remote-signing/URL suites now run unchanged.

- Added native JWT expiration conversion for absolute numeric claims, dates, and
  strict upstream duration strings (including signed/relative/fractional forms).
  All seven original expiration utility declarations now execute in V through a
  synchronous command transport. Configured `expirationTime` controls native
  signing and an explicit payload `exp` takes precedence. Native regression
  coverage includes pre-epoch dates and JavaScript rounding of negative ties.

- Added signing-key ID/algorithm pins, declared extra-algorithm lazy minting,
  live-key lookup, millisecond key ordering, and protected profile headers. Missing
  or expired pinned keys fail without replacement; explicit algorithm conflicts
  preserve legacy-row inheritance details. Custom signers receive protected
  headers and signing overrides. Both complete upstream signing-override and
  multi-algorithm source files now run (33 declarations); their adapter and
  key-generation helpers execute in V. Native tests cover mint rollback inside
  an existing transaction and resolved key authority over caller alg/kid headers.

- Added native session JWT payload/subject callbacks, including async fixture
  transport, null-subject fallback, payload issue-time precedence, and callback
  error propagation before key minting. Both token issuance and automatic session
  JWT headers use the same native claim-building path. Independent JOSE checks
  verify customized claims.

- Added request-scoped base URL resolution when no origin is configured, including
  secure-cookie selection and same-origin checks. Direct server JWT calls retain
  an unresolved origin and log upstream-compatible warnings; verification skips
  unspecified issuer/audience checks but still requires subject/audience claims.
  Both original unresolved-origin tests now execute unchanged. Native regressions
  cover multiple HTTPS origins, cross-origin rejection, and no request-origin
  leakage into subsequent direct calls.

- Ported the original active-transaction key-minting regression. Raw constructor
  and SQLite dialect descriptors now open V SQLite storage with explicit native
  migrations; transaction callbacks run within a real V transaction. The trusted
  endpoint context issues tokens without reacquiring the connection lock. An
  independent test verifies missing migrations, key visibility inside a nested
  transaction, rollback on an outer JS failure, and successful subsequent issuance.
  The main JWT file then ran every runtime declaration; its client type checks
  are recorded separately below. Nonempty short secrets warn rather
  than fail initialization, matching pinned upstream; empty secrets still fail.

- Added upstream-compatible XChaCha20-Poly1305 (V HChaCha20 derivation plus
  OpenSSL AEAD), versioned symmetric envelopes, key retirement/legacy-key policy,
  rotating JWE decode, isolated OAuth-purpose derivation, and native secret
  environment/configuration helpers. Complete crypto secret-rotation and purpose
  files now run (43 declarations, 52 runtime cases). New private JWK writes use
  upstream ciphertext while older native envelopes remain readable. Independent
  TS crypto tests exchange ciphertext, JWEs, and encrypted JWKs in both directions.
  Main auth integration is recorded below.

- Corrected signing-key creation/expiration/grace decisions to use millisecond
  time. The full run exposed a second-boundary error in short rotation windows;
  a deterministic native regression now covers a 1.1-second advance from a
  fractional starting time. Custom second-only clocks remain supported, with an
  optional millisecond clock for applications/tests that need finer precision.

- Connected ordered versioned secrets to auth initialization, current cookie
  signing, encrypted JWK persistence, JWE caches, and native sealed-session token
  recovery. Explicit legacy-secret policy and version retirement remain enforced.
  File-backed native tests reopen sessions and keys across rotation; integration
  tests verify existing signing-key reuse and rejection of invalid configurations.
  Cookie signature acceptance remains current-secret-only, matching pinned
  upstream. Initialization failures now close their bridge cleanly.

- Added a typed official-client integration test covering optional/null additional
  fields through native signup, profile updates, sessions, JWKS, and JWT issuance.
  Imported the final two JWT source declarations unchanged; their manifest labels
  identify them as TS client type checks with separate native integration coverage.
  All four JWT source files now run in full. These checks establish the supported
  official TS client pairing, not TS-style compile-time generics in the V API.

- Imported the complete core password reset/verification file (25 declarations)
  without assertion changes. Added independent reset TTL, opt-in session
  revocation, post-commit reset callbacks, enumeration-resistant delivery failure,
  authoritative password verification, millisecond account update timestamps, and
  adapter transaction-disabled behavior. Password hashing is observable through
  native callbacks and preserves policy API errors. Rejected passwords do not
  spend reset tokens; token races and failed writes retain native transaction
  semantics. Existing local reset tests now explicitly configure the policy they
  intended to exercise. Native account updates preserve canonical identity.

- Imported the full email-verification file (25 declarations) unchanged. Added
  upstream-compatible HS256 verification JWTs, idempotent repeated verification,
  before/after callbacks, optional sign-in, current-session cookies, and the
  unauthenticated 500 ms timing floor. Added email-change confirmation/verification
  with session-owner checks, cached-user refresh, and canonical credential IDs.
  Callback request snapshots survive consumed bodies and clone failures. Native
  legacy links remain readable. Independent JOSE tests exchange tokens and check
  algorithm/expiry rejection and cross-user email-change isolation. Local HTTP
  redirect tests now exercise the HTTP boundary; trusted server calls mirror the
  upstream origin-policy bypass.

- Imported all 17 `updateUser` declarations from the user lifecycle file without
  changing their assertions. Password changes validate current-password length
  before hashing, use an authoritative session, and replace all revoked sessions
  with a new session/token/cookie. Account writes and replacement creation share
  the transaction. Database-backed secondary deletions and replacement writes wait
  for commit; the source tests cover failures at every step. Trusted adapter user
  updates preserve custom fields without reapplying defaults. The remaining 17
  declarations in this source file were completed in the following batch.

- Completed all 34 declarations in `update-user.test.ts`, retaining every source
  assertion. Deletion is opt-in, accepts a fresh session or verified password, and
  supports expiring single-use verification links, GET callbacks, redirect queries,
  and before/after hooks. Tokens stay consumed after owner mismatch or callback
  failure; successful deletion survives an after-hook error. Stateful authorization
  bypasses cookie caches. Added native server-only password setting that reuses an
  existing passwordless credential account. Corrected the fixture's `sessionSetter`
  to match upstream token-only behavior; `cookieSetter` retains all cookies.
  Six independent tests check default-disabled behavior, expiry, wrong-owner token
  burning, retained stale cache cookies, hook failure durability, and server-only
  policy errors. Trusted verification inspection reads actual native records.

- Imported the complete sign-out file (9 declarations) and error-page security
  file (2 declarations), preserving their bodies/assertions. Local sign-out clears
  cookies despite lookup, delete, commit, or secondary-revocation errors. Added
  an explicit logout-provider interface and generic end-session URL configuration,
  linked account ID-token storage, timestamp ordering, provider fallback, callback
  redirects, client IDs, state, and optional redirect suppression. Four independent
  cases verify failure isolation and invalid-provider fallback with existing URL
  parameters. The error endpoint escapes descriptions and rejects invalid codes;
  custom styling and production/error-URL routing remain separate work.
  Generic OAuth discovery, sign-in, and token exchange are still unimplemented.

- Imported all 9 declarations / 11 runtime cases from the cookie-cache fallback
  file. Retired, malformed, expired, or unverifiable cache cookies fall through to
  authoritative token lookup, and stale base/chunk cookies are expired. Added
  custom names/prefixes, explicit secure overrides, and cross-subdomain domains
  across token, cache, remember-marker, and OAuth-state cookies. Names are resolved
  independently, so custom names do not need a shared dotted prefix. Native config
  validates names/domains before emitting headers. Four independent cases verify
  domain derivation, matching issue/clear scopes, custom markers, secure overrides,
  and rejection of header-injection configuration. Custom attributes are still
  rejected by the fixture rather than ignored.

- Imported the full trusted-origins file (38 declarations). Native matching now
  supports host/protocol wildcards, custom schemes, exact custom authorities, pinned
  path boundaries with decoded traversal normalization, and safe relative URLs.
  Native request-scoped callbacks and environment origins feed HTTP/CORS/redirect
  decisions; trusted endpoint contexts expose the same matcher. Plugin init origin
  contributions are transported without running TS auth logic. The standalone V
  helper expands dynamic allowed-host/protocol/fallback lists, including loopback
  exceptions; live dynamic baseURL host resolution remains unimplemented.
  Three independent cases check concurrent request isolation, HTTP wildcard and
  encoded-path rejection, and loopback/lookalike-host classification. Fixture query
  schemas decode business callback inputs, and official TS clients retain their
  plugin endpoint types. Zod is pinned explicitly to the already-installed 4.6.7.

- Imported the full HTTP origin-check middleware file (38 declarations), including
  Fetch Metadata CSRF, separate bypass options, exact/slash-boundary path exemptions,
  request-inferred hosts, environment origins, non-string/duplicate-query errors,
  and the paused-hook concurrent-request regression. Added native request-hook
  plugins and prepare/complete APIs: trust is resolved before hooks, hooks can wait
  without locking storage, and completion uses the original snapshot. Native hooks
  can replace requests or short-circuit responses. Trusted transports must keep
  prepared contexts private; no HTTP endpoint accepts them. The TS fixture runs
  original application callbacks between native preparation/completion and forwards
  selector values back to native redirect checks. Structural CR/LF/NUL checks stay
  active even with an explicitly disabled origin policy. Three native tests cover
  hook behavior, snapshot isolation, and redirect header injection. Compatibility
  deprecation messages currently deduplicate per Auth instance, rather than across
  all instances in a JS module.

- Added native per-call JWT option sets for signing, verification, and key lookup,
  plus trusted pre-resolved signing material. Per-call custom stores/signers use
  scoped callback registrations and never replace plugin configuration. The
  server-only `signJWT` facade shallowly replaces top-level `overrideOptions`, as
  upstream does; helper calls without options use helper defaults. Empty issuer
  and empty audience-array settings retain their meaning, nullable claims default
  correctly, JOSE setter types are enforced, and fractional NumericDates survive
  default-expiry calculation and verification. Per-call Date expiration is floored
  natively. Key encryption settings now control private-key interpretation. Fixed
  explicit key pinning exactly at expiry: it is usable at equality and rejected
  one millisecond later, while automatic selection excludes equality. Nine
  independent JOSE/runtime cases cover these behaviors, alongside a native
  pre-resolved-key test proving no storage lookup/mint is needed. All 142 imported
  JWT runtime cases still pass. Schema/model mapping remains separate adapter work.

- Preserved millisecond precision throughout user/account/session dates, refresh
  scheduling, freshness, compact cache clocks, active-session references, opaque
  token deadlines, and per-instance rate windows. JWT NumericDates remain seconds.
  New verification records carry optional millisecond expiry while old SQLite JSON
  rows keep their seconds interpretation. Database sessions/opaque tokens remain
  usable exactly at expiry and expire after it; active-device lists still exclude
  equality, matching their separate upstream rule. Secondary TTLs floor remaining
  milliseconds into seconds and avoid creating immortal session entries with a
  zero TTL. Native memory KV storage supports millisecond clocks and keeps counter
  deadlines across increments. Native reset/magic-link messages and lifecycle
  contexts preserve actual HTTP request metadata. Six runtime contracts and two
  native tests cover exact timestamps, +1 ms boundaries, cache fallback, secondary
  TTLs, rate windows, an actual old SQLite row, and delivery metadata. Older local
  boundary assertions were corrected against the pinned source.

- Added native request/response cookie utilities, attribute conversion, secure
  prefix removal, request mutation/merging, session-token selection, canonical
  chunk reconstruction, and pending-cookie expiry cleanup. Imported 58 original
  declarations (76 runtime cases) from the cookies source without changing their
  assertions; the remaining 39 declarations stay explicitly unported. The TS
  facade translates Headers, Map, Date and NaN representations while V performs
  parsing, selection, encoding and merging. Ordered entries preserve numeric cookie
  names across JSON. Four independent runtime contracts compare published helpers,
  and three native tests cover malformed UTF-8, encoded controls, round trips,
  chunk ordering/cleanup and attribute overrides. General Date-string coercion,
  standalone cache reading, account-cookie synchronization and broader cookie
  configuration still require work.

- Added the standalone native cookie-cache reader with compact HMAC, HS256/384/512
  JWT, JWE and public-JWKS profile validation. It preserves the source's independent
  reader semantics, including permissive chunk reconstruction, schema defaults,
  unknown fields, environment secrets, first-matching-JWK selection, dedicated
  profile/claim binding, and version callbacks before final expiry checks. Two-phase
  fixture calls keep authentication and final policy in V while allowing asynchronous
  JS business callbacks. All getSessionCookie declarations and compact reader expiry
  declarations are now imported: the cookies source has 64 selected declarations
  (82 runtime cases), with 33 still unported. Fourteen independent runtime cases and
  two native tests cover these behaviors. Fixed fractional JWE NumericDates at the
  15-second tolerance boundary; truncation previously rejected a still-valid expiry
  or accepted a not-yet-valid token. Exotic JS coercion/Date normalization, cookie
  attribute configuration, account-cookie synchronization and remaining integration
  suites still require work.

## Next infrastructure work

- Imported all cookie field-filtering, sensitive middleware and chunking suites
  without changing assertions: the cookies file now runs 95 declarations as 113
  cases, with only two Google/account-cookie cases unported. Native standalone
  readers emit schema-validation warnings through an application logger; the test
  facade forwards these native events to the active endpoint logger. Invalid MACs
  remain silent misses. Oversized-cache diagnostics match upstream, and ordinary
  authentication still succeeds after a cache is skipped. Added native raw-session
  bulk deletion by user ID with counts, exposed through an explicitly limited
  fixture adapter operation, to verify revoked database sessions cannot regain
  sensitive access through cached cookies/query overrides. Removed the divergent
  default 64 KiB library body cap; positive `max_body_bytes` still enforces an
  explicit byte limit, while zero matches the upstream default. Three native tests
  cover per-user deletion/counts, optional body-limit boundaries, and native warning
  callbacks. Chunking debug metadata, fractional duration precision, account-cookie
  synchronization and broader adapter/logger operations remain unfinished.

- Added the native `CookieFactory`, standalone descriptor/getter counterparts,
  default/per-cookie attribute configuration, shared HTTP serialization and cache
  lifetime selection. Native auth now captures the production security fallback
  instead of changing it from each request scheme, matching the pinned source;
  cross-domain rebuilding still uses the resolved origin. Preserved IPv6 domain
  brackets and Host/Secure/Partitioned/SameSite=None serializer invariants. Expiry
  writes preserve configured attributes, and cache/marker/token Max-Age precedence
  follows their separate upstream rules. Imported all basic/production/domain/
  configuration suites, including an import-path-only adaptation of the original
  production dynamic import. The cookies source now runs 72 declarations as 90
  cases, with 25 declarations still unported. Twenty-two independent runtime cases
  compare fresh official-process descriptors and actual native issuance/expiry;
  two native tests cover factory isolation and prefix/header rules. Corrected an
  older owned JWT-origin test's cookie-security assumption against upstream source.
  Fractional issuance durations, exact malformed-option/error timing, account
  cookies and remaining integration suites still need work.

- Preserved fractional global/per-cookie cache lifetimes and refresh thresholds
  end to end. Cache config now uses floating-point seconds; JWT/JWE NumericDates
  retain fractions during encoding and decoding, compact snapshots apply Date's
  integer-millisecond clipping, and HTTP Max-Age floors separately (negative
  fractions remain absent). Legacy integer crypto APIs delegate to explicit
  fractional-lifetime variants. General HMAC verification accepts the upstream
  HS256/384/512 algorithms through an explicit allowlist, checks fractional exp/nbf,
  and validates iat types. Email verification keeps its separate HS256-only policy;
  the existing independent endpoint regression caught and prevented broadening it.
  Fourteen independent cases cover every cache format with global and per-cookie
  fractional configuration, deleting database sessions before boundary reads so
  cache fallback cannot hide truncation. They also cover exact refresh thresholds,
  compact submillisecond clipping, primitive JOSE interoperability, and malformed
  claims. Two native tests exercise the new V APIs, legacy integer callers,
  floating-point defaults and compact clipping. Session TTL fractions, other
  malformed-option behavior and account-cookie/provider work remain incomplete.

- Added the native Google authorization-code provider and reusable HTTP transport.
  Grants carry PKCE, redirect/credential/scope parameters and provider hints; code
  response profiles enforce configured hosted domains. Added account token/expiry/
  scope fields, code-exchange token persistence for Google/GitHub, optional token
  encryption with plaintext migration, refresh-token retention and scope union.
  OAuth account hooks cannot change the selected identity binding. Added native
  rotated-secret account-cookie JWE, bounded chunks, attribute/lifetime handling,
  logout cleanup and session-user binding. Fresh pending account cookies survive a
  stale request cookie on user switch. OAuth callbacks now issue session cache as
  well as token cookies. The TS provider transport supplies HTTP bytes through MSW;
  policy and storage remain native. All 97 declarations of the original cookies
  file now run (115 runtime cases), including the two original Google/account switch
  regressions. The complete OAuth token-utility source adds 13 cases, with unchanged
  assertions. Nine independent Google/account cases and four native tests verify
  PKCE/grants, token storage/encryption/dates, refresh-token retention, grant union,
  hosted-domain enforcement, hook rollback, redirect refusal, cookie chunks,
  key rotation and fresh-cookie preservation. Direct Google ID-token credentials,
  broader provider options, account linking, token refresh, account endpoints,
  error redirects and full stateless OAuth remain incomplete.

- Added a native ID-token verification kernel and Google-specific verification
  with RS256 pinning, trusted key retrieval, required claims, both Google issuers,
  audience/nonce checks, 30-second clock skew, one-hour maximum age and hosted-domain
  enforcement. Standalone helpers try matching candidates; the provider resolver
  uses its first matching key. Shared account creation/update logic now serves both
  code and direct-token sign-in. The direct route rejects malformed/unsupported
  credentials, verifies before any account write, returns sessions without OAuth
  state, and preserves the pinned branch's token-field behavior. Google client-ID
  arrays and disableIdTokenSignIn are supported, and default Google flows preserve
  unverified email claims. The complete separate Google provider test file imports
  all 15 declarations unchanged; its HTTP mocks remain fixture transport only.
  Ten independent integration cases compare JOSE at clock/age boundaries and cover
  forged/none/HMAC tokens, missing claims, nonce, key selection/import metadata,
  hosted domains, direct session/cookie issuance, input validation, redirects and
  critical headers with a valid independently signed signature. Two native tests
  cover the V verifier, hashed/exact nonces, tolerance and resolver distinctions.
  Generalized the importer for pinned core source paths and retained top-level mock
  setup calls. Other ID-token provider configurations/callbacks, provider options,
  account linking, refresh and full email-verification/error handling remain open.

- Added a native shared ID-token policy with disable/override/custom-verifier
  precedence, explicit opaque-token gating, audience validation, key resolution,
  and post-signature claim callbacks. Callback errors fail closed. Independent
  ID-token verification profiles cover Apple, Cognito, Facebook, Google and
  Microsoft; PayPal declares no direct-token capability. Native key selection
  distinguishes Google's import-all/first-key behavior, exact-kid resolvers,
  Facebook's unique matching key, and Microsoft's absent/null algorithm fallback.
  Four native tests cover those policies, callback precedence, signed tokens,
  nonce configuration, Apple audience fallback and Microsoft tenant binding.
  These profiles do not implement the providers' code exchange, user-info or
  account integration. The shared upstream verifier suite is the next import;
  Facebook remote-key caching and broader provider options remain incomplete.

- Imported the complete pinned shared ID-token verifier source: all 17 static
  declarations run as 25 cases, with original assertions unchanged. Native policy
  handles capability/disable checks, application overrides, custom verifiers,
  JWKS callbacks, opaque-token opt-in, signature/standard claims, nonce and extra
  claim callbacks. The facade only serializes platform keys and invokes supplied
  callbacks. It preserves callback context identity and optional nonce arguments.
  Algorithm/critical-header validation now precedes key callbacks and remote HTTP.
  Platform CryptoKey hash/type/usage restrictions survive serialization; RSA
  verification requires at least 2048 bits. Twenty-two independent cases verify
  real signatures for all five verification profiles, Microsoft tenant restrictions,
  callback ordering/errors, opaque paths with unused invalid configuration, and
  nine additional HMAC/EdDSA/ECDSA/RSA/PSS algorithms. The manifest explicitly labels
  provider regressions as ID-token verification profiles; these do not establish
  full Apple/Cognito/Facebook/Microsoft OAuth or account integration. Remote-key
  caching, remaining provider options and the broader account APIs remain open.

- Corrected ID-token configuration boundaries: explicit empty issuer allowlists
  reject tokens; max-token-age parsing follows JOSE's unit grammar and rounding
  before applying a negative sign, and occurs after key resolution/signature checks.
  Eight additional independent cases compare JOSE, including invalid month units,
  large finite durations and callback ordering.
- Added the shared native authorization-URL builder and Basic credential helpers.
  The complete pinned helper sources run all four URL and thirteen credential
  cases unchanged. The builder preserves query order, replaces duplicate controlled
  keys, derives S256 PKCE, protects reserved parameters, supports configured endpoint/
  redirect overrides, scope joiners and claim requests, and uses native WHATWG-style
  form/UTF-8 encoding. Basic decoding follows the pinned lenient base64/percent
  behavior and validates the scheme, separator and nonempty credential halves.
- Routed Google authorization through the shared builder. Per-request scopes,
  login hints and additional parameters reach native policy; reserved/malformed
  parameters are rejected at the HTTP boundary. Redirect responses set Location
  only when requested. Google preserves duplicate scopes like the pinned provider;
  two older owned tests had incorrectly expected deduplication and were corrected
  against the source. Imported all five includeGrantedScopes cases from social.test
  unchanged, with the other 80 declarations explicitly unported in its manifest.
  Twenty-eight independent helper/HTTP cases and two native tests cover encoding,
  malformed input, query handling, options callbacks, PKCE and Google integration.
  Broader WHATWG URL normalization, remaining provider options, OAuth state/account
  flows, linking and refresh remain incomplete.

- Added native token request builders for authorization-code, refresh-token and
  client-credentials grants. Strategies cover public clients, secret-in-body,
  correctly form-encoded Basic credentials, private-key JWT and custom request
  callbacks. Native policy enforces manual-assertion pairing, conflicting secret/
  strategy rejection, primary client identity, refresh-owned/unsafe parameter
  filtering and repeated resource indicators. Callback errors retain their causes
  through the platform fixture. Redirect-refusing requests and normalized responses
  remain native, including response-time token deadlines.
- Added native private-key JWT assertion validation/signing with eager option
  checks, algorithm/kid precedence, fresh RFC 7523 claims and unique jti. JWK and
  unencrypted PKCS#8 inputs use native Ed25519/OpenSSL primitives. The complete
  client-assertion, private-key authentication and refresh helper source files run
  all 39 declarations as 41 cases unchanged. Eight independent cases verify PKCS#8
  RSA/PSS/ECDSA/Ed25519 assertions with JOSE, real HTTP grants, fractional expiries,
  response-time clocks, scope differences and async callback context/errors.
  These are standalone grant helpers; account refresh endpoints, automatic refresh,
  account linking and full provider integration remain incomplete. Broader response
  coercion, transport error shapes and redirect-helper callback parity remain open.

- Added the native one-time-token plugin, typed generation/redemption APIs and
  trusted verification creation/find/consume APIs. OTTs bind to an existing session,
  support plain/SHA256/custom hashing and generation callbacks, configurable precise
  expiry, client-request restrictions, cookie suppression and session OTT headers.
  Consumption commits before session lookup so a revoked/expired session cannot
  restore a token. Session-header tracking follows cookie issuance, including OTT
  redemption, rather than raw internal session allocation.
- Verification APIs preserve metadata and create-hook patches, implement plain/
  hashed identifiers with ordered prefix overrides, latest-record consumption,
  invalidation of older duplicates, expiry cleanup, delete veto/after hooks, and
  atomic secondary-store getAndDelete with optional database copies. Read cleanup
  preserves upstream's captured expired row for the first read. Custom identifier
  hashing and default-string-ID reservation gates are now implemented; configured
  persisted serial ID strategies and complete integration of legacy token helpers remain open. These are distinct from OTT's supported custom hasher.
- Imported all fourteen one-time-token source cases unchanged and all twelve cases
  from the internal-adapter consumeVerificationValue suite unchanged. The other
  58 internal-adapter declarations remain explicitly unported. Nine independent
  cases and two native tests cover independent hashing, native typed APIs, token
  burn after revocation, millisecond expiry boundaries, callback patches, duplicate
  records, cookie/header lifecycle and absence of extra session creation. The
  importer can extract an intact nested suite while retaining the complete original
  source and inventory; fixture callbacks still execute native operations.

- Added the native email-OTP plugin with all nine HTTP endpoints and trusted
  create/read APIs. Configurable codecs, rotate/reuse behavior, attempt budgets,
  plugin rate limits, email-verification overrides, auto sign-in, password resets
  and authenticated email changes run in V. OTP consumption commits separately
  from downstream sign-in errors; password reset keeps successful consumption in
  the credential transaction so failures preserve the code. Verification update/
  delete-by-identifier APIs support resend and attempt accounting.
- Imported the entire email-OTP source file with all 91 upstream cases unchanged.
  Three independent Brand Map configuration cases cover hashed rotating codes,
  five attempts, core verification overrides and both email-change proofs; one
  native test verifies hashing, sign-in and single use. Database reservation
  locks for unverified account promotion are now implemented; complete public
  callback contexts remain open and PostgreSQL/Redis integration.

- Added deterministic verification reservations using a database primary-key gate,
  duplicate re-read and explicit rejection of secondary-only storage. Create hooks
  cannot replace the reservation key. Custom identifier hash callbacks support
  ordered prefix policies across create/find/update/delete/consume/reserve. Email-
  OTP promotion re-reads the user under a reservation before removing pre-proof
  accounts and sessions. Independent SQLite connections share the gate.
- Imported nine unchanged default-ID reservation cases, including both duplicate
  upstream suites; UUID/serial strategy cases remain explicitly excluded. Two
  independent callback/key lifecycle cases and a native SQLite connection test
  cover custom prefix precedence, hook bypass, deterministic IDs and release.

- Added native anonymous identities, protected isAnonymous defaults, custom email/
  name generation, explicit deletion and guest-account linking callbacks. Cookie
  issuance triggers the link callback before cleanup. Server-owned OAuth state
  carries the guest ID across cookie-less callbacks; client additionalData cannot
  impersonate a guest. Cleanup respects same-user/anonymous destinations and the
  disable-delete option.
- Fifteen original anonymous source cases run unchanged, including Google OAuth,
  verification-based upgrades and spoofed guest IDs. Three independent cases cover
  a Brand Map style domain merge callback with nested native adapter calls, hashed
  email-OTP upgrades, cleanup disabling and explicit deletion/token revocation.
  One native test covers protected guest identity, repeated sign-in and deletion.
  The generic-OIDC Expo case is now imported too; two direct JS middleware-mock
  cases remain explicitly unported; the anonymous file is a partial import.

- Added native generic OAuth/OIDC discovery, PKCE, Basic/body token authentication,
  token/profile application callbacks, signature-verified JWKS identities and bound
  request nonces. Provider metadata failures skip affected providers; known-valid
  callbacks produce upstream-style signup/error redirects. Trusted same-email
  linking, explicit/implicit signup gates and separate password registration
  controls support the current Nabu login configuration.
- Imported all twelve generic-OAuth ID-token cases unchanged plus selected scope,
  signup and discovery cases (21 runtime cases total). Added the original generic-
  OAuth anonymous Expo callback case. Four independent Nabu cases exercise a real
  mock IdP, Basic credentials without body secrets, PKCE, verified provisioning
  policy, same-user linking, replay prevention and disabled password registration.
  A native signed-token test covers discovery, subject selection, nonce and forged
  signatures. Atomic SQLite rate limits are now implemented; MongoDB, retry/cache, full generic
  options/linking/refresh and actual Nabu application migration remain open.

- Added native Redis secondary storage with application client transport and a
  built-in RESP2 TCP transport. Policy covers prefixed commands, GETDEL compatibility
  fallback, fixed-TTL atomic counters and safe SCAN enumeration/clearing. The TCP
  transport authenticates each fresh connection, preserves binary UTF-8 strings,
  bounds responses and enforces I/O deadlines without retrying interrupted mutations.
- Imported the complete Redis package test file unchanged: 15 runtime cases. Seven
  additional real-server/protocol cases verify cross-instance auth session/OTT
  sharing, fixed TTLs, literal-prefix isolation, authentication errors, fragmented
  and oversized replies, and mutation timeouts. The integration tests start an
  isolated password-protected local Redis and shut it down afterward; redis-server
  and redis-cli are required for those tests. TLS, pooling, native dial deadlines
  and the application-specific tolerant/strict wrapper remain open.

- Added rolling-window rate limits with native memory and atomic SQLite database
  backends, sensitive-route defaults, plugin overrides and static wildcard/disabled
  rules. SQLite schema v5 adds indexed persistent counters; immediate transactions
  serialize independent connections and counts remain committed across auth errors.
  Responses match upstream JSON and X-Retry-After boundaries. Cleanup retains the
  longest statically configured window.
- Imported 16 unchanged rate-limiter cases for memory/database concurrency, window
  boundaries and static rules. Two independent Nabu configuration cases cover failed
  authentication, trusted-call bypass and rightmost forwarded-chain isolation. Two
  native tests exercise racing independent SQLite connections, rolling windows and
  longer-window retention. MongoDB integration, dynamic/custom/secondary stores,
  precise cleanup-hook scheduling, environment defaults and full IP/proxy policy
  remain unported. The rate-limiter file is a partial import. An older owned test
  now sets an explicit two-request sign-in rule; upstream sensitive-path defaults
  override the global max with three. Its assertions are unchanged.

- Added native record ID generation with 32-character alphanumeric defaults, UUIDs
  and supplied model-aware generators across users/sessions/accounts/JWKs/trusted
  verifications. Opaque session/reset tokens retain their independent entropy.
  UUID reservation gates format deterministic digests as version-five UUIDs so
  forced IDs remain stable; custom application IDs are preserved through hooks.
- Imported the complete core ID-field source file unchanged (27 runtime cases),
  including generator precedence, forced transforms and deterministic ID warnings.
  The fixture carries opaque native helper state and invokes supplied generators;
  field policy remains in V. Added the original UUID reservation case, three
  independent persisted-generation/digest cases and one native typed API case.
  Persisted serial/database-generated IDs, full physical schema mapping and legacy
  opaque-verification digest IDs remain open; passing helper tests does not provide
  a serial database adapter.

- Unified reset, OAuth-state, deletion and native magic-link proofs through the
  trusted verification APIs. Configured hashing/prefix policy, Redis storage, UUID
  IDs, hook metadata and atomic consumption now apply to these flows. New reset
  tokens use the pinned 24-character form, and trusted APIs can supply reset proofs.
  Legacy digest-keyed rows remain readable without new non-upstream lookup columns.
  OAuth state is burned before exchange; deletion consumption commits before owner
  checks. Native magic links revoke pre-proof access and use session-cookie/cache/
  OTT issuance. The existing-user-only registration limitation remains explicit.
- Existing upstream reset, email verification, generic OIDC and anonymous suites
  pass. Four new independent cases cover hashed UUID reset/deletion records,
  supplied reset proofs and magic-link cleanup/header issuance. Existing Nabu/Redis
  suites add hashed secondary-only OAuth/reset cases. Native millisecond assertions
  are retained while locating newly created proofs by the new logical identifier.
  Build scripts disable V compiler automatic bug-report uploads after a compiler
  ternary/json code-generation failure; the native workaround compiles successfully.

- Added native libpq PostgreSQL storage using physical columns, UUIDs, table/field
  mappings, explicit transactional migrations and additional user/session fields.
  Concurrent migrations serialize with a schema-scoped advisory lock. Sessions use
  upstream-shaped token columns; signed nonpersistent markers suppress refresh.
  User updates patch changed fields and read back the stored row before hooks/cache
  mirroring, preserving concurrent application role changes. Quoted identifiers and
  application-owned columns are independently tested.
- Repeated 213 original runtime cases from sign-in/sign-up, core sessions,
  one-time-token, email OTP and password reset on isolated PostgreSQL 18.4 clusters.
  Five additional contracts verify physical columns, separate-process proof
  consumption/reservations, concurrent rate limiting/migrations and application
  update isolation. Backend copies preserve assertions without increasing the
  unique upstream corpus count. PostgreSQL setup is checksum-pinned and isolated
  under ignored build/deps. This does not prove compatibility with live Brand Map
  databases or complete Prisma/plugin/query parity. MongoDB remains open for Nabu.

- Added native two-factor storage (SQLite schema v6, map snapshots, mapped
  PostgreSQL factor rows), encrypted TOTP enrollment/confirmation, delivered OTPs,
  recovery-code codecs, trusted devices, challenge caps and account lockout. The
  sign-in gate runs before cookie/JWT/OTT issuance. Passwordless controls and custom
  codecs remain application-supplied callbacks. Account changes preserve lockout
  state on authenticated re-verification. Factor row locks protect PostgreSQL
  operations across connections.
- All 71 main upstream two-factor runtime cases pass; 20 selected security/attempt/
  lockout cases also pass, with the server-error case isolated unchanged to avoid
  the serialized fixture spending the shared account budget in a previous burst.
  The original attempt file remains partial: its complete shared-account ordering
  has not passed. The same 91 cases repeat on mapped PostgreSQL. Legacy JS adapter
  fallback/direct atomic injection, username/phone probes and middleware newSession
  probes remain excluded. Four owned cases cover Brand Map fixed-code codecs,
  JWT/OTT ordering, separate-process PostgreSQL redemption and HTTP rate limits.
  Three native functions cover RFC vectors, imported Base32/window handling and
  typed sign-in challenge responses. No application database was touched.

- Added native additional-field input validators/transforms with Standard Schema
  result/error precedence and explicit async validation rejection. Field uniqueness
  is enforced in maps and SQLite/PostgreSQL indexes; SQLite configured unique fields
  require explicit migration before writes. PostgreSQL uses fieldName aliases when
  adapter mappings do not override them. Four native functions cover parser policy,
  migration idempotence/fail-closed writes and rollback behavior.
- Added mapped provider fields, protected-field filtering/defaults and optional
  implicit-link profile sync. PostgreSQL savepoints recover rejected profile updates
  while retaining provider account bindings. Five unchanged upstream profile-input
  cases run on SQLite and PostgreSQL. Seven owned cases verify Brand Map username
  rules, validator/transform ordering, async rejection, uniqueness across adapters,
  PostgreSQL races/aliases and rejected-sync recovery. Broader linking, output
  transforms, functional defaults and complete query/schema support remain open.

- Added implicit-link local-email verification gates (default required), verified
  provider/local trust handling and disableImplicitLinking. The explicit pinned
  legacy local-verification opt-out promotes verified provider email only after
  account binding validation. Google callback rejections use the source redirect.
  Ten unchanged upstream policy cases repeat on SQLite/PostgreSQL text-ID schemas;
  the text matrix preserves deliberate non-UUID fixture IDs. Four Nabu contracts
  cover the local default rejection, opt-out, trusted-provider linking switch and
  the application provisioning callback verifying the row before the native gate.
  A native matrix checks gate combinations and promotion. Explicit linkSocial and
  remaining binding/provider integration remain unported.

- Fixed an OTP resend race found by the full regression run: email and two-factor
  OTP replacement no longer leaves older proofs selectable when createdAt values
  share a millisecond. The existing hashed/five-attempt contract now freezes time;
  an additional PostgreSQL contract verifies the same timestamp collision. Source
  email-OTP and two-factor assertions remain unchanged. This changes proof-delete
  hook timing on replacement; exhaustive callback sequencing remains open.

- Added optional native MongoDB storage for Nabu using the checksummed C driver,
  V BSON encoding, ObjectId/binary-UUID/custom string IDs, mapped collections/fields,
  replica-set transactions, explicit migrations, scalar additional-field uniqueness,
  indexed session lookup, atomic verification consumption/reservation and shared
  database quotas. Session dates are BSON dates with a real TTL index. Existing
  Nabu indexes are reused when their keys/options are equivalent.
  284 unchanged upstream auth cases repeat on an isolated MongoDB replica set;
  these copies do not increase unique corpus coverage. Nine owned contracts cover
  physical types, metadata, rollback, pagination, aliases, uniqueness, shared quotas,
  TTL and existing Nabu indexes. Two more Nabu contracts verify actual MongoDB
  provisioning callbacks, signed OIDC/Basic/PKCE login and replay/unprovisioned
  rejection. Three native BSON functions cover wire fixtures, literal JSON and
  structural rejection. Generic MongoDB queries, driver-mock source tests, transient
  transaction body retries, exhaustive commit/abort behavior, optional profile-sync
  failure recovery and actual application migration remain open.

- Added native admin user/role/ban/password/session operations and permission
  checks, with separate role/ban/email grants, authoritative roles/session revocation
  despite stale cookie snapshots, and ban enforcement on internal session creation.
  Supports Brand Map's custom role names, plugin field aliases, provisioning gate,
  defaults, custom ban messages and fractional/default ban durations. PostgreSQL UUID
  user lookups return absence for malformed external IDs instead of a database cast
  error. 78 unchanged upstream cases repeat on all three native database adapters;
  thirteen owned contracts and three native functions verify the security boundaries.
  Impersonation, callback redirects, generic endpoint hooks, query performance and
  the excluded source cases remain open.

- Added admin impersonation/restoration, protected ownership/session overrides,
  independent expiry, original remember preference, signed restoration cookies,
  separate admin-target permission and normal-session filtering. Banned OAuth
  callbacks now roll back pending writes and redirect with the configured message,
  preserving trusted callback query parameters and fragments. The main 70-case
  admin suite passes in full; 90 selected source cases repeat on all three adapters
  (270 cases). Twelve owned impersonation contracts and two more native functions
  cover cookie persistence, forged/revoked/restored sessions, current roles, hook
  inputs, ID isolation and failed OAuth rollback. Pure SDK constructor/client probes,
  generic endpoint hooks and numeric-ID/username variants remain open.

- Added the organization CRUD/membership foundation, static permission enforcement,
  protected Brand Map review fields and creator/lifecycle hooks. SQLite migration 7
  and mapped PostgreSQL/MongoDB models provide scoped persistence with uniqueness
  and deletion cleanup. PostgreSQL readback preserves externally changed moderation
  fields. 22 unchanged source cases repeat across three backends (66 cases), plus
  nine owned contracts and three native functions. Invitation APIs and dynamic roles
  remain the next Brand Map requirements. Source fixtures translate upstream's
  test-only origin/CSRF defaults explicitly; native production validation stays strict.
- Isolated simulated-clock MongoDB tests from the real TTL worker. A separate
  TTL-enabled replica set continues to verify actual expiration and equivalent
  existing indexes; production storage behavior is unchanged.

- Added native organization invitations, email callbacks, custom expiry, limits,
  resend/cancel policies, recipient ownership/verification gates and trusted email
  enumeration. Guarded status transitions and transactional acceptance prevent
  duplicate membership; independent PostgreSQL/MongoDB concurrent requests verify
  one winner. Hook/delivery failures roll back database changes and allow retry.
  18 unchanged invitation cases repeat on three backends (54 cases), and two more
  CRUD cases per backend cover invitation views and hook-supplied IDs. Eleven owned
  contracts plus one native function verify integration boundaries. Database-owned
  numeric IDs, team invitations and full callback context remain open.

- Added dynamic organization role CRUD, current-membership permission checks and
  static/database grant merging. Scoped authorization, grant-subset errors, reserved
  names, assigned-role deletion guards, role caps and protected additional fields
  are native. Member-role assignment validates dynamic roles after authorization,
  preserves owner constraints and runs lifecycle hooks. 24 unchanged runtime source
  cases repeat on three backends (72 cases), plus two source grant-merge cases per
  backend and nine owned integration contracts. Brand Map's `accessControl` resource
  remains distinct from Better Auth's `ac` policy. Aggregate concurrency, functional
  role caps and full generic adapter/context behavior remain open.

- Added member list pagination/filtering/sorting with complete user joins, active
  role lookup, member removal and leaving. Removal hooks roll back on failure;
  owner/tenant guards and active-cookie cleanup are verified. Organization deletion
  returns the deleted record and clears current active selection. 22 unchanged
  member source cases repeat on three backends (66 cases), including official-client
  logout hook invalidation, plus nine owned integration contracts with 111-member
  joins. Generic adapter instrumentation, aggregate owner races, functional limits
  and forbidden-read active-selection cleanup remain open.

- Added the initial native OpenAPI generator and configurable Scalar reference
  page. Known models/core routes, user request fields, nullable session and social
  token shapes, unique operation IDs, explicit native endpoint metadata and hidden
  paths are supported. Reference values/nonce attributes are escaped. 16 unchanged
  source cases and three owned contracts pass; the manifest explicitly identifies
  omitted standalone fixtures for unselected tests. Complete endpoint snapshots,
  automatic plugin schemas and arbitrary Zod composition remain open.

- Fixed active-organization cleanup after denied metadata/full reads or activation.
  Intentional cleanup commits while preserving the 403 response, and refreshed
  cookies reflect the cleared selection. Missing-organization reads retain a valid
  selection; failed activation clears it. Twelve independent cases repeat across
  the three adapters alongside 72 unchanged CRUD source cases. Other failures
  retain normal rollback behavior.

- Added synchronous functional additional-field creation defaults for users,
  sessions and organization models, including trusted user/session creation.
  OpenAPI generation omits runtime defaults and does not execute factories.
  Explicit values/nulls and existing read/update values remain stable, and session
  factory failures roll back all signup writes. The unchanged runtime source case
  repeats on three adapters; nine owned contracts and two native functions verify
  the boundaries. TypeScript date hydration follows configured record schemas while
  JSON fields stay literal. Async/update factories and exhaustive transform/default
  combinations remain open.

- Added six unchanged additional-field integration cases on SQLite/PostgreSQL and
  five on MongoDB (17 repeated cases), including two-factor coexistence, official
  clients, profile updates and secondary-session defaults. SQLite's configured
  missing user/session fields now read as null consistently across lookup/list APIs.
  One native function verifies legacy payloads remain unchanged and factories never
  execute on these reads. Reserved credential/transport user names remain absent.
  Pure SDK probes and MongoDB's inapplicable SQL-null case
  remain explicitly excluded.

- Completed preservation of the additional-fields source file: its four remaining
  SDK/type probes run through a lazy native constructor fixture and the official
  SDK, with an explicit execution-surface label. API/HTTP/context calls from that
  constructor delegate to V and unsupported/prototype names fail explicitly.
  Two native integration contracts verify constructor session protections and
  React client sign-in fields. React/type test dependencies match the upstream
  lockfile. These compiler/client probes are distinct from native runtime coverage;
  the fixture does not establish complete production constructor/client parity.

- Corrected the source inventory to union complementary imports by AST source
  position and verify every matching checksum. Repeated backend copies and duplicate
  titles cannot inflate coverage. Six audit cases cover complementary selections,
  repeats, ambiguous legacy records, stale checksums and invalid source metadata;
  `make check` now includes them. Source bodies/assertions are unchanged. The inventory
  identifies 1,204 preserved declarations, distinct from runtime/backend case counts.

- Added native OpenAPI request schemas for all nine public email-OTP POST endpoints,
  including required fields, purpose enums, extensible signup input and the deprecated
  reset alias. Three additional unchanged upstream cases and one owned live OTP
  signup contract pass; trusted internal OTP APIs stay hidden from HTTP docs.

- Added declarative native custom endpoint input schemas and V projection for
  object/record intersections, unions, arrays, nullable/default/catch/readonly/pipe
  wrappers, required properties and query string constraints. Seven additional
  unchanged upstream cases pass. Two owned contracts verify conflict fallback,
  explicit override precedence and factory/preprocessor/handler isolation; two
  native functions verify structural merges and malformed/deep schema rejection.
  The fixture translates Zod structure only. This documentation IR does not install
  runtime validators; remaining schema kinds and plugin route shapes remain open.

- Added OAuth form/JSON POST callbacks that redirect to GET without consuming state
  or exchanging codes. The eventual GET still requires the bound browser cookie and
  rejects replay. Native validation retains cookie-bearing CSRF checks; one native
  function, three signed Nabu OIDC backend contracts and an HTTP boundary contract
  cover the flow. Two unchanged upstream OpenAPI cases verify both callback methods,
  path parameters and separate operation objects. OAuth-proxy/SAML parity is not
  implied by these core callback and documentation contracts.

- Imported fourteen additional unchanged verification storage cases: hashing/prefix
  overrides, legacy plain-token fallback after changing configuration, secondary-only
  and dual persistence, database fallback, deletion, TTLs and pre-parsed date revival.
  Native fixture instances sharing a descriptor now use the same real temporary SQLite
  file. The focused matrix passes 38 cases; type checking and six inventory audit tests
  pass. This fixture/coverage batch changes no native authentication implementation.

- Added OAuth missing-state/provider-denial/missing-code redirects, generic callback
  issuer checks before token exchange and session-hook API error redirects with
  account/user/session rollback. Three unchanged upstream generic-OAuth cases and
  six Nabu contracts verify these on the three native adapters; one native function
  checks binding, proof retention/consumption and replay. Public provider metadata
  now includes the actual discovered issuer. IdP-initiated flows and remaining global
  error/context mappings remain unported.

- Preserved application policy/hook API error codes and descriptions in OAuth
  redirects, including exact casing. Callback rejection now rolls back pending
  identity/account writes and queued effects while leaving consumed state unusable.
  Two unchanged upstream policy tests, nine signed OIDC contracts across all three
  adapters and one native function verify returned/thrown errors, before-account
  hook failures, stateless rejection, replay and ordinary HTTP error privacy.
  Post-commit hooks/external effects remain outside rollback guarantees.

- Aligned OAuth state-cookie naming/root path and cleanup with upstream, while
  accepting earlier native cookies only when the canonical cookie is absent.
  Account linking now defaults to enabled under the existing verification/trust
  gates, with explicit opt-out preserved; account JSON outputs materialize nullable
  token/scope fields. Five more unchanged generic-OAuth cases verify full flows,
  account/session data and provider failures. Three backend contracts verify linking
  defaults/opt-out and null expiry; a native function covers cookie migration,
  canonical precedence and replay. Cookie-only/JWE state formats remain unported.

- Distinguished OAuth token, profile, identity and session failure boundaries.
  Token failures use `invalid_code`; ordinary identity failures use the upstream
  creation/linking codes; profile API errors preserve HTTP status/message/optional
  code, including Nabu's 403 rejections. Code-less policy errors and unexpected session
  exceptions keep their HTTP behavior. The bridge preserves API-error identity across
  nested calls, and consumed state cookies expire on HTTP failures. Two unchanged
  upstream cases, 45 backend error contracts and three Nabu linking-failure contracts
  verify these behaviors; Nabu's older owned redirect assertions were corrected using
  pinned source and an installed-upstream profile-error check.

- Exposed native provider display names, including Nabu's configured label and
  exact omitted/empty-name semantics. One unchanged upstream case and an owned
  metadata case extend coverage; the focused generic-OAuth/Nabu matrix passes 61
  cases, with type checking and six audits; it is included in the complete run below.

- Documented all 27 public organization routes, including writable/protected Brand
  Map fields, nested role grants, queries and response containers. Disabled dynamic
  role paths and trusted-only selectors stay hidden. Four owned schema/live HTTP
  contracts cover all three adapters, with the unchanged upstream CRUD/dynamic-role
  and OpenAPI suites in a 191-case focused matrix. These documentation assertions
  are owned coverage, not new upstream OpenAPI declarations. The live tests exposed
  eager organization default evaluation; supplied values now bypass factories and
  missing values evaluate once. A native throwing-factory regression also passes.

The latest complete verification passes 3456 TypeScript cases across 151 files, all 126
native V test functions across 40 files (including all 20,034 Unicode vectors),
TypeScript checking and the real HTTP migration/auth/CSRF/restart smoke test.
The TypeScript suite ran in four disjoint shards after monolithic runs were
terminated with signal 9; it covers every current test file. The ten
source-preservation audit tests also pass. Formatting and `git diff --check` pass. Repeated backend runs do not increase unique
upstream source coverage, and these results do not imply full upstream parity.

The user resumed work and authorized incremental commits and pushes to
`alexvyber/better-auth-v`, prioritizing missing Brand Map and Nabu capabilities.
The objective remains incomplete. The corpus currently records 34 completely
imported files, sixteen partial imports and 386 unported files; imported status describes source
preservation, not broad feature completion.

1. Complete hook and secondary-storage parity: partial-update payloads, precise
   cancellation results, full context, remaining transaction combinations, and remaining
   adapter operations/observability. Cache effects are not distributed transactions;
   rollback cleanup is best effort and cannot reverse existing updates/deletes.
2. Complete remaining JWT/plugin integration details: schema/column mappings,
   remaining callback/type counterparts, and broader provider use. Verify combinations with deferred
   read-only session GET and other hooks; JWT header issuance can rotate keys.
3. Complete remaining admin integration and complete remaining organization context/query integration, plus account-cookie behavior and remaining rotation combinations. The complete
   sign-up/session source runs do not establish full plugin or stateless parity.
   Preserve every original assertion when importing additional suites.
4. Complete the PostgreSQL/MongoDB adapter contracts, query and plugin schemas, and add MySQL,
   remaining secondary stores, and plugin schemas. The existing SQLite payload schema is
   not the upstream physical schema.
5. Implement the remaining provider, plugin, client-contract, browser integration,
   and tooling surfaces listed in the corpus and compatibility contract.

## Existing application schema and bearer compatibility gate

The application schema gate seeds Brand Map's existing PostgreSQL tables and Nabu's
raw MongoDB documents before native initialization, disables V migrations and drives
native authentication with the official SDK over HTTP. All four new contracts pass,
including schema preservation, mapped fields, existing upstream credentials/cookies,
renewal, restart/revocation, JWT keys, protected fields, organizations/roles/invitations,
OTP and one-time tokens. The snapshot and its deviations are documented in
`docs/application-compatibility.md`. Current Brand Map source includes admin and
one-time-token plugins. Full applications and their domain services are not run.

The gate exposed a fixed-length cookie-token assumption and the wrong bearer output
header format. Native cookies now accept other upstream token lengths with HMAC
verification intact; bearer scheme casing/whitespace/signature encoding and invalid
signed-header cookie fallback follow upstream. The full original bearer suite passes
on SQLite, PostgreSQL and MongoDB: 33 runtime cases, seven unique source declarations.
The corpus now preserves 1211 unique declarations. A native signature regression also
passes. Generic adapter query/join/transaction-failure contracts remain incomplete.

## Shared adapter conformance continuation

The complete upstream shared `auth-flow.ts` and `transactions.ts` suites are now
preserved and registered against native SQLite/PostgreSQL/MongoDB. Their eight
object entries run twenty-four cases, tracked separately from the test/spec corpus
in `adapter-suites.imports.json`; no test bodies/assertions are changed. Two source
audits validate snapshots, checksums and registrations without requiring an upstream
checkout during ordinary `make check` runs.

The adapter facade now delegates `transaction()` to native transactions, borrowing
an active native callback context for nested calls. Raw user writes honor
`forceAllowId` and schema defaults without application creation hooks. Equality
inspection is applied inside callback transactions. Nine owned contracts verify
commits, nesting, rollback/error identity, connection recovery, ID/default semantics,
hook isolation and filtered reads. The focused adapter/member/profile/JWT regressions
and type checking pass. Driver-specific generic queries/joins and transient or
ambiguous-commit cases remain incomplete.

Native context frames now distinguish active transactions from after-commit hooks.
`EndpointContext.with_transaction` opens a fresh atomic transaction after commit,
sharing an existing one while active. The after-commit contracts verify independent
commit and rollback without reversing the original user creation. Nabu's MongoDB
OIDC gate now starts from directly provisioned BSON documents and app-created indexes
before native initialization, with migrations disabled, and preserves application
data through the signature-verified verification/linking flow.

Final `make check` passes 2895 runtime TypeScript cases across 149 files, 122 native
V functions across 38 files, all eight source-preservation audits, type checking
and the native HTTP migration/auth/restart smoke. Formatting and diff checks pass.

## Core adapter queries and joins

Native `adapterQuery` now evaluates validated core-model predicates, date/numeric
comparisons, nulls, membership, literal string matching, comparison modes, AND/OR
groups, stable sorting, pagination and projections. User/session/account joins
support bounded forward arrays and backwards user objects. Raw creation covers all
four core models; user updates, deletion and counts execute through native storage.
General query execution is scan-based; session-token authentication remains an indexed
lookup and user relations are scoped before decrypting session rows. The session
interceptor now follows the flat joined DTO and retains private persistence metadata.

The preserved basic suite selects 89 of 108 entries; nineteen arbitrary-plugin,
custom-relation and increment entries remain excluded explicitly. The unchanged joins
wrapper repeats applicable selections. The complete shared matrix runs 555 cases on
SQLite/PostgreSQL/MongoDB, without altering test bodies/assertions. Its source-entry
inventory remains separate from the static test/spec corpus. Per-test backend cleanup
bounds temporary disk use. The owned Mongo cursor test now requests 200 rows explicitly
to retain its 105-row getMore assertion under the upstream default 100-row page.

Three native functions verify malformed-query deletion safety, empty-result validation,
projection/tenant scoping, timezone-equivalent date matching and isolation from unrelated
session encryption. Final `make check`: 3426 TypeScript cases / 149 files, 125 native
functions / 39 files, ten source audits, type checking and native HTTP smoke all pass.
Formatting and diff checks pass. Query pushdown, arbitrary plugin relations, guarded
increments, MongoDB transaction retries and organization aggregate races remain open.

## Native MongoDB transaction retries

`Auth.with_transaction` and inactive `EndpointContext.with_transaction` now delegate
replayable callbacks to `mongoc_client_session_with_transaction`. Transient body or
commit failures replay the body; unknown commit results retry commit without body
replay. Failed-attempt pending hooks/cache cleanup are discarded, and committed
hooks execute after the driver's successful commit. The native RPC preserves MongoDB
labels and original callback identity, including a final commit error after an earlier
transient callback error. Auth has a stable heap lifetime across native callbacks.

A terminal failed commit uses a best-effort raw abort on its exact session/transaction,
tracked through public APM metadata, with one retry for retryable abort errors. Settled
251/256 replies are accepted, cleanup failures are logged without replacing the primary
error, and sessions end on every result. Trusted diagnostics expose command counts and
abort results. The test replica set alone enables test commands for fault injection.

Eight owned real-server fault contracts cover replay, partial rollback, commit-only
retry, committed-hook counts, terminal cleanup, retryable cleanup, error preservation
and recovery. One native function checks error-label/cleanup decoding. The unchanged
upstream auth/rollback/basic/join matrix still passes. These fault contracts are native
equivalents; the original Node-driver mock suite is not claimed as imported.

Final `make check`: 3434 TypeScript cases / 150 files, 126 native functions / 40 files,
ten audits, type checking and HTTP smoke pass. This batch exposes retries through the
explicit transaction API and callback contexts. Existing `with_internal` and HTTP
transactions retain their current boundaries; organization HTTP integration is next.
Callbacks in replayable transactions can execute more than once, as upstream does.

## Organization aggregate concurrency

Organization mutations now acquire a native per-store transaction barrier on
PostgreSQL and MongoDB; SQLite already serializes writers through BEGIN IMMEDIATE.
The barrier covers membership, user-wide organization and role caps, last-owner
transitions and assignment versus role deletion. It requires transactions enabled
and does not coordinate raw domain writes. The coarse scope trades throughput for
portable aggregate correctness across independent Auth instances.

MongoDB organization POST routes use the managed transaction runner, restoring
request-local session/anonymous/OAuth state before replay. Session-read transient
errors retain their retry label inside this scope. Other HTTP paths keep their
existing boundaries, including intentional intermediate commits. Coordination data
is installed by explicit native migrations; cold instances probe existing data
without runtime collection creation and fail closed until migrated if it is absent.

Twenty-one owned concurrency/rollback cases run across three backends, plus one
MongoDB cold-instance/migration recovery case. Isolated binaries with the barrier
removed reproduce two successful additions at a one-slot membership limit on both
PostgreSQL and MongoDB. The original invitation concurrency contracts exposed a
hook-order deadlock: acceptance now preserves beforeAcceptInvitation before the
barrier, rechecks capacity under it and retains its atomic claim. Those unchanged
contracts and the new cases pass together (33 cases). No upstream assertions were
changed or exclusions counted as passes.

Complete TypeScript verification: four disjoint shards pass 1061/701/1139/555 cases
across 38/38/38/37 files (3456 cases / 151 files total). All 40 native test files
and ten preservation audits pass; the organization native tests are rechecked
after the invitation hook-order correction. Type checking and real HTTP migration,
authentication, CSRF and restart smoke tests pass. The monolithic make-check
attempt was interrupted, so these separately completed targets are the validation
record for this batch. The shared basic suite still explicitly excludes nineteen
arbitrary-plugin/custom-relation/guarded-increment entries; this is not full parity.
The owned concurrency fixture uses the harness configuration type instead of
propagating its precise plugin generic through every independent instance. This
avoids excessive compiler work without changing runtime setup or assertions.

## Configured adapter tables and custom joins

Eighteen previously excluded shared basic entries now run unchanged. The focused
auth/transaction/basic/join matrix passes 663 runtime cases across SQLite,
PostgreSQL and MongoDB; basic selects 107 of 108 entries, with only incrementOne
still excluded in this batch. Repeated join/backend cases do not increase unique
source coverage, and the shared helper inventory remains separate from the static
test/spec corpus.

`Config.adapter_models` supplies native table/field/reference metadata. Explicit
migrations create configured SQLite JSON-payload tables, typed PostgreSQL tables
with mapped columns and foreign keys, and MongoDB collections with unique indexes.
Native query execution applies defaults on creation, preserves nullable fields,
arrays and JSON, validates types/references and supports custom raw mutation,
filtering, projection and schema-driven joins. Unique references yield objects or
null; other incoming references yield bounded arrays. Unknown/ambiguous joins fail
closed even for empty base results. The renamed-email foreign-key case passes.

The shared-suite fixture has an explicit schema-only mode: it transports plugin
schema descriptors to native tables without claiming their HTTP endpoints are
implemented. Organization/member/invitation raw models can join custom team tables;
this does not establish full organization-team API parity. Core adapter updates
remain user-only; custom configured models also support updates. References are
validated by native writes; only PostgreSQL currently installs custom foreign-key
constraints in the database. General queries/joins remain scan-based.

Two owned native functions additionally verify memory/SQLite type/reference and
unique failures, JSON preservation, projected joins, rollback and empty-result
ambiguity rejection. Native adapter query regression tests and all ten preservation
audits pass. Configuration must precede migration (`Auth.migrate_storage`); opening
an adapter or creating Auth does not install custom tables.

This batch also passes TypeScript checking and all 128 native test functions across
41 files. Atomic incrementOne is the single remaining shared basic exclusion.

## Guardrails for continuing

- Authentication decisions and persistence belong in V. TS code translates test
  configuration, requests, callback values, and response/error representations.
- Do not replace expected values, remove assertions, or count excluded/disabled
  declarations as passing. Partial imports must remain visible in manifests.
- Tests that depend on JS internals or compile-time types require explicit native
  contract coverage and/or a faithful TS facade; do not mark them passed merely
  because the existing TS implementation passes them.
- Read-only deferred session GET must keep working with `PRAGMA query_only=ON`.
- Preserve transaction rollback, one-time reset/OAuth token consumption, protected fields,
  browser-bound OAuth state, and canonical credential-account selection.
- Use `make check` for the complete current verification set. Real scrypt tests
  take substantially longer than fast fixture authentication tests.
