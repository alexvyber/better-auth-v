# Full-parity work log

The active objective is full Better Auth parity, including the remaining features
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

The latest `make check` passes 867 TypeScript cases across 43 files, all 74 native
V test functions across 20 files (including all 20,034 Unicode vectors), TypeScript
checking, and real HTTP migration/auth/CSRF/restart checks. The complete session
file contains 80 cases and the complete sign-up file contains 37. V formatting and
`git diff --check` pass. These counts do not imply that the full upstream corpus
passes.

The user resumed the full-parity objective and authorized incremental commits and
pushes to `alexvyber/better-auth-v`. The objective remains incomplete.

1. Complete hook and secondary-storage parity: partial-update payloads, precise
   cancellation results, full context, remaining transaction combinations, and remaining
   adapter operations/observability. Cache effects are not distributed transactions;
   rollback cleanup is best effort and cannot reverse existing updates/deletes.
2. Complete remaining JWT/plugin integration details: schema/column mappings,
   remaining callback/type counterparts, and broader provider use. Verify combinations with deferred
   read-only session GET and other hooks; JWT header issuance can rotate keys.
3. Implement complete admin and organization plugins beyond their schema/creation
   foundations, plus account-cookie behavior and remaining rotation combinations. The complete
   sign-up/session source runs do not establish full plugin or stateless parity.
   Preserve every original assertion when importing additional suites.
4. Expand the adapter contract/schema/migrations to PostgreSQL, MySQL, MongoDB,
   secondary stores, and plugin schemas. The existing SQLite payload schema is
   not the upstream physical schema.
5. Implement the remaining provider, plugin, client-contract, browser integration,
   and tooling surfaces listed in the corpus and compatibility contract.

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
