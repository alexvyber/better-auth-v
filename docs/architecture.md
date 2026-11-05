# Architecture and ownership

The public package remains `better_auth`. Its entry consists of `auth.v`,
`config.v` and `types.v`; implementation and co-located native tests live under
`internal/`. Public constructors, record types and storage interfaces retain
their existing names.

```text
internal/
  runtime/                 invocation state, transactions and hooks
  http/                    dispatch, request policy and public API forwarding
  features/<feature>/      feature implementation and native tests
  persistence/<backend>/   auth record storage and migrations
  persistence/queries/     typed adapter execution and joins
  schema/                  configured field and relation registry
  crypto/                  signing, encryption and native headers
adapter/                   independent command grammar
schema/                    independent logical model definitions
domain/                    independent permission and rate-limit policy
storage/                   independent native SQL connection drivers
normalization/             independent Unicode normalization
```

`v.mod` registers `internal` as a recursive source group. These directories
remain `module better_auth`, preserving private access without introducing new
public helpers. They are source organization, not independent V modules.
`adapter`, `schema`, `domain`, `storage` and `normalization` retain their existing
independent module boundaries. Runtime consumers import the public package.

## Model definitions

`schema/models.v` owns the built-in logical fields and reference topology. It has
no storage, HTTP or root-module imports. Storage implementations and schema
generation consume these definitions instead of PostgreSQL acting as the source
of truth for every backend. Returned field lists are copies.

`internal/schema/registry.v` compiles these definitions together with configured additional
fields, organization fields and plugin tables when `Auth` is constructed. Field
validation and join resolution use this registry. Ambiguous or missing relations
fail at lookup, preserving existing behavior for otherwise valid configurations.
Physical column names, migrations and database-specific constraints remain owned
by their storage implementations.

## Invocation and attempt state

`Auth` owns configuration, the compiled registry, storage and the connection lock.
`internal/runtime/operation_context.v` owns mutable invocation data:

- `OperationContext`: request metadata, interception guards and the current attempt.
- `AttemptContext`: session results, anonymous-link state, OAuth consumption state
  and the transaction's pending effects.
- `TransactionState`: active status, after-commit tasks and secondary sessions
  requiring cleanup if the attempt rolls back.

HTTP entry installs an operation and restores the previous operation on exit.
Nested trusted request reads replace request metadata while sharing the enclosing
attempt and interception guards. This is scoped state, not parallel execution:
the existing per-Auth connection mutex still serializes invocations.

## Transactions and effects

`internal/runtime/transactions.v` owns begin, commit, rollback and managed-driver replay. A managed
attempt starts from the captured invocation state with an empty transaction state.
Failed attempts discard queued effects and clean up secondary sessions. Effects
are released after the driver reports a successful commit.

`internal/runtime/transaction_effects.v` owns the typed after-commit task kinds and their execution.
`internal/runtime/hooks.v` owns database hook invocation and hooked mutations.

`Auth.transaction[T]` returns a native typed result. Nested
`EndpointContext.transaction[T]` shares an active transaction, including rollback.
The legacy string-returning `with_transaction` API delegates to the same runner.
Driver callbacks still use their existing string outcome interface; application
results stay in a typed attempt object and are not encoded as JSON.

Replayable callbacks may execute more than once. Use queued after-commit effects
for external work that must occur only after successful commit. An after-commit
failure can surface after the physical database commit, as before.

`Endpoint.transaction_mode` declares the route policy. Its default is
`single_attempt`; organization mutations explicitly select `replayable`. Deferred
session GET retains its read-only policy. Custom endpoints under an organization
URL must declare replayability explicitly; the URL prefix no longer grants it.
Routes that intentionally consume tokens across intermediate commits retain
single-attempt execution.

## Conformance harness

`tests/harness/test-instance.ts` composes the fixture. Its extracted helpers own
types, route metadata, option validation, async scopes, adapter transport, field
conversion and plugin configuration. Async scopes are shared from one module so
nested callback calls retain their native transaction and request association.

`cmd/bridge/main.v` owns CLI selection and initial frame dispatch. Configuration
owns the lifetime of callback-captured values; commands, protocol frames, replies,
storage construction and individual callback families have separate files.
Authentication, predicate evaluation, persistence and retries remain in V.
Imported upstream test bodies and their preservation manifests are unchanged.

## Typed adapter commands

The independent `adapter` module decodes the trusted JSON command boundary into
`Create`, `Read`, `Mutation` and `Increment` variants. Predicates, connectors,
comparison modes, sort direction, pagination, projection and join options are
parsed once. Query execution and atomic retries consume these plans directly;
only application-defined record values remain dynamic JSON. Schema validation
still runs against the Auth registry, including when no row matches.

## Independent storage and domain modules

`storage/sqlite` owns SQLite connection setup, prepared execution and driver rows.
`storage/postgres` owns libpq connections, prepared execution, savepoints and rows.
Neither imports the auth runtime. Database-native types stay behind these module
boundaries. The root storage adapters translate auth records and own their schema
mapping and migration rules, retaining existing public types and storage interfaces.

Driver implementations use V's conditional source files: `-d sqlite` and
`-d postgres` enable the relevant native import and linkage. Without a flag, a
backend exposes the same connection contract with explicit disabled errors and
no database imports. Opening the root adapter therefore fails with the required
flag rather than silently substituting another backend. Memory-only consumers
still need OpenSSL, but neither SQL library. MongoDB retains its separate
`-d mongodb` native-driver opt-in.

`domain/permissions` owns complete-role permission decisions and built-in role
grants. Admin and organization services share it without constructing synthetic
users to check organization permissions. `domain/ratelimit` owns window decisions,
counter progression and retry-after rounding. Both compile and test independently
of HTTP, configuration, persistence, OpenSSL and the root auth module.

Feature orchestration and auth record mappings remain in the public V module,
organized under `internal/features` and `internal/persistence`. Extracting every auth service or complete storage adapter is further
work, rather than a consequence of moving its native I/O into a separate module.
Existing record and storage interface types remain stable: V aliases alone do not
transparently satisfy interfaces using another nominal record type.

## Verification

Run `make check` for native tests, source-preservation audits, TypeScript
conformance/typechecking and HTTP integration. On constrained machines the same
TypeScript corpus can run as four disjoint Vitest shards with one worker each.
`make check-package` additionally verifies unrelated installed consumers, including
nested typed transactions and structured transaction results. Its Git installer
uses a local snapshot; it does not publish to the VPM registry.

For real-scrypt cases on a loaded machine, an optimized native bridge can be
selected without changing test bodies or timeouts:

```sh
V_C_ERROR_BUG_REPORT_DISABLED=1 v -prod -d sqlite -d postgres -o build/auth-bridge-prod cmd/bridge
BETTER_AUTH_BRIDGE_BIN="$PWD/build/auth-bridge-prod" pnpm exec vitest run --maxWorkers=1
```

The MongoDB tests still require their normal Mongo bridge and native driver build.

Native tests are co-located with their sources. Use `make test-v`, or run a
subset with `node scripts/test-native.mjs internal/features/organization`.
`node scripts/test-native.mjs --list` enumerates the tests. V 0.5.2 does not
implicitly load sibling source groups for a nested test; the runner supplies the
rest of `better_auth` through `-file-list`, without copying tests or exposing
private helpers. Independent-module and external-plugin tests compile normally.
The default is one compiler at a time; `BETTER_AUTH_TEST_JOBS` controls concurrency.
