# VPM package preparation

The intended registry name is `alexvyber.better_auth`. The manifest name stays
`better_auth`, the V module declaration is `module better_auth`, and the repository
is `https://github.com/alexvyber/better-auth-v`. The repository name does not need
to match the registry name. Version `0.1.0` is the initial release candidate;
no release tag or registry entry is created by these preparation checks.

This is an independent partial reimplementation. Read [the compatibility
contract](compatibility.md) before adopting it. Publishing does not imply full
Better Auth parity.

## Consumer requirements

V 0.5.2, Git, a C compiler, OpenSSL 3 development files, SQLite development files,
and libpq development files are required for the default module. Both database
bindings are currently compiled into the root module even when the application
uses another store. No VPM dependencies are declared. Node.js and pnpm are not
runtime dependencies; PostgreSQL and Redis servers are only needed if those stores
are used. SQLite needs no server.

After registry publication, consumers install and import:

```sh
v install alexvyber.better_auth
```

```v
import alexvyber.better_auth

fn main() {
    mut storage := better_auth.open_sqlite('auth.db')!
    storage.migrate()! // Run explicitly as a deployment step in a real service.
    mut auth := better_auth.new(better_auth.Config{
        base_url: 'http://localhost:3000'
        secret: 'replace-with-a-stable-random-secret-at-least-32-bytes'
    }, storage)!
    defer { auth.close() or {} }
    response := auth.handle(better_auth.Request{
        method: 'GET'
        url: 'http://localhost:3000/api/auth/ok'
    })
    println(response.body)
}
```

Direct Git installs before registry registration use `v.mod`'s unqualified name,
so their import is `better_auth`. V 0.5.2 can resolve a registered name for a direct
Git URL after registration; prefer the explicit registry command above to avoid
depending on that lookup. Local checkout examples use the unqualified import.

## Optional MongoDB driver

The default package builds without MongoDB. For `-d mongodb`, build the pinned
MongoDB C driver in the installed module directory first. This optional setup uses
Node.js, CMake, a C/C++ toolchain and OpenSSL 3; it does not require pnpm, npm
packages, a local MongoDB server or the upstream test checkout:

```sh
cd "${VMODULES:-$HOME/.vmodules}/alexvyber/better_auth"
node scripts/build-test-mongo.mjs --driver-only
```

Return to your application's directory and compile with `v -d mongodb ...`.
The driver requires a replica set for transactions. The existing `pnpm mongo:setup`
command additionally prepares the local test server and is intended for contributors.

## Verification before publication

```sh
make check-package
```

This check copies tracked files into two isolated `VMODULES` roots, one with
`alexvyber/better_auth` and one with `better_auth`. It compiles and runs consumers
outside the repository, without custom compiler search paths or global V modules.
It verifies real scrypt/NFKC hashing, SQLite migrations and login after restart,
RSA JWT signing/verification and key persistence, bundled C headers and embedded
Unicode tables. Licenses and required package files must be tracked; generated
build/dependency trees must not be tracked. New package files must be staged before
running this check. The unqualified layout uses VPM's actual Git installer against
a temporary local Git snapshot; the namespaced registry layout is simulated. This
does not submit to VPM or claim that a public registry download has been tested.

The package CI repeats this default consumer check on Ubuntu and macOS using
checksum-pinned official V 0.5.2 release binaries. A green local macOS result alone does not establish Linux or Windows
support. MongoDB dependency setup and the full conformance matrix remain separate
from the default package CI. For implementation changes also run `make check` as
documented in the README.

## Publication steps

VPM requires a public GitHub repository and a GitHub login to submit the package.
Its documentation warns that submitted names/URLs cannot be edited by the
publisher, so verify the exact values before submitting.

1. Review the candidate, compatibility limitations, license notices and CI results.
2. Make `alexvyber/better-auth-v` public when ready. Preparing this package does not
   change repository visibility.
3. Tag the reviewed release commit as `0.1.0` and push that tag. The tag must match
   the version in `v.mod`; do not tag an unverified working tree.
4. Log in at [VPM's submission page](https://vpm.vlang.io/new), submit package name
   `better_auth` for publisher `alexvyber`, and repository URL
   `https://github.com/alexvyber/better-auth-v`.
5. In a fresh temporary `VMODULES`, run `v install alexvyber.better_auth`, then
   compile the consumer above from a separate project. Check the registry entry
   and versioned install `v install alexvyber.better_auth@0.1.0` as well.
6. Change the README's preparation notice to the actual publication status only
   after the registry install succeeds.

See the official [V package management documentation](https://docs.vlang.io/package-management.html).

## License contents

Keep `LICENSE` (this implementation), `UPSTREAM_LICENSE` (imported upstream tests),
and `normalization/data/UNICODE_LICENSE` (Unicode data) with the repository. VPM
clones the repository; it does not produce an npm-style runtime-only archive.
