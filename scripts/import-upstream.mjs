import ts from "typescript";
import { testFunctionNames } from './upstream-test-discovery.mjs';
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const commit = "0e75ddcf36489aa3a191ea902a82d1892034dc74";
const repo = resolve(process.argv[2] ?? ".upstream/better-auth");
const marker = resolve(repo, ".source-commit");
const head = existsSync(marker)
  ? readFileSync(marker, "utf8").trim()
  : execFileSync("git", ["-C", repo, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
if (head !== commit)
  throw new Error(`Expected upstream ${commit}, got ${head}`);
const plans = [
  {file: 'verify-id-token', path: 'packages/core/src/oauth2/verify-id-token.test.ts', suites: null, includeHelpers: true,
   testSurfaces: {'verifyProviderIdToken': 'native-provider-policy; provider regressions use native ID-token verification profiles, not full OAuth flows'},
   imports: 'import { createHash } from "node:crypto";\nimport type { JWK } from "jose";\nimport { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";\nimport { describe, expect, it } from "vitest";\nimport type { OAuthIdTokenConfig } from "@better-auth/core/oauth2";\nimport { apple, cognito, facebook, google, microsoft, paypal, supportsIdTokenSignIn, verifyProviderIdToken } from "../harness/id-token.js";\n',
  },
  {file: 'google-provider', path: 'packages/core/src/social-providers/google.test.ts', suites: null, includeHelpers: true, setupCalls: new Set(['vi.mock']),
   imports: 'import { exportJWK, generateKeyPair, generateSecret, SignJWT } from "jose";\nimport { beforeEach, describe, expect, it, vi } from "vitest";\nimport { betterFetch } from "@better-fetch/fetch";\nimport { google, verifyGoogleIdToken } from "../harness/google.js";\n',
  },
  {file: 'oauth-utils', source_file: 'utils', directory: 'oauth2', suites: null, includeHelpers: true,
   imports: 'import type { AuthContext } from "@better-auth/core";\nimport { describe, expect, it } from "vitest";\nimport { symmetricEncrypt, decryptOAuthToken, setTokenUtil } from "../harness/crypto.js";\n',
  },
  {file: 'cookie-utils', source_file: 'cookies', directory: 'cookies',
   suites: null,
   helpers: new Set(['COOKIE_CACHE_JWT_TYPE', 'COOKIE_CACHE_JWT_AUDIENCE']),
   dynamicImports: {'../test-utils/test-instance': '../harness/test-instance.js'},
   extraImports: 'import { beforeAll, afterAll } from "vitest";\nimport type { GoogleProfile } from "@better-auth/core/social-providers";\nimport { HttpResponse, http } from "msw";\nimport { setupServer } from "msw/node";\nimport { signJWT, symmetricDecodeJWT } from "../harness/crypto.js";\nimport { DEFAULT_SECRET } from "../harness/constants.js";\n',
   imports: 'import { afterEach, describe, expect, it, vi, onTestFinished } from "vitest";\nimport type { BetterAuthOptions } from "@better-auth/core";\nimport type { AuthEndpointContext } from "@better-auth/core/context";\nimport { runWithEndpointContext } from "@better-auth/core/context";\nimport { createLogger } from "@better-auth/core/env";\nimport { safeJSONParse } from "@better-auth/core/utils/json";\nimport { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";\nimport { serializeCookie } from "better-call";\nimport { jwt } from "../harness/plugins.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { base64Url } from "@better-auth/utils/base64";\nimport { createHMAC } from "@better-auth/utils/hmac";\nimport { applySetCookies, HOST_COOKIE_PREFIX, SECURE_COOKIE_PREFIX, parseSetCookieHeader, stripSecureCookiePrefix, toCookieOptions, setRequestCookie, parseCookies, getSessionCookie, getChunkedCookie, getCookieCache, getCookies, expireCookie } from "../harness/cookies.js";\n',
  },
  {file: 'origin-check', directory: 'api/middlewares', suites: null,
   imports: 'import { createAuthEndpoint, originCheck } from "../harness/endpoint.js";\nimport { describe, expect, it, vi } from "vitest";\nimport * as z from "zod";\nimport { createAuthClient } from "better-auth/client";\nimport { parseSetCookieHeader } from "better-auth/cookies";\nimport { getTestInstance } from "../harness/test-instance.js";\n',
  },
  {file: 'trusted-origins', directory: 'auth', suites: null, includeHelpers: true,
   imports: 'import { createAuthEndpoint } from "../harness/endpoint.js";\nimport { describe, expect, it } from "vitest";\nimport * as z from "zod";\nimport { getTrustedOrigins } from "../harness/trusted-origins.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport type { BetterAuthOptions } from "better-auth";\n',
  },
  {file: 'cookie-cache-fallback', suites: null,
   imports: 'import { afterEach, describe, expect, it, vi } from "vitest";\nimport { parseCookies, parseSetCookieHeader } from "better-auth/cookies";\nimport { symmetricEncodeJWT } from "../harness/crypto.js";\nimport { getTestInstance } from "../harness/test-instance.js";\n',
  },
  {file: 'error', suites: null},
  {file: 'sign-out', suites: null,
   imports: 'import { describe, expect, it, vi } from "vitest";\nimport { parseSetCookieHeader } from "better-auth/cookies";\nimport type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth";\nimport { genericOAuth } from "../harness/plugins.js";\nimport { getTestInstance } from "../harness/test-instance.js";\n',
  },
  {file: 'update-user', suites: null,
   imports: 'import { describe, expect, it, vi } from "vitest";\nimport { createAuthClient } from "better-auth/client";\nimport { inferAdditionalFields } from "better-auth/client/plugins";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport type { Account, Session } from "better-auth";\n',
  },
  { file: "sign-in", suites: null },
  { file: "email-verification", suites: null },
  { file: "password", directory: "crypto", suites: null },
  {
    file: 'password-reset', source_file: 'password', suites: null,
    imports: 'import { APIError } from "@better-auth/core/error";\nimport { afterEach, describe, expect, it, vi } from "vitest";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport type { Account, BetterAuthOptions } from "better-auth";\n',
  },
  {
    file: 'secret-rotation', directory: 'crypto', suites: null,
    imports: 'import type { SecretConfig } from "@better-auth/core";\nimport { describe, expect, it } from "vitest";\nimport { buildSecretConfig, parseSecretsEnv, validateSecretsArray, formatEnvelope, parseEnvelope, symmetricDecrypt, symmetricEncrypt, symmetricDecodeJWT, symmetricEncodeJWT } from "../harness/crypto.js";\n',
  },
  {
    file: 'crypto-purpose', source_file: 'purpose', directory: 'crypto', suites: null, includeHelpers: true,
    imports: 'import type { SecretConfig } from "@better-auth/core";\nimport { describe, expect, it } from "vitest";\nimport { symmetricDecrypt, symmetricEncrypt, derivePurposeKey, type EncryptionPurpose } from "../harness/crypto.js";\n',
  },
  {
    file: 'jwt-plugin', source_file: 'jwt', directory: 'plugins/jwt',
    testSurfaces: {'jwtClient types': 'official-ts-client-types; native integration covered by tests/jwt-client-contract.test.ts'},
    suites: new Set(['jwt', 'signJWT - alg: $alg', 'jwt - custom adapter', 'jwt - custom jwksPath', 'jwt - signing algorithm comes from the key', 'jwt - remote signing', 'jwt - remote url', 'toExpJWT', 'jwt - unresolved issuer and audience', 'jwt - JWKS minting inside an active transaction', 'jwtClient types']),
    imports: 'import { betterAuth, getMigrations, DatabaseSync, NodeSqliteDialect, runWithTransaction } from "../harness/native-auth.js";\nimport { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";\nimport { createAuthClient } from "better-auth/client";\nimport { jwtClient, inferAdditionalFields } from "better-auth/client/plugins";\nimport { createLocalJWKSet, jwtVerify, decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";\nimport { parseCookies } from "better-auth/cookies";\nimport type { JWKOptions, JwtOptions, Jwk } from "better-auth/plugins/jwt";\nimport type { JSONWebKeySet } from "jose";\nimport type { BetterAuthClientPlugin, GenericEndpointContext } from "@better-auth/core";\nimport { generateExportedKeyPair, toExpJWT, createCookieCacheSigner, SESSION_COOKIE_JWT_TYPE } from "../harness/jwt.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { jwt } from "../harness/plugins.js";\n',
  },
  ...['sign-overrides', 'multi-alg'].map(file => ({
    file: 'jwt-' + file, source_file: file, directory: 'plugins/jwt', suites: null, includeHelpers: true,
    imports: 'import type { AuthContext, GenericEndpointContext } from "@better-auth/core";\nimport type { JWTPayload } from "jose";\nimport { decodeProtectedHeader } from "jose";\nimport { describe, expect, it, vi } from "vitest";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { jwt } from "../harness/plugins.js";\nimport { getJwksAdapter, signJWT, generateExportedKeyPair } from "../harness/jwt.js";\nimport type { JWSAlgorithms, Jwk } from "better-auth/plugins/jwt";\n',
  })),
  {
    file: 'jwt-rotation', source_file: 'rotation', directory: 'plugins/jwt', suites: null,
    imports: 'import { afterEach, describe, expect, it, vi } from "vitest";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { jwt } from "../harness/plugins.js";\nimport type { Jwk } from "better-auth/plugins/jwt";\n',
  },
  {
    file: "session-api",
    helpers: new Set(['refreshCacheTest', 'COOKIE_CACHE_JWT_TYPE', 'COOKIE_CACHE_JWT_AUDIENCE']),
    suites: new Set([
      "session",
      "session storage",
      "cookie cache",
      "cookie cache with JWT strategy",
      "cookie cache with JWT strategy backed by JWKS",
      "cookie cache with JWE strategy",
      "cookie cache refreshCache",
      "cookie cache versioning",
      "date field type consistency",
      "update-session cookie cache revocation",
      "forced strict session validation",
      "deferSessionRefresh",
      "updateSession",
      "get-session cache headers",
      "updateSession plugin authority fields",
    ]),
    imports:
      'import { afterEach, beforeEach, describe, expect, expectTypeOf, it, test, onTestFinished, vi } from "vitest";\nimport type { GenericEndpointContext } from "@better-auth/core";\nimport { runWithEndpointContext, runWithRequestState } from "@better-auth/core/context";\nimport { parseCookies, parseSetCookieHeader } from "better-auth/cookies";\nimport { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";\nimport { jwt, admin, organization } from "../harness/plugins.js";\nimport { signJWT, verifyJWT } from "better-auth/crypto";\nimport { memoryAdapter } from "../harness/memory-adapter.js";\nimport { createAuthEndpoint, freshSessionMiddleware } from "../harness/endpoint.js";\nimport { getSessionFromCtx, getAuthoritativeSessionFromCtx } from "../harness/session.js";\nimport { getDate } from "../harness/date.js";\nimport { getTestInstance } from "../harness/test-instance.js";\n',
    skippedTests: new Set([
    ]),
  },
  {
    file: "sign-up",
    suites: new Set([
      "validateUserInfo sign-up",
      "sign-up user enumeration protection",
      "sign-up session caching",
      "sign-up with custom fields",
      "sign-up CSRF protection",
      "sign-up with form data",
      "sign-up sendOnSignUp option behavior",
      "sign-up enumeration protection — indistinguishable response",
      "sign-up enumeration protection — customSyntheticUser with admin plugin",
    ]),
  },
];
for (const plan of plans) {
  const relativePath = plan.path ?? `packages/better-auth/src/${plan.directory ?? "api/routes"}/${plan.source_file ?? plan.file}.test.ts`;
  const source = readFileSync(resolve(repo, relativePath), "utf8");
  const sourceFile = ts.createSourceFile(
    plan.file + ".test.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  const inventory = [];
  const testNames = testFunctionNames(sourceFile);
  let output =
    "// Generated from pinned upstream source; do not edit assertions here.\n" +
    (plan.imports ?? "") + (plan.extraImports ?? "");
  for (const statement of sourceFile.statements) {
    if (ts.isExpressionStatement(statement) && ts.isCallExpression(statement.expression) && plan.setupCalls?.has(statement.expression.expression.getText(sourceFile))) {
      output += '\n' + statement.getText(sourceFile) + '\n';
      continue;
    }
    if (ts.isVariableStatement(statement) && statement.declarationList.declarations.some(declaration => plan.helpers?.has(declaration.name.getText(sourceFile)))) {
      output += '\n' + statement.getText(sourceFile) + '\n';
      continue;
    }
    if (ts.isImportDeclaration(statement)) {
      if (plan.imports) continue;
      let text = statement
        .getText(sourceFile)
        .replace('"../../cookies"', '"better-auth/cookies"')
        .replace('"./password"', '"../harness/password.js"')
        .replace(
          '"../../test-utils/test-instance"',
          '"../harness/test-instance.js"',
        )
        .replace('"../../plugins/admin/admin"', '"../harness/plugins.js"');
      output += text + "\n";
      continue;
    }
    if (plan.includeHelpers && !ts.isExpressionStatement(statement)) {
      output += '\n' + statement.getText(sourceFile) + '\n';
      continue;
    }
    if (
      !ts.isExpressionStatement(statement) ||
      !ts.isCallExpression(statement.expression)
    )
      continue;
    const call = statement.expression;
    let rootExpression = call.expression;
    while (ts.isCallExpression(rootExpression)) rootExpression = rootExpression.expression;
    if (!/^(describe|suite)(\.|$)/.test(rootExpression.getText(sourceFile))) continue;
    const name = call.arguments[0].text;
    const callback = call.arguments[1];
    const selected = plan.suites === null || plan.suites.has(name);
    const removals = [];
    function collect(node, path = [name]) {
      if (ts.isCallExpression(node)) {
        let expression = node.expression;
        while (ts.isCallExpression(expression))
          expression = expression.expression;
        const callee = expression.getText(sourceFile);
        const callbacks = node.arguments.filter(
          (arg) => ts.isArrowFunction(arg) || ts.isFunctionExpression(arg),
        );
        if (/^(describe|suite)(\.|$)/.test(callee) && callbacks.length) {
          const title =
            node.arguments[0]?.text ??
            node.arguments[0]?.getText(sourceFile) ??
            "<dynamic>";
          for (const fn of callbacks) collect(fn.body, [...path, title]);
          return;
        }
        if (
          testNames.has(callee.split('.')[0]) &&
          (callbacks.length || callee.endsWith(".todo"))
        ) {
          const title =
            node.arguments[0]?.text ??
            node.arguments[0]?.getText(sourceFile) ??
            "<dynamic>";
          const include = selected && !plan.skippedTests?.has(title);
          inventory.push({
            suite: name,
            suites: path,
            test: title,
            selected: include,
            ...(plan.testSurfaces?.[name] ? {executionSurface: plan.testSurfaces[name]} : {}),
            upstreamDisabled: /\.(skip|todo|fails)(\.|$)/.test(callee),
            reason: include
              ? null
              : (plan.unportedReasons?.[name] ?? "Unported: requires session cache, secondary-storage/hooks, adapter introspection, or plugin integration"),
          });
          if (selected && !include)
            removals.push([node.getFullStart(), node.end]);
          return;
        }
      }
      ts.forEachChild(node, (child) => collect(child, path));
    }
    collect(callback.body);
    if (selected) {
      const start = statement.getStart(sourceFile);
      let text = source.slice(start, statement.end);
      const edits = removals.map(([from, to]) => [from, to, '']);
      function remapDynamicImport(node) {
        if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          const specifier = node.arguments[0];
          if (specifier && ts.isStringLiteral(specifier) && plan.dynamicImports?.[specifier.text]
            && !removals.some(([from, to]) => specifier.pos >= from && specifier.end <= to)) {
            edits.push([specifier.getStart(sourceFile), specifier.end, JSON.stringify(plan.dynamicImports[specifier.text])]);
          }
        }
        ts.forEachChild(node, remapDynamicImport);
      }
      remapDynamicImport(statement);
      for (const [from, to, replacement] of edits.sort((a, b) => b[0] - a[0]))
        text = text.slice(0, from - start) + replacement + text.slice(to - start);
      output += "\n" + text + "\n";
    }
  }
  mkdirSync("tests/upstream/sources", { recursive: true });
  writeFileSync(`tests/upstream/sources/${plan.file}.test.ts.txt`, source);
  writeFileSync(`tests/upstream/${plan.file}.test.ts`, output);
  const manifest =
    plan.file === "sign-in" ? "manifest.json" : `${plan.file}.manifest.json`;
  writeFileSync(
    `tests/upstream/${manifest}`,
    JSON.stringify(
      {
        repository: "https://github.com/better-auth/better-auth",
        commit,
        packageVersion: "1.7.15",
        path: relativePath,
        sha256: createHash("sha256").update(source).digest("hex"),
        changes:
          "Import paths and fixture only; suite selections recorded below; selected test bodies and assertions unchanged",
        tests: inventory,
      },
      null,
      2,
    ) + "\n",
  );
  console.log(
    `${plan.file}: ${inventory.filter((test) => test.selected).length} selected declarations, ${inventory.filter((test) => !test.selected).length} unported. Parameterized declarations may run multiple cases.`,
  );
}
