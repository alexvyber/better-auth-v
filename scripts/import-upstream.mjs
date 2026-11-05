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
 {file:'oauth-link-policy',path:'packages/better-auth/src/oauth2/link-account.test.ts',
 suites:new Set(['oauth2 - email verification on link','oauth2 - account linking without trustedProviders','oauth2 - disableImplicitLinking','oauth2 - accountLinking.requireLocalEmailVerified: false opt-out']),
 includeHelpers:true,setupCalls:new Set(['beforeAll','afterEach','afterAll']),
 skippedTests:new Set(['should allow explicit linkSocial when disableImplicitLinking is true']),
 imports:'import type { GoogleProfile } from "@better-auth/core/social-providers";\nimport type { User } from "better-auth";\nimport { HttpResponse, http } from "msw";\nimport { setupServer } from "msw/node";\nimport { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";\nimport { signJWT } from "../harness/crypto.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { DEFAULT_SECRET } from "../harness/constants.js";\n',
 unportedReason:'Unported explicit linking, remaining provider policies, account identity/security/schema cases; implicit-link policy suites selected',
 },
 {file:'oauth-profile-input',path:'packages/better-auth/src/oauth2/link-account.test.ts',
 suites:new Set(['oauth2 - updateUserInfoOnLink on implicit sign-in link','oauth2 - first sign-in provisioning applies user input rules']),
 includeHelpers:true,setupCalls:new Set(['beforeAll','afterEach','afterAll']),
 imports:'import type { GoogleProfile } from "@better-auth/core/social-providers";\nimport type { User } from "better-auth";\nimport { HttpResponse, http } from "msw";\nimport { setupServer } from "msw/node";\nimport { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";\nimport * as z from "zod";\nimport { signJWT } from "../harness/crypto.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { DEFAULT_SECRET } from "../harness/constants.js";\n',
 unportedReason:'Unported explicit account linking, remaining provider binding/security/schema scenarios; implicit profile sync and provider input rules are selected',
 },
 ...['attempt-cap', 'account-lockout', 'security'].map(kind => ({
 file:'two-factor-'+kind, path:'packages/better-auth/src/plugins/two-factor/two-factor.'+kind+'.test.ts',
 suites: kind === 'security' ? new Set([
 'two-factor security: sign-in does not leak session cookies (cookieCache disabled)',
 'two-factor security: chunked session_data is fully scrubbed on 2FA-required sign-in',
 'two-factor security: 2FA challenge is single-use and expiry-bounded',
 'two-factor security: OTP attempts are atomic under concurrency']) : null,
 includeHelpers: kind !== 'account-lockout', helpers: kind === 'account-lockout' ? new Set(['setup']) : undefined,
 skippedTests: kind === 'attempt-cap' ? new Set(['a server error during verification does not spend an attempt slot']) : kind === 'account-lockout' ? new Set([
 'enforces account lockout through legacy adapter fallbacks', 'consumes an email OTP once through legacy adapter fallbacks',
 'allows a backup code to be consumed once through legacy adapter fallbacks', 'sets the lock with a guarded counter transition']) : undefined,
 imports: 'import type { BetterAuthOptions, GenericEndpointContext } from "@better-auth/core";\nimport type { SecondaryStorage } from "@better-auth/core/db";\nimport { createOTP } from "@better-auth/utils/otp";\nimport { describe, expect, it } from "vitest";\nimport { symmetricDecrypt } from "better-auth/crypto";\nimport { convertSetCookieToCookie } from "../harness/two-factor.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport type { User, Session, Verification } from "better-auth";\nimport { DEFAULT_SECRET } from "../harness/constants.js";\nimport { TWO_FACTOR_ERROR_CODES } from "better-auth/plugins/two-factor";\nimport type { TwoFactorOptions, TwoFactorTable, UserWithTwoFactor } from "better-auth/plugins/two-factor";\nimport { twoFactor } from "../harness/plugins.js";\nconst DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS = 5;\n',
 unportedReason: 'Unported legacy JS adapter injection, username/phone entry points and JS middleware newSession probes',
 })),
 {file:'two-factor', path:'packages/better-auth/src/plugins/two-factor/two-factor.test.ts', suites:null,
 imports: 'import { APIError, BASE_ERROR_CODES } from "@better-auth/core/error";\nimport { base32 } from "@better-auth/utils/base32";\nimport { createOTP } from "@better-auth/utils/otp";\nimport { describe, expect, it, vi } from "vitest";\nimport { createAuthClient } from "better-auth/client";\nimport { applySetCookies, parseSetCookieHeader } from "../harness/cookies.js";\nimport { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";\nimport { convertSetCookieToCookie } from "../harness/two-factor.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { DEFAULT_SECRET } from "../harness/constants.js";\nimport { anonymous, twoFactor, magicLink } from "../harness/plugins.js";\nimport { TWO_FACTOR_ERROR_CODES } from "better-auth/plugins/two-factor";\nimport { twoFactorClient } from "better-auth/client/plugins";\nimport type {TwoFactorTable,UserWithTwoFactor} from "../harness/two-factor.js";\n',
 },
 {file: 'postgres-sign-in', source_file: 'sign-in', suites: null, executionSurface: 'native-postgres-uuid-mapped-physical-schema',
 imports: 'import { APIError, BASE_ERROR_CODES } from "@better-auth/core/error";\nimport { describe, expect, it, vi } from "vitest";\nimport { parseSetCookieHeader } from "better-auth/cookies";\nimport { getTestInstance } from "../harness/postgres-fixture.js";\n',
 },
 {file: 'postgres-sign-up', source_file: 'sign-up', suites: null, executionSurface: 'native-postgres-uuid-mapped-physical-schema',
 imports: 'import { BASE_ERROR_CODES } from "@better-auth/core/error";\nimport { afterEach, describe, expect, it, vi } from "vitest";\nimport { admin } from "../harness/plugins.js";\nimport { getTestInstance } from "../harness/postgres-fixture.js";\n',
 },
 {file: 'id-field', path: 'packages/core/src/db/adapter/get-id-field.test.ts', suites: null, includeHelpers: true,
 imports: 'import { describe, expect, it, vi } from "vitest";\nimport { logger } from "@better-auth/core/env";\nimport type { BetterAuthOptions } from "@better-auth/core";\nimport type { BetterAuthDBSchema } from "@better-auth/core/db";\nimport { encodeDeterministicId, initGetIdField } from "../harness/id-field.js";\n',
 },
 {file: 'rate-limiter', path: 'packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts', suites: new Set(['rate-limiter', 'atomic concurrent enforcement', 'should work with custom rules']),
 imports: 'import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";\nimport { getTestInstance } from "../harness/test-instance.js";\n',
 unportedReason: 'Unported pruning hooks, dynamic/custom/secondary limit storage, IP normalization/proxy policy, and environment defaults; basic memory/database enforcement and static rules selected',
 },
 {file: 'redis-storage', path: 'packages/redis-storage/test/redis-storage.test.ts', suites: null,
 imports: 'import { describe, expect, it, vi } from "vitest";\nimport { redisStorage } from "../harness/redis-storage.js";\n',
 },
 {file: 'generic-oauth', path: 'packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts', suites: new Set(['oauth2']), nestedSuites: new Set(['id_token verification']),
 includeTests: new Set(['should not create user when sign ups are disabled', 'should create user when sign ups are disabled and sign up is requested', 'skips discovery missing %s endpoints', 'keeps explicit token exchange with incomplete discovery (custom=%s)', 'does not take down the auth API when one provider’s discovery is unreachable'.replace('’', "'"), 'should merge client-requested scopes with config scopes']),
 imports: 'import { createServer } from "node:http";\nimport type { AddressInfo } from "node:net";\nimport type { GenericEndpointContext } from "@better-auth/core";\nimport { runWithEndpointContext } from "@better-auth/core/context";\nimport { betterFetch } from "@better-fetch/fetch";\nimport { generateKeyPair, SignJWT } from "jose";\nimport { HttpResponse, http } from "msw";\nimport { setupServer } from "msw/node";\nimport { OAuth2Server } from "oauth2-mock-server";\nimport { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";\nimport { createAuthClient } from "better-auth/client";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { genericOAuth } from "../harness/plugins.js";\n',
 unportedReason: 'Unported generic provider helpers, refresh/linking/popup/retry/options and dynamic-baseURL integration; ID-token verification suite selected',
 },
 {file: 'anonymous', path: 'packages/better-auth/src/plugins/anonymous/anon.test.ts', suites: new Set(['anonymous', 'anonymous linking through generic oauth (Expo)']), includeHelpers: true, setupCalls: new Set(['beforeAll', 'afterEach', 'afterAll']),
 skippedSuites: new Set(['anonymous cleanup safeguards']),
 imports: 'import type { GoogleProfile } from "@better-auth/core/social-providers";\nimport { betterFetch } from "@better-fetch/fetch";\nimport { HttpResponse, http } from "msw";\nimport { setupServer } from "msw/node";\nimport { beforeAll, afterAll, afterEach, describe, expect, it, vi } from "vitest";\nimport { signJWT } from "../harness/crypto.js";\nimport { DEFAULT_SECRET } from "../harness/constants.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { anonymous, genericOAuth } from "../harness/plugins.js";\nimport { OAuth2Server } from "oauth2-mock-server";\nimport { anonymousClient } from "better-auth/client/plugins";\n',
 unportedReason: 'Unported direct middleware-object injection; all HTTP anonymous and OAuth integration cases selected',
 },
  {file: 'email-otp', path: 'packages/better-auth/src/plugins/email-otp/email-otp.test.ts', suites: null,
   imports: 'import { afterEach, describe, expect, it, vi } from "vitest";\nimport { createAuthClient } from "better-auth/client";\nimport { getCookieCache, parseSetCookieHeader } from "../harness/cookies.js";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { bearer, emailOTP } from "../harness/plugins.js";\nimport { emailOTPClient } from "better-auth/client/plugins";\nimport { splitAtLastColon } from "../harness/crypto.js";\n',
  },
  {file: 'internal-adapter', path: 'packages/better-auth/src/db/internal-adapter.test.ts', suites: new Set(), extractSuites: ['consumeVerificationValue', 'reserveVerificationValue'], includeHelpers: true,
   skippedTests: new Set(['keeps reserving when ids are database-generated numbers']),
   imports: 'import { describe, expect, it, vi } from "vitest";\nimport type { SecondaryStorage } from "@better-auth/core/db";\nimport { DatabaseSync, init, getMigrations } from "../harness/verification-fixture.js";\nimport type { BetterAuthOptions } from "../harness/verification-fixture.js";\n',
   unportedReason: 'Unported adapter/session/schema and ID strategies; consume and default-ID reservation suites are selected',
  },
  {file: 'one-time-token', path: 'packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts', suites: null,
   imports: 'import { afterEach, describe, expect, it, vi } from "vitest";\nimport { getTestInstance } from "../harness/test-instance.js";\nimport { isAPIError } from "@better-auth/core/utils/is-api-error";\nimport { oneTimeToken } from "../harness/plugins.js";\nimport { oneTimeTokenClient } from "better-auth/client/plugins";\nimport { defaultKeyHasher } from "../harness/crypto.js";\n',
  },
  {file: 'oauth-client-assertion', path: 'packages/core/src/oauth2/client-assertion.test.ts', suites: null,
   imports: 'import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from "jose";\nimport { describe, expect, it } from "vitest";\nimport { createPrivateKeyJwtClientAssertionGetter, signPrivateKeyJwtClientAssertion } from "../harness/oauth-token.js";\n',
  },
  {file: 'oauth-private-key-auth', path: 'packages/core/src/oauth2/private-key-jwt-authentication.test.ts', suites: null, includeHelpers: true, setupCalls: new Set(['vi.mock']),
   imports: 'import { base64 } from "@better-auth/utils/base64";\nimport { decodeJwt, exportJWK, generateKeyPair } from "jose";\nimport { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";\nimport { betterFetch } from "@better-fetch/fetch";\nimport { CLIENT_ASSERTION_TYPE, createPrivateKeyJwtClientAssertionGetter, clientCredentialsToken, refreshAccessToken, authorizationCodeRequest, validateAuthorizationCode } from "../harness/oauth-token.js";\n',
  },
  {file: 'oauth-refresh', path: 'packages/core/src/oauth2/refresh-access-token.test.ts', suites: null, includeHelpers: true, setupCalls: new Set(['vi.mock']),
   imports: 'import { beforeEach, describe, expect, it, vi } from "vitest";\nimport { betterFetch } from "@better-fetch/fetch";\nimport { refreshAccessToken, mergeScopes, parseScopeField } from "../harness/oauth-token.js";\n',
  },
  {file: 'social', path: 'packages/better-auth/src/social.test.ts', suites: new Set(['Google Provider - includeGrantedScopes']),
   imports: 'import { describe, expect, it } from "vitest";\nimport { getTestInstance } from "../harness/test-instance.js";\n',
   unportedReason: 'Remaining social-provider, callback, account-linking, refresh, adapter and profile contracts are not yet implemented',
  },
  {file: 'oauth-basic-credentials', path: 'packages/core/src/oauth2/basic-credentials.test.ts', suites: null,
   imports: 'import { describe, expect, it } from "vitest";\nimport { encodeBasicCredentials, decodeBasicCredentials } from "../harness/oauth-helpers.js";\n',
  },
  {file: 'oauth-authorization-url', path: 'packages/core/src/oauth2/create-authorization-url.test.ts', suites: null, includeHelpers: true,
   imports: 'import { describe, expect, it } from "vitest";\nimport { createAuthorizationURL, RESERVED_AUTHORIZATION_PARAMS } from "../harness/oauth-helpers.js";\n',
  },
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
plans.push({file:'admin',helpers:new Set(['server','handlers','testIdToken']),setupCalls:new Set(['beforeAll','afterEach','afterAll']),path:'packages/better-auth/src/plugins/admin/admin.test.ts',
 suites:new Set(['Admin plugin','access control','Admin plugin id-token sign-in','admin createUser validateUserInfo provisioning gate','admin create-user password length']),
 skippedTests:new Set([
 'should throw error when assigning non-existent admin roles','should validate on the client',
 ]),
 unportedReason:'Generic endpoint hooks/cache probes, numeric-ID/username and constructor/client-only source cases remain unported',
 imports:`import type {BetterAuthPlugin} from '@better-auth/core';
import type {UserWithRole} from 'better-auth/plugins/admin';
import {BetterAuthError} from '@better-auth/core/error';
import {createAccessControl} from 'better-auth/plugins/access';
import {ADMIN_ERROR_CODES} from 'better-auth/client/plugins';
import {createAuthMiddleware} from 'better-auth/api';
import {getSessionFromCtx} from '../harness/session.js';
import type {GoogleProfile} from '@better-auth/core/social-providers';
import {exportJWK,generateKeyPair,SignJWT} from 'jose';
import {HttpResponse,http} from 'msw';
import {setupServer} from 'msw/node';
import {beforeAll,afterAll,afterEach,describe,it,expect,vi} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';
import {admin} from '../harness/plugins.js';
import {createAuthClient} from 'better-auth/client';
import {adminClient} from 'better-auth/client/plugins';
import {signJWT} from '../harness/crypto.js';
import {DEFAULT_SECRET} from '../harness/constants.js';
`});
const adminPlan=plans.find(plan=>plan.file==='admin');
adminPlan.imports=adminPlan.imports.replace('../harness/test-instance.js','../harness/admin-fixture.js');
for(const [prefix,fixture,surface] of [['postgres','postgres-fixture','native-postgres-uuid-mapped-physical-schema'],['mongo','mongo-fixture','native-mongodb-objectid-replica-set']]) {
 plans.push({...adminPlan,file:prefix+'-admin',imports:adminPlan.imports.replace('../harness/admin-fixture.js','../harness/admin-'+fixture+'.js'),executionSurface:surface});
}
const organizationCRUD={file:'organization-crud',path:'packages/better-auth/src/plugins/organization/routes/crud-org.test.ts',
 suites:new Set(['get-full-organization','get-organization','organization hooks','updateOrganization']),
 skippedTests:new Set(['should apply beforeCreateTeam hook','should apply afterCreateTeam hook','should allow passing id through `beforeCreateTeam`']),
 executionSurface:'native-api-upstream-test-origin-defaults',
 unportedReason:'Invitation and team integration cases remain for subsequent batches',
 imports:`import {describe,expect,it,vi} from 'vitest';
import type {APIError} from 'better-auth/api';
import {createAccessControl} from 'better-auth/plugins/access';
import {adminAc,defaultStatements,memberAc,ownerAc} from 'better-auth/plugins/organization/access';
import {createAuthClient} from 'better-auth/client';
import {organizationClient,ORGANIZATION_ERROR_CODES} from 'better-auth/client/plugins';
import {getTestInstance} from '../harness/organization-fixture.js';
import {organization} from '../harness/plugins.js';
`};
const organizationInvitations={file:'organization-invitations',path:'packages/better-auth/src/plugins/organization/routes/crud-invites.test.ts',
 suites:new Set(['organization invitation recipient ownership gates']),
 skippedTests:new Set(['requires verified email for invitation ID calls when the database owns IDs','accepts an invitation by ID with database-owned IDs when verification is explicitly disabled']),
 executionSurface:'native-api-upstream-test-origin-defaults',unportedReason:'Database-owned numeric ID generation and organization teams remain unported',
 imports:`import type {BetterAuthOptions,GenerateIdFn} from '@better-auth/core';
import type {OrganizationOptions} from 'better-auth/plugins/organization';
import {describe,expect,it} from 'vitest';
import {organizationClient} from 'better-auth/client/plugins';
import {organization} from '../harness/plugins.js';
import {getTestInstance} from '../harness/organization-fixture.js';
`};
const dynamicRoles={file:'organization-dynamic-roles',path:'packages/better-auth/src/plugins/organization/routes/crud-access-control.test.ts',
 suites:new Set(['dynamic access control']),skippedTests:new Set(['should preserve exact built-in organization role statement types']),
 executionSurface:'native-api-upstream-test-origin-defaults',unportedReason:'Pure TypeScript statement type probe is not a native runtime test',
 imports:`import type {DBFieldAttribute} from '@better-auth/core/db';
import {describe,expect,expectTypeOf,it} from 'vitest';
import {createAuthClient} from 'better-auth/client';
import {parseSetCookieHeader} from 'better-auth/cookies';
import {createAccessControl} from 'better-auth/plugins/access';
import {adminAc,defaultStatements,memberAc,ownerAc} from 'better-auth/plugins/organization/access';
import {inferOrgAdditionalFields,organizationClient,ORGANIZATION_ERROR_CODES} from 'better-auth/client/plugins';
import {organization} from '../harness/plugins.js';
import {getTestInstance} from '../harness/organization-fixture.js';
`};
plans.push(dynamicRoles);
for(const [prefix,fixture] of [['postgres','postgres-fixture'],['mongo','mongo-fixture']]){
 plans.push({...dynamicRoles,file:prefix+'-organization-dynamic-roles',imports:dynamicRoles.imports.replace('../harness/organization-fixture.js','../harness/organization-'+fixture+'.js'),executionSurface:'native-'+prefix+'-dynamic-organization-roles'});
}
plans.push(organizationInvitations);
const invitationLifecycle={file:'organization-invitation-lifecycle',path:'packages/better-auth/src/plugins/organization/organization.test.ts',
 suites:new Set(['invitation expiration and filtering','invitation limit','cancel pending invitations on re-invite','re-invite without cancelPendingInvitationsOnReInvite still throws','resend invitation should reuse existing','dynamic access control should merge DB permissions with built-in roles']),

 executionSurface:'native-api-upstream-test-origin-defaults',unportedReason:'Remaining organization suites and dynamic invitation limits remain unported',
 imports:`import {describe,expect,it,vi} from 'vitest';
import type {APIError} from 'better-auth/api';
import {createAccessControl} from 'better-auth/plugins/access';
import {adminAc,defaultStatements,memberAc,ownerAc} from 'better-auth/plugins/organization/access';
import {createAuthClient} from 'better-auth/client';
import {organizationClient,ORGANIZATION_ERROR_CODES} from 'better-auth/client/plugins';
import {organization} from '../harness/plugins.js';
import {getTestInstance} from '../harness/organization-fixture.js';
`};
plans.push(invitationLifecycle);
for(const [prefix,fixture,surface] of [['postgres','postgres-fixture','native-postgres-uuid-mapped-physical-schema'],['mongo','mongo-fixture','native-mongodb-objectid-replica-set']]){
 for(const plan of [organizationInvitations,invitationLifecycle]){
  // Non-UUID custom generator source case uses the explicit text-ID fixture.
  const fixturePath=prefix==='postgres'?'../harness/organization-postgres-text-fixture.js':'../harness/organization-'+fixture+'.js';
  plans.push({...plan,file:prefix+'-'+plan.file,imports:plan.imports.replace('../harness/organization-fixture.js',fixturePath),executionSurface:surface});
 }
}

plans.push(organizationCRUD);
for(const [prefix,fixture,surface] of [['postgres','postgres-fixture','native-postgres-uuid-mapped-physical-schema'],['mongo','mongo-fixture','native-mongodb-objectid-replica-set']]){plans.push({...organizationCRUD,file:prefix+'-organization-crud',imports:organizationCRUD.imports.replace('../harness/organization-fixture.js','../harness/organization-'+fixture+'.js'),executionSurface:surface})}
const policy = plans.find(plan => plan.file === 'oauth-link-policy');
plans.push({...policy,file:'postgres-oauth-link-policy',imports:policy.imports.replace('../harness/test-instance.js','../harness/postgres-text-fixture.js'),executionSurface:'native-postgres-text-id-mapped-physical-schema'});
const attemptPlan = plans.find(plan => plan.file === 'two-factor-attempt-cap');
plans.push({...attemptPlan, file: 'two-factor-attempt-server-error',
 suites: new Set(['two-factor security: TOTP enforces a per-challenge attempt cap']),
 skippedTests: undefined, nestedSuites: new Set(),
 includeTests: new Set(['a server error during verification does not spend an attempt slot']),
 executionSurface: 'native-isolated-account-server-error',
 unportedReason: 'Other attempt cases run separately; serialized bridge exhausts shared account budget in the original suite ordering'});
// Repeat intact assertions over native PostgreSQL; these copies do not expand the unique corpus.
for (const name of ['one-time-token', 'email-otp', 'password-reset', 'session-api', 'two-factor', 'two-factor-account-lockout', 'two-factor-security', 'two-factor-attempt-cap', 'two-factor-attempt-server-error', 'oauth-profile-input']) {
 const original = plans.find(plan => plan.file === name);
 plans.push({...original, file: 'postgres-' + name, source_file: original.source_file ?? name,
  ...(name === 'session-api' ? {suites: new Set(['session'])} : {}),
  imports: original.imports.replace('../harness/test-instance.js', '../harness/postgres-fixture.js'),
  executionSurface: 'native-postgres-uuid-mapped-physical-schema'});
}
// The same selected source cases run against a native MongoDB replica set.
for (const name of ['sign-in','sign-up','session-api','one-time-token','email-otp','password-reset','two-factor']) {
 const reference = plans.find(plan => plan.file === 'postgres-' + name);
 plans.push({...reference, file:'mongo-'+name,
  imports: reference.imports.replace('../harness/postgres-fixture.js','../harness/mongo-fixture.js'),
  executionSurface:'native-mongodb-objectid-replica-set'});
}
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
    if (ts.isFunctionDeclaration(statement) && statement.name && plan.helpers?.has(statement.name.text)) {
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
    const extractedSuites = plan.extractSuites ?? (plan.extractSuite ? [plan.extractSuite] : []);
    const extractions = [];
    const selected = !extractedSuites.length && (plan.suites === null || plan.suites.has(name));
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
          if (extractedSuites.includes(title)) extractions.push(node);
          for (const fn of callbacks) collect(fn.body, [...path, title]);
          if ((plan.skippedSuites?.has(title) && (selected || path.some(title => extractedSuites.includes(title)))) || (selected && plan.nestedSuites && !plan.nestedSuites.has(title) && !path.some(title => plan.nestedSuites.has(title)))) removals.push([node.getFullStart(), node.end]);
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
          const include = (extractedSuites.length ? path.some(title => extractedSuites.includes(title)) : selected) && !plan.skippedTests?.has(title) && !path.some(title => plan.skippedSuites?.has(title)) && (!plan.nestedSuites || path.some(title => plan.nestedSuites.has(title)) || plan.includeTests?.has(title));
          inventory.push({
            suite: name,
            suites: path,
            test: title,
            selected: include,
            ...(plan.executionSurface || plan.testSurfaces?.[name] ? {executionSurface: plan.executionSurface ?? plan.testSurfaces[name]} : {}),
            upstreamDisabled: /\.(skip|todo|fails)(\.|$)/.test(callee),
            reason: include
              ? null
              : (plan.unportedReasons?.[name] ?? plan.unportedReason ?? "Unported: requires session cache, secondary-storage/hooks, adapter introspection, or plugin integration"),
          });
          if ((selected || path.some(title => extractedSuites.includes(title))) && !include && !path.some(title => plan.skippedSuites?.has(title)))
            removals.push([node.getFullStart(), node.end]);
          return;
        }
      }
      ts.forEachChild(node, (child) => collect(child, path));
    }
    collect(callback.body);
    const normalizedRemovals = removals.filter(([from, to]) => !removals.some(([outerFrom, outerTo]) => outerFrom <= from && outerTo >= to && (outerFrom < from || outerTo > to)));
    for (const node of extractions) {
      const start = node.getStart(sourceFile);
      let text = node.getText(sourceFile);
      for (const [from, to] of normalizedRemovals.filter(([from, to]) => from >= start && to <= node.end).sort((a, b) => b[0] - a[0])) text = text.slice(0, from - start) + text.slice(to - start);
      output += '\n' + text + ';\n';
    }
    if (selected) {
      const start = statement.getStart(sourceFile);
      let text = source.slice(start, statement.end);
      const edits = normalizedRemovals.map(([from, to]) => [from, to, '']);
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
