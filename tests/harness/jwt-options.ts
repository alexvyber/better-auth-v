import type {JwtOptions} from 'better-auth/plugins/jwt';

type Options = Record<string, any>;
function keys(value: Options, allowed: string[], path: string) {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Error(`Unported JWT option ${path}.${key}`);
}

// Configuration/Date representation only. Claims, key choice, and signing stay in V.
export function encodeJWTOptions(input?: JwtOptions) {
  const options = (input ?? {}) as Options;
  keys(options, ['jwks', 'jwt', 'adapter', 'sessionCookieCache', 'disableSettingJwtHeader'], 'options');
  const jwks = options.jwks ?? {};
  const jwt = options.jwt ?? {};
  keys(jwks, ['keyPairConfig', 'keyPairConfigs', 'remoteUrl', 'rotationInterval', 'gracePeriod', 'disablePrivateKeyEncryption', 'jwksPath'], 'jwks');
  keys(jwt, ['issuer', 'audience', 'expirationTime', 'sign', 'definePayload', 'getSubject'], 'jwt');
  keys(jwks.keyPairConfig ?? {}, ['alg', 'crv', 'modulusLength'], 'jwks.keyPairConfig');
  keys(options.adapter ?? {}, ['getJwks', 'createJwk'], 'adapter');
  for (const [name, fn] of Object.entries({...options.adapter, sign: jwt.sign, definePayload: jwt.definePayload, getSubject: jwt.getSubject})) {
    if (fn !== undefined && typeof fn !== 'function') throw new Error('Invalid JWT callback: ' + name);
  }
  const pair = jwks.keyPairConfig ?? {};
  return {
    options_json: JSON.stringify({
      algorithm: pair.alg ?? '', curve: pair.crv ?? '', modulus_length: pair.modulusLength ?? 2048,
      key_pair_configs: (jwks.keyPairConfigs ?? []).map((key: Options) => {
        keys(key, ['alg', 'crv', 'modulusLength'], 'jwks.keyPairConfigs');
        return {algorithm: key.alg, curve: key.crv ?? '', modulus_length: key.modulusLength ?? 2048};
      }),
      remote_url: jwks.remoteUrl ?? '', rotation_interval: jwks.rotationInterval ?? 0, grace_period: jwks.gracePeriod ?? 2592000,
      disable_private_key_encryption: jwks.disablePrivateKeyEncryption ?? false, jwks_path: jwks.jwksPath ?? '/jwks',
      session_cookie_cache: options.sessionCookieCache ?? false, disable_setting_jwt_header: options.disableSettingJwtHeader ?? false,
      issuer: jwt.issuer ?? null,
      audience: typeof jwt.audience === 'string' ? jwt.audience : null,
      audiences: Array.isArray(jwt.audience) ? jwt.audience : null,
    }),
    expiration_json: jwt.expirationTime === undefined ? '' : JSON.stringify(jwt.expirationTime instanceof Date ? {$jwtDateMillis: jwt.expirationTime.getTime()} : jwt.expirationTime),
  };
}
