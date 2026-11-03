import type { GenericEndpointContext } from '@better-auth/core';
import type { Session, User } from 'better-auth';

interface NativeSessionBridge {
  nativeSession(endpoint: GenericEndpointContext, authoritative: boolean): Promise<{session: Session; user: User} | null>;
}

// These helpers only transport the upstream endpoint context to V. Strictness,
// cache validity, persistence, and emitted cookies are decided by V.
export function getSessionFromCtx(endpoint: GenericEndpointContext) {
  return (endpoint.context as unknown as NativeSessionBridge).nativeSession(endpoint, false);
}
export function getAuthoritativeSessionFromCtx(endpoint: GenericEndpointContext) {
  return (endpoint.context as unknown as NativeSessionBridge).nativeSession(endpoint, true);
}
