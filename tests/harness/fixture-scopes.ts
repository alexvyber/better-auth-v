import {AsyncLocalStorage} from "node:async_hooks";

export const nativeTransactionScope = new AsyncLocalStorage<boolean>();
export const currentUserHeaders = new AsyncLocalStorage<Headers>();
export const currentOperation = new AsyncLocalStorage<{ transactionError?: unknown; storeFailure?: unknown; request?: Request }>();
export function safeCloneRequest(request?: Request): Request | undefined {
  if (!request) return undefined;
  try { return request.clone(); }
  catch { return new Request(request.url, {method: request.method, headers: request.headers}); }
}
