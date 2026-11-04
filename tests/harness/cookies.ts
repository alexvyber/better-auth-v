import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export const SECURE_COOKIE_PREFIX = '__Secure-';
export const HOST_COOKIE_PREFIX = '__Host-';
type CookieAttributes = {value: string; expires?: Date; [key: string]: unknown};

// Only translate native results into platform objects; parsing, selection and
// serialization are performed by V. Dates/NaN use explicit JSON wire markers.
function revive(_key: string, value: any): any {
  if (value && typeof value === 'object' && '$date' in value) return new Date(value.$date ?? NaN);
  if (value && typeof value === 'object' && '$nan' in value) return NaN;
  return value;
}
function wire(value: any): any {
  if (value instanceof Date) return {$date: Number.isNaN(+value) ? null : +value};
  if (typeof value === 'number' && Number.isNaN(value)) return {$nan: true};
  if (Array.isArray(value)) return value.map(wire);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, wire(v)]));
  return value;
}
function native<T>(input: Record<string, unknown>): T {
  const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--cookies'], {
    input: JSON.stringify(wire(input)) + '\n', encoding: 'utf8',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim());
  return JSON.parse(result.stdout, revive) as T;
}
export const parseCookies = (header: string) => new Map(native<[string, string][]>({op: 'parse', header}));
export const parseSetCookieHeader = (header: string) => new Map(native<[string, CookieAttributes][]>({op: 'parse-set', header}));
export const stripSecureCookiePrefix = (name: string) => native<string>({op: 'strip', name});
export const toCookieOptions = (attributes: CookieAttributes) => native<Record<string, unknown>>({op: 'options', attributes});
export function setRequestCookie(headers: Headers, name: string, value: string): void {
  headers.set('cookie', native<string>({op: 'set-request', header: headers.get('cookie') ?? '', name, value}));
}
export function applySetCookies(headers: Headers, values: Iterable<string>): void {
  headers.set('cookie', native<string>({op: 'apply', header: headers.get('cookie') ?? '', values: [...values]}));
}
export function getSessionCookie(request: Request | Headers, config?: {cookiePrefix?: string; cookieName?: string; path?: string}): string | null {
  const headers = request instanceof Headers || !('headers' in request) ? request : request.headers;
  return native({op: 'session', header: headers.get('cookie') ?? '', prefix: config?.cookiePrefix ?? 'better-auth', name: config?.cookieName ?? 'session_token'});
}
export function getChunkedCookie(ctx: {headers?: Headers; getCookie(name: string): string | undefined | null}, name: string): string | null {
  return native({op: 'chunks', header: ctx.headers?.get('cookie') ?? '', name, value: ctx.getCookie(name)});
}
export function expireCookie(ctx: {responseHeaders?: Headers; context?: {responseHeaders?: Headers}; setCookie(name: string, value: string, attributes: any): unknown}, cookie: {name: string; attributes: Record<string, unknown>}): void {
  const targets = new Set([ctx.responseHeaders, ctx.context?.responseHeaders]);
  for (const headers of targets) {
    if (!headers) continue;
    const values = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [headers.get('set-cookie') ?? ''];
    const kept = native<string[]>({op: 'remove', name: cookie.name, values});
    headers.delete('set-cookie');
    for (const entry of kept) headers.append('set-cookie', entry);
  }
  ctx.setCookie(cookie.name, '', native({op: 'expire-options', attributes: cookie.attributes}));
}
