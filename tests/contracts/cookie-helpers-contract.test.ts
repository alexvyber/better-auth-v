import {describe, expect, it} from 'vitest';
import * as reference from 'better-auth/cookies';
import {applySetCookies, getSessionCookie, parseCookies, parseSetCookieHeader, setRequestCookie, toCookieOptions} from '../harness/cookies.js';

describe('native cookie helper interoperability', () => {
  it('matches reference decoding on malformed UTF-8 and percent escapes', () => {
    const header = 'a=%20%FF;b=%C0%AF;c=%E2%82%AC;d=%;e=%GG;f=hello+world;g=%00%0A;h="quoted";2=two;1=one;a=last';
    expect([...parseCookies(header)]).toEqual([...reference.parseCookies(header)]);
    const actual = new Headers({cookie: header});
    const expected = new Headers({cookie: header});
    setRequestCookie(actual, 'value', 'literal%20+€;=');
    reference.setRequestCookie(expected, 'value', 'literal%20+€;=');
    expect(actual.get('cookie')).toBe(expected.get('cookie'));
  });

  it('preserves attribute dates, NaN and insertion order across the native boundary', () => {
    const header = '2=second; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=+123junk; Priority=High, 1=first; Max-Age=invalid; Expires=invalid';
    const actual = parseSetCookieHeader(header);
    const expected = reference.parseSetCookieHeader(header);
    expect([...actual]).toEqual([...expected]);
    expect(toCookieOptions(actual.get('2')!)).toEqual(reference.toCookieOptions(expected.get('2')!));
    expect(toCookieOptions(actual.get('1')!)).toEqual(reference.toCookieOptions(expected.get('1')!));
  });

  it('normalizes semantic values without treating a proxy merge as a browser cookie jar', () => {
    const actual = new Headers({cookie: '2=two; 1=one; stale=keep'});
    const expected = new Headers(actual);
    const values = ['stale=; Max-Age=0; Path=/other', '2=replace; Expires=Wed, 21 Oct 2015 07:28:00 GMT, next=%E2%82%AC%3B'];
    applySetCookies(actual, values);
    reference.applySetCookies(expected, values);
    expect(actual.get('cookie')).toBe(expected.get('cookie'));
    expect([...parseCookies(actual.get('cookie')!)]).toEqual([...reference.parseCookies(expected.get('cookie')!)]);
  });

  it('keeps secure empty values distinct from absence while considering legacy separators', () => {
    const headers = new Headers({cookie: 'better-auth.session_token=stale; __Secure-better-auth.session_token=; better-auth-session_token=legacy'});
    expect(getSessionCookie(headers)).toBe(reference.getSessionCookie(headers));
    expect(getSessionCookie(headers)).toBe('legacy');
  });
});
