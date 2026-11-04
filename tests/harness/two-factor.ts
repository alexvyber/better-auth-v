import {applySetCookies} from './cookies.js';
export function convertSetCookieToCookie(headers: Headers): Headers {
 const values = headers.getSetCookie();
 if (values.length) applySetCookies(headers, values);
 return headers;
}
export type TwoFactorTable = {id:string;userId:string;secret:string;backupCodes:string;verified:boolean;failedVerificationCount?:number;lockedUntil?:Date|null};
export type UserWithTwoFactor = {id:string;email:string;twoFactorEnabled:boolean};
