import { genericOAuth as upstreamGenericOAuth, admin as upstreamAdmin, organization as upstreamOrganization, oneTimeToken as upstreamOneTimeToken, emailOTP as upstreamEmailOTP, anonymous as upstreamAnonymous, twoFactor as upstreamTwoFactor, magicLink as upstreamMagicLink } from 'better-auth/plugins';
export { jwt, bearer } from 'better-auth/plugins';

// Preserve constructor inputs so the fixture can reject unimplemented options.
// Upstream's admin descriptor does not expose its captured options.
const inputs = new WeakMap<object, Record<string, any>>();
export const admin = ((options?: Record<string, any>) => {
  const plugin = upstreamAdmin(options);
  inputs.set(plugin, options ?? {});
  return plugin;
}) as typeof upstreamAdmin;
export const organization = ((options?: Record<string, any>) => {
  const plugin = upstreamOrganization(options);
  inputs.set(plugin, options ?? {});
  return plugin;
}) as typeof upstreamOrganization;
export function schemaPluginOptions(plugin: object) { return inputs.get(plugin); }

export const genericOAuth = ((options: Parameters<typeof upstreamGenericOAuth>[0]) => {
  const plugin = upstreamGenericOAuth(options);
  inputs.set(plugin, options);
  return plugin;
}) as typeof upstreamGenericOAuth;

export const oneTimeToken = ((options?: Parameters<typeof upstreamOneTimeToken>[0]) => {
 const plugin = upstreamOneTimeToken(options);
 inputs.set(plugin, options ?? {});
 return plugin;
}) as typeof upstreamOneTimeToken;

export const emailOTP = ((options: Parameters<typeof upstreamEmailOTP>[0]) => {
 const plugin = upstreamEmailOTP(options); inputs.set(plugin, options); return plugin;
}) as typeof upstreamEmailOTP;

export const anonymous = ((options?: Parameters<typeof upstreamAnonymous>[0]) => {
 const plugin = upstreamAnonymous(options); inputs.set(plugin, options ?? {}); return plugin;
}) as typeof upstreamAnonymous;

export const twoFactor = ((options?: Parameters<typeof upstreamTwoFactor>[0]) => {
 const plugin = upstreamTwoFactor(options); inputs.set(plugin, options ?? {}); return plugin;
}) as typeof upstreamTwoFactor;

export const magicLink = ((options: Parameters<typeof upstreamMagicLink>[0]) => {
 const plugin = upstreamMagicLink(options); inputs.set(plugin, options); return plugin;
}) as typeof upstreamMagicLink;
