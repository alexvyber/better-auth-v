import { admin as upstreamAdmin, organization as upstreamOrganization } from 'better-auth/plugins';
export { jwt } from 'better-auth/plugins';

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
