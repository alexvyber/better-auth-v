import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {logger} from '@better-auth/core/env';
import type {BetterAuthOptions} from '@better-auth/core';
let nativeState: unknown = {};
function native(op: string, fields: Record<string, unknown> = {}) {
 const result = spawnSync(fileURLToPath(new URL('../../build/auth-bridge', import.meta.url)), ['--id-field'], {input: JSON.stringify({op, state: nativeState, ...fields}) + '\n', encoding: 'utf8'});
 if (result.error) throw result.error;
 if (result.status !== 0) throw new Error(result.stderr.trim());
 const reply = JSON.parse(result.stdout);
 nativeState = reply.state;
 for (const warning of reply.warnings) logger.warn(warning);
 return reply.defined ? reply.value : undefined;
}
function strategy(options: Pick<BetterAuthOptions, 'advanced'>): string {
 const configured = options.advanced?.database?.generateId;
 return typeof configured === 'function' ? 'function' : configured === false ? 'disabled' : configured ?? 'random';
}
export function encodeDeterministicId(digest: Uint8Array, options: Pick<BetterAuthOptions, 'advanced'>): string {
 return native('deterministic', {digest: [...digest], options: {strategy: strategy(options)}});
}
export function initGetIdField({options, schema, disableIdGeneration = false, customIdGenerator, supportsUUIDs = false}: {
 options: BetterAuthOptions;
 schema: Record<string, {modelName: string; fields: unknown}>;
 disableIdGeneration?: boolean;
 customIdGenerator?: (input: {model: string}) => string;
 supportsUUIDs?: boolean;
}) {
 return ({customModelName = 'user', forceAllowId = false}: {customModelName?: string; forceAllowId?: boolean}) => {
  const settings = {strategy: strategy(options), model: customModelName, disable_id_generation: disableIdGeneration, supports_uuids: supportsUUIDs, force_allow_id: forceAllowId, adapter_generator: !!customIdGenerator};
  const descriptor = native('descriptor', {options: settings});
  const defaults: Record<string, () => unknown> = {
   undefined: () => undefined,
   configured: () => (options.advanced!.database!.generateId as (input: {model: string}) => unknown)({model: descriptor.model}),
   adapter: () => customIdGenerator!({model: descriptor.model}),
   uuid: () => native('uuid'),
   random: () => native('random'),
  };
  return {
   type: descriptor.type as 'string' | 'number', required: descriptor.required as boolean,
   defaultValue: descriptor.has_default ? defaults[descriptor.default_kind] : undefined,
   transform: {input: (value: unknown) => native('input', {options: settings, value}), output: (value: unknown) => native('output', {value})},
  };
 };
}
