import {afterAll} from 'vitest';
import {Bridge, transportJSON} from './bridge.js';
const instances = new Set<Bridge>();
afterAll(async () => {for (const bridge of instances) await bridge.close(); instances.clear();});
export interface NativeRedisOptions {address: string; username?: string; password?: string; database?: number; timeout_millis?: number}
const nativeConfigurations = new WeakMap<object, {tcp: NativeRedisOptions; keyPrefix: string}>();
export function nativeRedisConfiguration(storage: object | undefined) {return storage ? nativeConfigurations.get(storage) : undefined;}
export function redisStorage({client, keyPrefix = 'better-auth:', tcp}: {client?: Record<string, any>; keyPrefix?: string; tcp?: NativeRedisOptions}) {
 const bridge = new Bridge(['--redis']); instances.add(bridge);
 let callbackFailure: unknown;
 if (client) bridge.setCallback('redis.command', async ({method, arguments: args}) => {
  if (typeof client[method] !== 'function') throw new Error('Redis client does not implement ' + method);
  try { return await client[method](...args); } catch (error) {callbackFailure = error; throw error;}
 });
 const ready = bridge.send('init', {options: {keyPrefix}, tcp});
 const invoke = async (method: string, args: unknown[]) => {
  await ready;
  callbackFailure = undefined;
  try {
   const reply = await bridge.send('redis', {method, arguments_json: transportJSON(args)});
   return JSON.parse(reply.value_json);
  } catch (error) { if (callbackFailure) throw callbackFailure; throw error; }
 };
 const storage = {
  get: (key: string) => invoke('get', [key]),
  getAndDelete: (key: string) => invoke('getAndDelete', [key]),
  increment: (key: string, ttl: number) => invoke('increment', [key, ttl]),
  set: async (key: string, value: string, ttl?: number) => {await invoke('set', [key, value, ttl]);},
  delete: async (key: string) => {await invoke('delete', [key]);},
  listKeys: (): Promise<string[]> => invoke('listKeys', []),
  clear: async () => {await invoke('clear', []);},
 };
 if (tcp) nativeConfigurations.set(storage, {tcp, keyPrefix});
 return storage;
}
