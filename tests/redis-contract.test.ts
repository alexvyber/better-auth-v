import {spawn, execFileSync, type ChildProcess} from 'node:child_process';
import {createConnection, createServer} from 'node:net';
import {once} from 'node:events';
import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import {redisStorage} from './harness/redis-storage.js';
import {getTestInstance} from './harness/test-instance.js';
import {oneTimeToken} from './harness/plugins.js';

let server: ChildProcess;
let port = 0;
const password = 'isolated-native-redis-test';
const tcp = () => ({address: `127.0.0.1:${port}`, password, timeout_millis: 500});
function redis(...args: string[]) {return execFileSync('redis-cli', ['--no-auth-warning', '-h', '127.0.0.1', '-p', String(port), '-a', password, '--raw', ...args], {encoding: 'utf8'}).trimEnd();}
beforeAll(async () => {
 const listener = createServer(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
 port = (listener.address() as {port: number}).port;
 await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
 server = spawn('redis-server', ['--bind', '127.0.0.1', '--port', String(port), '--save', '', '--appendonly', 'no', '--requirepass', password], {stdio: 'ignore'});
 for (let attempt = 0; attempt < 100; attempt++) {
  const connected = await new Promise<boolean>(resolve => {const socket = createConnection({host: '127.0.0.1', port}); socket.once('connect', () => {socket.destroy(); resolve(true);}); socket.once('error', () => {socket.destroy(); resolve(false);});});
  if (connected) return;
  await new Promise(resolve => setTimeout(resolve, 20));
 }
 throw new Error('Isolated Redis did not start');
});
afterAll(async () => {if (server && server.exitCode === null) {server.kill('SIGTERM'); await once(server, 'exit');}});

describe('native Redis TCP and auth integration', () => {
 it('round-trips binary UTF-8 values and consumes across independent clients once', async () => {
  const first = redisStorage({tcp: tcp(), keyPrefix: 'binary:'});
  const second = redisStorage({tcp: tcp(), keyPrefix: 'binary:'});
  const value = 'å\0💡'.repeat(5000);
  await first.set('proof', value, 60);
  expect(await second.get('proof')).toBe(value);
  const results = await Promise.all([first.getAndDelete('proof'), second.getAndDelete('proof')]);
  expect(results.filter(result => result === value)).toHaveLength(1);
  expect(results.filter(result => result === null)).toHaveLength(1);
 });

 it('does not reset a counter TTL and confines scans to literal prefixes', async () => {
  const storage = redisStorage({tcp: tcp(), keyPrefix: 'ba[1]:',});
  expect(await storage.increment('rate', 60)).toBe(1);
  expect(redis('EXPIRE', 'ba[1]:rate', '7')).toBe('1');
  expect(await storage.increment('rate', 60)).toBe(2);
  expect(Number(redis('TTL', 'ba[1]:rate'))).toBeGreaterThan(0);
  expect(Number(redis('TTL', 'ba[1]:rate'))).toBeLessThanOrEqual(7);
  redis('SET', 'ba1:foreign', 'keep');
  await storage.set('session', 'value');
  expect((await storage.listKeys()).sort()).toEqual(['rate', 'session']);
  await storage.clear();
  expect(await storage.listKeys()).toEqual([]);
  expect(redis('GET', 'ba1:foreign')).toBe('keep');
 });

 it('propagates authentication errors without treating them as unsupported GETDEL', async () => {
  const storage = redisStorage({tcp: {...tcp(), password: 'incorrect'}, keyPrefix: 'wrong:'});
  await expect(storage.getAndDelete('proof')).rejects.toThrow(/WRONGPASS/);
 });

 it('shares native sessions and one-time handoffs across independent auth instances', async () => {
  const storage = redisStorage({tcp: tcp(), keyPrefix: 'auth:'});
  const configuration = {secondaryStorage: storage, plugins: [oneTimeToken({storeToken: 'hashed'})]};
  const first = await getTestInstance(configuration);
  const second = await getTestInstance(configuration, {disableTestUser: true});
  const {headers} = await first.signInWithTestUser();
  const {token} = await first.auth.api.generateOneTimeToken({headers});
  expect((await second.auth.api.verifyOneTimeToken({body: {token}})).user.email).toBe(first.testUser.email);
  await expect(first.auth.api.verifyOneTimeToken({body: {token}})).rejects.toMatchObject({body: {code: 'BAD_REQUEST', message: 'Invalid token'}});
 });
});

describe('Redis TCP protocol failures', () => {
 async function withPeer(reply: (socket: import('node:net').Socket) => void, run: (options: {address: string; timeout_millis: number}) => Promise<void>) {
  const sockets = new Set<import('node:net').Socket>();
  const peer = createServer(socket => {sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.once('data', () => reply(socket));});
  peer.listen(0, '127.0.0.1'); await once(peer, 'listening');
  try {await run({address: `127.0.0.1:${(peer.address() as {port: number}).port}`, timeout_millis: 100});}
  finally {for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => peer.close(() => resolve()));}
 }
 it('reads replies split across TCP frames without losing binary bytes', async () => {
  await withPeer(socket => {
   socket.write('$5\r\nA');
   setTimeout(() => {socket.write(Buffer.from([0, 66, 67, 68, 13, 10]));}, 10);
  }, async options => {expect(await redisStorage({tcp: options}).get('fragmented')).toBe('A\0BCD');});
 });
 it('rejects oversized bulk lengths before allocating the payload', async () => {
  await withPeer(socket => {socket.write('$999999999999\r\n');}, async options => {
   await expect(redisStorage({tcp: options}).get('oversized')).rejects.toThrow('invalid Redis bulk length');
  });
 });
 it('times out interrupted mutations without retrying them', async () => {
  let commands = 0;
  await withPeer(() => {commands++;}, async options => {
   await expect(redisStorage({tcp: options}).increment('counter', 60)).rejects.toThrow();
   expect(commands).toBe(1);
  });
 });
});
