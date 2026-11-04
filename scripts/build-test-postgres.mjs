// A local test dependency only; never installs globally or connects to an application DB.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {availableParallelism} from 'node:os';
import {resolve, join} from 'node:path';
const version = '18.4';
const checksum = '81a81ec695fb0c7901407defaa1d2f7973617154cf27ba74e3a7ab8e64436094';
const dependencies = resolve('build/deps');
const prefix = join(dependencies, 'pgsql');
const binary = join(prefix, 'bin/postgres');
if (existsSync(binary)) {
 execFileSync(binary, ['--version'], {stdio: 'inherit'});
 process.exit(0);
}
mkdirSync(dependencies, {recursive: true});
const archive = join(dependencies, `postgresql-${version}.tar.bz2`);
if (!existsSync(archive)) {
 const response = await fetch(`https://ftp.postgresql.org/pub/source/v${version}/postgresql-${version}.tar.bz2`, {signal: AbortSignal.timeout(120000)});
 if (!response.ok) throw new Error(`PostgreSQL download failed: ${response.status}`);
 writeFileSync(archive, new Uint8Array(await response.arrayBuffer()));
}
if (createHash('sha256').update(readFileSync(archive)).digest('hex') !== checksum) throw new Error('PostgreSQL archive checksum mismatch');
const source = join(dependencies, `postgresql-${version}`);
if (!existsSync(source)) execFileSync('tar', ['-xjf', archive, '-C', dependencies], {stdio: 'inherit'});
execFileSync('./configure', [`--prefix=${prefix}`, '--without-icu', '--without-readline', '--without-zlib', '--without-lz4', '--without-zstd'], {cwd: source, stdio: 'inherit'});
execFileSync('make', [`-j${Math.min(availableParallelism(), 8)}`], {cwd: source, stdio: 'inherit'});
execFileSync('make', ['install'], {cwd: source, stdio: 'inherit'});
execFileSync(binary, ['--version'], {stdio: 'inherit'});
