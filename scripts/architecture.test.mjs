import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {test} from 'node:test';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
function sources(directory){
 return readdirSync(join(root,directory),{withFileTypes:true}).flatMap(entry=>{
  const path=join(directory,entry.name);
  return entry.isDirectory()?sources(path):path.endsWith('.v')?[path]:[];
 });
}
test('independent adapter, domain and SQL driver modules do not import the auth runtime',()=>{
 for(const directory of ['adapter','domain','storage'])for(const path of sources(directory)){
  const source=readFileSync(join(root,path),'utf8');
  assert(!/^import\s+(?:alexvyber\.)?better_auth(?:\s|$)/m.test(source),path);
 }
});
test('native SQL imports occur only in explicitly enabled driver files',()=>{
 const paths=[...readdirSync(root).filter(path=>path.endsWith('.v')),...sources('internal'),...sources('adapter'),...sources('domain'),...sources('storage')];
 for(const path of paths){
  const source=readFileSync(join(root,path),'utf8');
  if(/^import\s+db\.sqlite\b/m.test(source))assert.match(path,/^storage\/sqlite\/.*_d_sqlite\.v$/);
  if(/^import\s+db\.pg\b/m.test(source))assert.match(path,/^storage\/postgres\/.*_d_postgres\.v$/);
 }
});

test('root remains a small public entry and shared implementation sources are registered',()=>{
 assert.deepEqual(readdirSync(root).filter(path=>path.endsWith('.v')).sort(),['auth.v','config.v','types.v']);
 assert.match(readFileSync(join(root,'v.mod'),'utf8'),/subdirs:\s*\[\s*'internal'\s*\]/);
 for(const path of sources('internal'))assert.match(readFileSync(join(root,path),'utf8'),/^module better_auth$/m,path);
});

test('storage implementation methods stay with their backend',()=>{
 const backends={MemoryStorage:'memory',MemorySecondaryStorage:'memory',NoSecondaryStorage:'memory',SQLiteStorage:'sqlite',PostgresStorage:'postgres',MongoStorage:'mongo',RedisStorage:'redis',RedisTCPClient:'redis'};
 for(const path of sources('internal').filter(path=>!path.endsWith('_test.v'))){
  const source=readFileSync(join(root,path),'utf8');
  for(const [type,backend] of Object.entries(backends)){
   const receiver=new RegExp(`^(?:pub )?fn \\([^\\n]*\\b${type}\\)`,'m');
   if(receiver.test(source))assert(path.startsWith(`internal/persistence/${backend}/`),`${type} implementation outside its backend: ${path}`);
  }
 }
});

test('owned integration tests stay under contracts and upstream tests retain their directory',()=>{
 assert(!readdirSync(join(root,'tests')).some(path=>path.endsWith('.test.ts')||path.endsWith('_test.v')));
 assert(sources('tests/contracts').some(path=>path.endsWith('_test.v')),'External native plugin contract missing');
 const config=readFileSync(join(root,'vitest.config.ts'),'utf8');
 assert(config.includes('tests/contracts/**/*.test.ts'));
 assert(config.includes('tests/upstream/**/*.test.ts'));
});
