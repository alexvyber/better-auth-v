// Verify tracked package contents from unrelated consumers, without checkout paths
// or global V modules masking installation errors. No npm dependencies are needed.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {cpSync,existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const repository=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const manifest=readFileSync(join(repository,'v.mod'),'utf8');
assert.match(manifest,/name:\s*'better_auth'/);
assert.match(manifest,/version:\s*'\d+\.\d+\.\d+(?:-[^']+)?'/);
assert.match(manifest,/license:\s*'MIT'/);
assert.match(manifest,/repo_url:\s*'https:\/\/github\.com\/alexvyber\/better-auth-v'/);
const files=execFileSync('git',['ls-files','-z'],{cwd:repository,encoding:'utf8'}).split('\0').filter(Boolean);
for(const required of ['v.mod','LICENSE','UPSTREAM_LICENSE','jws_openssl.h','mongo_driver.h','normalization/nfkc.v','normalization/data/tables.txt','normalization/data/UNICODE_LICENSE']){
 assert(files.includes(required),`Required package file is not tracked: ${required}`);
}
assert(!files.some(file=>/^(?:build|node_modules|\.upstream)\//.test(file)),'Generated dependencies must not be tracked');
const temporary=mkdtempSync(join(tmpdir(),'better-auth-package-'));
const v=process.env.V??'v';
const coreOnly=process.argv.includes('--core-only');
const consumer=(prefix)=>`module main

import ${prefix}

fn main() {
 // Exercises the embedded Unicode tables from the installed nested module.
 hasher := better_auth.ScryptHasher{}
 encoded := hasher.hash('Café package password')!
 assert hasher.verify('Cafe\u0301 package password', encoded)!
 assert !hasher.verify('wrong password', encoded)!
 mut storage := better_auth.open_sqlite('auth.sqlite')!
 storage.migrate()!
 config := better_auth.Config{
  secret: 'package-check-secret-at-least-32-characters'
  base_url: 'http://localhost:3000'
  plugins: [better_auth.Plugin(better_auth.JWTPlugin{
   options: better_auth.JWTOptions{ algorithm: 'RS256' }
  })]
 }
 mut auth := better_auth.new(config, storage)!
 // Compile public generic transaction results from an unrelated module.
 answer := auth.transaction[int](fn (mut context better_auth.EndpointContext) !int {
  return context.transaction[int](fn (mut _ better_auth.EndpointContext) !int {
   return 42
  })
 })!
 assert answer == 42
 response := auth.transaction[better_auth.Response](fn (mut _ better_auth.EndpointContext) !better_auth.Response {
  return better_auth.Response{status: 201, body: 'typed package result'}
 })!
 assert response.status == 201
 assert response.body == 'typed package result'
 created := auth.sign_up_email(better_auth.SignUpInput{
  email: 'package@example.com'
  name: 'Package consumer'
  password: 'a-long-package-password'
 }, better_auth.RequestContext{})!
 assert created.token != none
 // Exercises the bundled OpenSSL C shim and persisted key storage.
 jwt := auth.sign_jwt('{"sub":"package-consumer"}')!
 assert (auth.verify_jwt(jwt, '')!).value != none
 auth.close()!
 mut reopened := better_auth.open_sqlite('auth.sqlite')!
 mut restarted := better_auth.new(config, reopened)!
 defer { restarted.close() or {} }
 login := restarted.sign_in_email(better_auth.SignInInput{
  email: 'package@example.com'
  password: 'a-long-package-password'
 }, better_auth.RequestContext{})!
 assert login.user.id == created.user.id
 assert (restarted.verify_jwt(jwt, '')!).value != none
 println('Installed package verified: ${prefix}')
}
`;
// Keep core linking independent of native database headers/libraries.
const coreConsumer=(prefix)=>`module main
import ${prefix}

fn main() {
 mut auth := better_auth.new(better_auth.Config{
  secret: 'memory-package-secret-at-least-32-characters'
 }, better_auth.MemoryStorage{})!
 defer {auth.close() or {}}
 assert auth.with_internal(fn (mut context better_auth.EndpointContext) !string {
  user := context.create_user(better_auth.User{id:'core-user',email:'core@example.com'})!
  return user.id
 })! == 'core-user'
 mut sqlite_disabled := false
 better_auth.open_sqlite(':memory:') or {
  assert err.msg().contains('-d sqlite')
  sqlite_disabled = true
 }
 assert sqlite_disabled
 mut postgres_disabled := false
 better_auth.open_postgres(better_auth.PostgresOptions{connection_string:'host=localhost'}) or {
  assert err.msg().contains('-d postgres')
  postgres_disabled = true
 }
 assert postgres_disabled
}
`;
const postgresConsumer=(prefix)=>`module main
import ${prefix}
fn main() {
 mut rejected := false
 // Forces native PostgreSQL connection handling without a database server.
 better_auth.open_postgres(better_auth.PostgresOptions{connection_string:'invalid'}) or {
  assert !err.msg().contains('support is disabled')
  rejected = true
 }
 assert rejected
}
`;
function linkedLibraries(binary) {
 const output=execFileSync(process.platform==='darwin'?'otool':'ldd',process.platform==='darwin'?['-L',binary]:[binary],{encoding:'utf8'});
 return process.platform==='darwin'?output.split('\n').slice(1).join('\n'):output;
}
try{
 const source=join(temporary,'source');mkdirSync(source,{recursive:true});
 for(const file of files){
  const target=join(source,file);mkdirSync(dirname(target),{recursive:true});
  cpSync(join(repository,file),target);
 }
 const git=(args)=>execFileSync('git',args,{cwd:source,stdio:'pipe'});
 git(['init','--quiet','--initial-branch=main']);git(['add','--all']);
 git(['-c','user.name=Package check','-c','user.email=package-check@localhost','-c','commit.gpgsign=false','commit','--quiet','-m','Package verification snapshot']);
 for(const prefix of ['alexvyber.better_auth','better_auth']){
  const root=join(temporary,prefix);const modules=join(root,'modules');
  const installed=join(modules,...prefix.split('.'));const app=join(root,'consumer');
  mkdirSync(modules,{recursive:true});mkdirSync(app,{recursive:true});
  const env={...process.env,VMODULES:modules,V_C_ERROR_BUG_REPORT_DISABLED:'1',VPM_FAIL_ON_PROMPT:'1'};
  if(prefix==='better_auth'){
   // Actual VPM Git installer, using a local candidate snapshot before publication.
   execFileSync(v,['install','--git',source],{cwd:app,env,stdio:'inherit',timeout:180000});
  }else{
   // Registry registration is a separate release step. Reproduce its layout.
   for(const file of files){
    const target=join(installed,file);mkdirSync(dirname(target),{recursive:true});
    cpSync(join(source,file),target);
   }
  }
  assert(!existsSync(join(installed,'build')));
  writeFileSync(join(app,'v.mod'),"Module { name: 'package_consumer' version: '0.0.0' dependencies: [] }\n");
  for(const [name,code,flags] of [
   ['core',coreConsumer(prefix),[]],
   ['sqlite',consumer(prefix),['-d','sqlite']],
   ['postgres',postgresConsumer(prefix),['-d','postgres']],
  ]){
   if(coreOnly && name!=='core')continue;
   writeFileSync(join(app,'main.v'),code);
   const binary=join(app,name);
   execFileSync(v,[...flags,'-o',binary,'main.v'],{cwd:app,stdio:'inherit',timeout:180000,env});
   const linked=linkedLibraries(binary);
   if(name!=='sqlite')assert(!/sqlite/i.test(linked),`${name} unexpectedly links SQLite: ${linked}`);
   if(name!=='postgres')assert(!/libpq/i.test(linked),`${name} unexpectedly links libpq: ${linked}`);
   execFileSync(binary,[],{cwd:app,stdio:'inherit',timeout:180000,env});
   console.log(`Installed ${prefix}: ${name} consumer and dependency isolation verified`);
  }
 }
 console.log('Package checks passed without Node packages, a database server, or checkout build artifacts.');
}finally{rmSync(temporary,{recursive:true,force:true})}
