// Tests stay next to their shared-module sources. V 0.5.2 does not add the
// manifest's other source groups when starting from a nested test directory.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readdirSync,readFileSync,mkdtempSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
function walk(directory){
 return readdirSync(join(root,directory),{withFileTypes:true}).flatMap(entry=>{
  const path=join(directory,entry.name);
  return entry.isDirectory()?walk(path):path.endsWith('.v')?[path]:[];
 });
}
export function discoverNativeTests(){
 const internal=walk('internal');
 const production=[...readdirSync(root).filter(path=>path.endsWith('.v')), ...internal]
  .filter(path=>!path.endsWith('_test.v'));
 const tests=[...internal,...['adapter','domain','schema','storage','normalization','tests'].flatMap(walk)]
  .filter(path=>path.endsWith('_test.v')).sort();
 return tests.map(path=>{
  const sameModule=/^module better_auth\s*$/m.test(readFileSync(join(root,path),'utf8'));
  const sources=sameModule?production.filter(source=>dirname(source)!==dirname(path)):[];
  return {path,sources};
 });
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const all=discoverNativeTests();
 assert(new Set(all.map(test=>test.path)).size===all.length,'Duplicate native test discovery');
 const filters=process.argv.slice(2).filter(arg=>arg!=='--list');
 const selected=all.filter(test=>filters.length===0||filters.some(filter=>test.path.includes(filter)));
 assert(selected.length>0,'No native tests matched');
 if(process.argv.includes('--list')){
  console.log(selected.map(test=>test.path).join('\n'));
 }else{
  const jobs=Number(process.env.BETTER_AUTH_TEST_JOBS??1);
  assert(Number.isInteger(jobs)&&jobs>0,'BETTER_AUTH_TEST_JOBS must be a positive integer');
  // A Git checkout may be named better-auth-v rather than better_auth. Explicit
  // module identity also prevents a globally installed copy masking this source.
  const modules=mkdtempSync(join(tmpdir(),'better-auth-native-modules-'));
  symlinkSync(root,join(modules,'better_auth'),process.platform==='win32'?'junction':'dir');
  let next=0,passed=0;
  async function worker(){
   while(next<selected.length){
    const position=next++;
    const test=selected[position];
    const args=['-d','sqlite','-d','postgres','-o',join(modules,`native-test-${position}`)];
    if(test.sources.length)args.push('-file-list',test.sources.map(path=>join(root,path)).join(','));
    args.push(join(root,test.path));
    const result=await new Promise(resolveRun=>{
     const child=spawn(process.env.V??'v',args,{cwd:root,env:{...process.env,VMODULES:modules,V_C_ERROR_BUG_REPORT_DISABLED:'1'}});
     let output='';
     child.stdout.on('data',chunk=>output+=chunk);
     child.stderr.on('data',chunk=>output+=chunk);
     child.on('error',error=>resolveRun({code:1,output:String(error)}));
     child.on('close',(code,signal)=>resolveRun({code:code??1,output:output+(signal?`\nSignal: ${signal}`:'')}));
    });
    if(result.code===0){passed++;console.log(`PASS ${test.path}`)}
    else console.error(`FAIL ${test.path}\n${result.output}`);
   }
  }
  try{
   await Promise.all(Array.from({length:Math.min(jobs,selected.length)},worker));
  }finally{rmSync(modules,{recursive:true,force:true})}
  console.log(`Native tests: ${passed}/${selected.length} files passed`);
  process.exitCode=passed===selected.length?0:1;
 }
}
