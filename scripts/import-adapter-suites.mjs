import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import ts from 'typescript';

// Shared upstream suites use createTestSuite and object entries, rather than
// *.test.ts/it declarations. Keep their inventory separate from corpus.json.
const lock=JSON.parse(readFileSync('upstream.lock.json','utf8'));
const root=resolve(process.argv[2]??'.upstream/better-auth');
const commit=readFileSync(resolve(root,'.source-commit'),'utf8').trim();
if(commit!==lock.commit)throw new Error('Pinned adapter-suite source mismatch');
const entries=[];
mkdirSync('tests/upstream/adapter-suites',{recursive:true});
mkdirSync('tests/upstream/adapter-suites/sources',{recursive:true});
for(const name of ['auth-flow','transactions']){
 const path='packages/test-utils/src/adapter/suites/'+name+'.ts';
 const source=readFileSync(resolve(root,path),'utf8');
 const ast=ts.createSourceFile(path,source,ts.ScriptTarget.Latest,true);
 const tests=[];
 function visit(node){
  if(ts.isPropertyAssignment(node)&&ts.isStringLiteral(node.name)&&ts.isArrowFunction(node.initializer))tests.push({title:node.name.text,sourceStart:node.getStart(ast),sourceLine:ast.getLineAndCharacterOfPosition(node.getStart(ast)).line+1,selected:true});
  ts.forEachChild(node,visit);
 }
 visit(ast);
 if(tests.length!==(name==='auth-flow'?7:1))throw new Error('Unexpected adapter suite declarations');
 const imported=source.replace('"../create-test-suite"','"../../harness/adapter-suite.js"');
 if(imported===source)throw new Error('Missing shared suite import');
 const target='tests/upstream/adapter-suites/'+name+'.ts';
 const snapshot='tests/upstream/adapter-suites/sources/'+name+'.ts.txt';
 writeFileSync(snapshot,source);
 writeFileSync(target,imported);
 entries.push({path,target,snapshot,sha256:createHash('sha256').update(source).digest('hex'),tests});
}
writeFileSync('tests/upstream/adapter-suites.imports.json',JSON.stringify({commit,changes:'Only createTestSuite import path changes; all test bodies, assertions and registrations preserved.',executionSurface:'native SQLite/PostgreSQL/MongoDB auth and transaction adapters; TS fixture registration/configuration/transport only',coverageNote:'Eight shared suite entries, outside the test/spec corpus denominator. Backend repetitions do not increase unique coverage.',files:entries},null,2)+'\n');
