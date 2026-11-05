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
for(const name of ['auth-flow','transactions','basic','joins']){
 const path='packages/test-utils/src/adapter/suites/'+name+'.ts';
 const source=readFileSync(resolve(root,path),'utf8');
 const ast=ts.createSourceFile(path,source,ts.ScriptTarget.Latest,true);
 const tests=[];
 function visit(node){
  if(ts.isPropertyAssignment(node)&&ts.isStringLiteral(node.name)&&(ts.isArrowFunction(node.initializer)||ts.isObjectLiteralExpression(node.initializer))){
   const excluded=name==='basic'&&(!ts.isArrowFunction(node.initializer)||/plugins:|incrementOne|oneToOneTable/.test(node.getText(ast)));
   tests.push({title:node.name.text,sourceStart:node.getStart(ast),sourceLine:ast.getLineAndCharacterOfPosition(node.getStart(ast)).line+1,selected:!excluded,...(excluded?{reason:'Arbitrary plugin tables, custom relationships and atomic incrementOne remain unported'}:{})});
  }
  ts.forEachChild(node,visit);
 }
 visit(ast);
 if(['auth-flow','transactions'].includes(name)&&tests.length!==(name==='auth-flow'?7:1))throw new Error('Unexpected adapter suite declarations');
 const imported=source.replace('"../create-test-suite"','"../../harness/adapter-suite.js"').replace('"./basic"','"./basic.js"');
 if(imported===source)throw new Error('Missing shared suite import');
 const target='tests/upstream/adapter-suites/'+name+'.ts';
 const snapshot='tests/upstream/adapter-suites/sources/'+name+'.ts.txt';
 writeFileSync(snapshot,source);
 writeFileSync(target,imported);
 entries.push({path,target,snapshot,sha256:createHash('sha256').update(source).digest('hex'),tests});
}
writeFileSync('tests/upstream/adapter-suites.imports.json',JSON.stringify({commit,changes:'Import paths only; all test bodies/assertions preserved. The native registrar selects recorded entries without registering exclusions as passing tests.',executionSurface:'native SQLite/PostgreSQL/MongoDB auth and transaction adapters; TS fixture registration/configuration/transport only',coverageNote:'Shared suite entries are outside the test/spec corpus denominator. Basic exclusions are recorded individually; the joins wrapper repeats selected basic entries and does not increase unique coverage.',files:entries},null,2)+'\n');
