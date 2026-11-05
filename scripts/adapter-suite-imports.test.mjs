import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';

const metadata=JSON.parse(readFileSync('tests/upstream/adapter-suites.imports.json','utf8'));
const lock=JSON.parse(readFileSync('upstream.lock.json','utf8'));
for(const entry of metadata.files)test('preserves every original shared adapter suite entry: '+entry.path,()=>{
 assert.equal(metadata.commit,lock.commit);
 const source=readFileSync(entry.snapshot,'utf8');
 assert.equal(createHash('sha256').update(source).digest('hex'),entry.sha256);
 assert.equal(readFileSync(entry.target,'utf8'),source.replace('"../create-test-suite"','"../../harness/adapter-suite.js"').replace('"./basic"','"./basic.js"'));
 const ast=ts.createSourceFile(entry.path,source,ts.ScriptTarget.Latest,true);const declarations=[];
 function visit(node){
  if(ts.isPropertyAssignment(node)&&ts.isStringLiteral(node.name)&&(ts.isArrowFunction(node.initializer)||ts.isObjectLiteralExpression(node.initializer))){
   const excluded=entry.path.endsWith('/basic.ts')&&/incrementOne/.test(node.getText(ast));
   declarations.push({title:node.name.text,sourceStart:node.getStart(ast),sourceLine:ast.getLineAndCharacterOfPosition(node.getStart(ast)).line+1,selected:!excluded,...(excluded?{reason:'Atomic incrementOne remains unported'}:{})});
  }
  ts.forEachChild(node,visit);
 }
 visit(ast);assert.deepEqual(entry.tests,declarations);assert.ok(declarations.length>0);
});
