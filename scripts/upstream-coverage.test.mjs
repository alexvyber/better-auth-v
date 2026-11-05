import {test} from 'node:test';
import assert from 'node:assert/strict';
import {sourceCoverage} from './upstream-coverage.mjs';
const declarations=[{sourceStart:10,suites:['suite'],title:'same title'},{sourceStart:20,suites:['suite'],title:'same title'},{sourceStart:30,suites:['suite'],title:'third'}];
const imported=(...positions)=>({sha256:'pinned',tests:positions.map(sourceStart=>({sourceStart,suites:['suite'],test:declarations.find(item=>item.sourceStart===sourceStart)?.title,selected:true}))});
test('complementary imports cover a source file once',()=>{
 assert.deepEqual(sourceCoverage('pinned',declarations,[imported(10,20),imported(30)]),{status:'imported-complete-file',importedDeclarations:3,unportedDeclarations:0});
});
test('backend repeats do not turn partial coverage into complete coverage',()=>{
 assert.deepEqual(sourceCoverage('pinned',declarations,Array.from({length:100},()=>imported(10))),{status:'imported-partial-file',importedDeclarations:1,unportedDeclarations:2});
});
test('duplicate titles remain distinct declarations',()=>{
 assert.equal(sourceCoverage('pinned',declarations,[imported(10),imported(30)]).unportedDeclarations,1);
});
test('every manifest must match the source checksum',()=>{
 assert.throws(()=>sourceCoverage('pinned',declarations,[imported(10),{...imported(20),sha256:'stale'}]),/checksum mismatch/);
});
test('incorrect positions or labels fail instead of inflating coverage',()=>{
 assert.throws(()=>sourceCoverage('pinned',declarations,[imported(999)]),/does not match source/);
 const wrong=imported(10);wrong.tests[0].test='third';assert.throws(()=>sourceCoverage('pinned',declarations,[wrong]),/does not match source/);
 const wrongLine=imported(10);wrongLine.tests[0].sourceLine=999;assert.throws(()=>sourceCoverage('pinned',declarations,[wrongLine]),/does not match source/);
});
test('legacy manifests only cover unambiguous labels and missing imports stay unported',()=>{
 const legacy={sha256:'pinned',tests:[{suites:['suite'],test:'same title',selected:true},{suites:['suite'],test:'third',selected:true}]};
 assert.deepEqual(sourceCoverage('pinned',declarations,[legacy]),{status:'imported-partial-file',importedDeclarations:1,unportedDeclarations:2});
 assert.deepEqual(sourceCoverage('pinned',declarations,[]),{status:'unported',importedDeclarations:0,unportedDeclarations:3});
});
