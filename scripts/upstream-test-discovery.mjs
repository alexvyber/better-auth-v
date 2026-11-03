import ts from 'typescript';

// Upstream's named fixtures (test.extend(...)) are test declarations too.
export function testFunctionNames(source) {
  const names = new Set(['it', 'test']);
  let changed;
  do {
    changed = false;
    function visit(node) {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && ts.isCallExpression(node.initializer)) {
        const call = node.initializer.expression;
        if (ts.isPropertyAccessExpression(call) && call.name.text === 'extend' && ts.isIdentifier(call.expression) && names.has(call.expression.text) && !names.has(node.name.text)) {
          names.add(node.name.text);
          changed = true;
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
  } while (changed);
  return names;
}
