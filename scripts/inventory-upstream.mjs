import ts from "typescript";
import { testFunctionNames } from './upstream-test-discovery.mjs';
import {sourceCoverage} from './upstream-coverage.mjs';
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const lock = JSON.parse(readFileSync("upstream.lock.json", "utf8"));
const root = resolve(process.argv[2] ?? ".upstream/better-auth");
const manifests = readdirSync("tests/upstream")
  .filter((name) => name === "manifest.json" || name.endsWith(".manifest.json"))
  .map((name) =>
    JSON.parse(readFileSync(join("tests/upstream", name), "utf8")),
  );
function* walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
    (a, b) => a.name.localeCompare(b.name),
  )) {
    if ([".git", "node_modules", "dist", ".next"].includes(entry.name))
      continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (/\.(test|spec)(-d)?\.(ts|tsx|js|jsx|mjs|mts)$/.test(entry.name))
      yield path;
  }
}
function label(call, source) {
  const argument = call.arguments[0];
  return argument &&
    (ts.isStringLiteral(argument) ||
      ts.isNoSubstitutionTemplateLiteral(argument))
    ? argument.text
    : (argument?.getText(source) ?? "<dynamic>");
}
const files = [];
for (const directory of ["."]) {
  if (!existsSync(join(root, directory))) continue;
  for (const path of walk(join(root, directory))) {
    const contents = readFileSync(path, "utf8");
    const source = ts.createSourceFile(
      path,
      contents,
      ts.ScriptTarget.Latest,
      true,
    );
    const declarations = [];
    const testNames = testFunctionNames(source);
    function visit(node, suites = []) {
      if (ts.isCallExpression(node)) {
        let expression = node.expression;
        // Covers test.each(cases)(...), describe.each(...), it.skip(...), etc.
        while (ts.isCallExpression(expression))
          expression = expression.expression;
        const name = expression.getText(source);
        if (
          /^(describe|suite)(\.|$)/.test(name) &&
          node.arguments.some(
            (arg) => ts.isArrowFunction(arg) || ts.isFunctionExpression(arg),
          )
        ) {
          for (const arg of node.arguments) {
            if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg))
              visit(arg.body, [...suites, label(node, source)]);
          }
          return;
        }
        if (
          testNames.has(name.split('.')[0]) &&
          (node.arguments.some(
            (arg) => ts.isArrowFunction(arg) || ts.isFunctionExpression(arg),
          ) ||
            name.endsWith(".todo"))
        ) {
          declarations.push({
            sourceStart:node.getStart(source),
            suites,
            title: label(node, source),
            line:
              source.getLineAndCharacterOfPosition(node.getStart(source)).line +
              1,
            parameterized: name.includes(".each"),
            upstreamDisabled: /\.(skip|todo|fails)(\.|$)/.test(name),
          });
          return;
        }
      }
      ts.forEachChild(node, (child) => visit(child, suites));
    }
    visit(source);
    const name = relative(root, path).replaceAll("\\", "/");
    const matching=manifests.filter(entry=>entry.path===name);
    const checksum=createHash('sha256').update(contents).digest('hex');
    const coverage=sourceCoverage(checksum,declarations,matching);
    const group = name.includes("/plugins/")
      ? "plugins"
      : name.includes("/adapters/") ||
          /^packages\/[^/]*adapter[^/]*\//.test(name)
        ? "adapters"
        : name.startsWith("e2e/")
          ? "e2e"
          : name.startsWith("demo/")
            ? "examples"
            : name.includes("/client/")
              ? "client"
              : name.includes("/api/")
                ? "core-api"
                : "utilities-and-tooling";
    files.push({
      path: name,
      sha256: createHash("sha256").update(contents).digest("hex"),
      group,
      ...coverage,
      kind: /\.(test|spec)-d\./.test(name) ? "type-only" : "runtime",
      declarations:declarations.map(({sourceStart,...entry})=>entry),
    });
  }
}
const groups = {};
for (const file of files) {
  const group = (groups[file.group] ??= {
    files: 0,
    declarations: 0,
    importedFiles: 0,
  });
  group.files++;
  group.declarations += file.declarations.length;
  if (file.status.startsWith("imported-")) group.importedFiles++;
}
const inventory = {
  commit: lock.commit,
  methodology:
    "Static AST inventory of test/spec files across the entire pinned repository, including demos, tooling, and type-only files. Declarations are not runtime case counts: parameterization, loops, conditions, and helper registration can change case counts. Selections are unioned across checksum-matched manifests by AST source position; backend repeats do not increase unique declaration coverage. Imported indicates preserved test source, not a passing test result.",
  totals: {
    files: files.length,
    declarations: files.reduce(
      (sum, file) => sum + file.declarations.length,
      0,
    ),
  },
  groups,
  files,
};
writeFileSync(
  "tests/upstream/corpus.json",
  JSON.stringify(inventory, null, 2) + "\n",
);
console.log(JSON.stringify({ totals: inventory.totals, groups }, null, 2));
