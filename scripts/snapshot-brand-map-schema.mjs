import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import ts from 'typescript';

// Read-only extraction. Tests consume the checked-in snapshot and never need an
// application checkout, application environment, or application database.
const root = resolve(process.argv[2] ?? '/Users/alexs/bm/server');
const path = 'platform/services/database-schema/prisma/migrations/20261102120000_catalog_baseline/migration.sql';
const source = readFileSync(resolve(root, path), 'utf8');
const tables = new Set(['auth_user','auth_session','auth_account','auth_verification','auth_organization','auth_member','auth_invitation','auth_organization_role','auth_two_factor','jwks']);
const enums = new Set(['customer_type_enum','customer_status_enum','curator_status_enum','organization_status_enum']);
const statements = source.split(';').map(statement => statement.trim()).filter(statement => {
 const type = statement.match(/^CREATE TYPE (\w+) AS ENUM/);
 if (type) return enums.has(type[1]);
 const table = statement.match(/^(?:CREATE TABLE|ALTER TABLE ONLY) (\w+)/);
 if (table) return tables.has(table[1]);
 const index = statement.match(/^CREATE (?:UNIQUE )?INDEX \w+ ON (\w+)/);
 return index && tables.has(index[1]);
});
for (const table of tables) if (!statements.some(statement => statement.startsWith('CREATE TABLE '+table+' ('))) throw new Error('Missing table: '+table);
for (const name of enums) if (!statements.some(statement => statement.startsWith('CREATE TYPE '+name+' AS ENUM'))) throw new Error('Missing enum: '+name);
// File-service rows are outside the auth contract. Preserve their auth-side FKs
// against an explicit minimal referenced table, rather than silently dropping FKs.
const output = '-- Extracted verbatim from Brand Map migration; see brand-map-schema.json.\n' +
 '-- Requires PostgreSQL 18 (uuidv7). The file-service table below is a fixture stub.\n' +
 'CREATE TABLE file (id uuid PRIMARY KEY);\n\n' + statements.join(';\n\n') + ';\n';
mkdirSync('tests/fixtures', {recursive:true});
writeFileSync('tests/fixtures/brand-map-schema.sql', output);
writeFileSync('tests/fixtures/brand-map-schema.json', JSON.stringify({
 source:path, sha256:createHash('sha256').update(source).digest('hex'),
 tables:[...tables], enums:[...enums], statements:statements.length,
 adaptations:['Auth-side statements copied verbatim; unrelated tables excluded.', 'Referenced file-service table represented by an id-only fixture stub.', 'Search path supplied by the disposable database fixture; UUIDv7 defaults preserved.'],
}, null, 2)+'\n');

const configPaths = ['platform/services/auth/src/create-auth.ts','packages/organization-permissions/src/exports.ts'];
const bindings = new Map();
const sources = configPaths.map(path => {
 const text=readFileSync(resolve(root,path),'utf8');
 const file=ts.createSourceFile(path,text,ts.ScriptTarget.Latest,true);
 const visit=node=>{if(ts.isVariableDeclaration(node)&&ts.isIdentifier(node.name)&&node.initializer)bindings.set(node.name.text,node.initializer);ts.forEachChild(node,visit)};
 visit(file);return {path,sha256:createHash('sha256').update(text).digest('hex')};
});
function literal(node) {
 if(ts.isAsExpression(node)||ts.isSatisfiesExpression(node))return literal(node.expression);
 if(ts.isStringLiteral(node))return node.text;
 if(ts.isArrayLiteralExpression(node))return node.elements.map(literal);
 if(ts.isObjectLiteralExpression(node))return Object.fromEntries(node.properties.map(property=>{
  if(!ts.isPropertyAssignment(property))throw new Error('Expected literal property');
  return [property.name.text,literal(property.initializer)];
 }));
 if(ts.isIdentifier(node)&&bindings.has(node.text))return literal(bindings.get(node.text));
 if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)){
  if(node.expression.text==='createAllStoreRolePermissions')return complete(literal(bindings.get('storeRolePermissionStatements')));
  if(node.expression.text==='createOrganizationRolePermission')return complete(literal(node.arguments[0]));
  if(node.expression.text==='createReadOnlyOrganizationPermissions')return complete(Object.fromEntries(Object.entries(literal(bindings.get('storeRolePermissionStatements'))).filter(([resource,actions])=>!['apiKey','organization'].includes(resource)&&actions.includes('read')).map(([resource])=>[resource,['read']])));
 }
 throw new Error('Unsupported configuration expression: '+node.getText());
}
function complete(input){const store=literal(bindings.get('storeRolePermissionStatements'));return Object.fromEntries(Object.keys(literal(bindings.get('organizationPermissionStatements'))).map(resource=>[resource,(input[resource]??[]).filter(action=>store[resource]?.includes(action))]))}
writeFileSync('tests/fixtures/brand-map-config.json',JSON.stringify({sources,fields:literal(bindings.get('fields')),statements:literal(bindings.get('organizationPermissionStatements')),roles:literal(bindings.get('organizationRolePermissions'))},null,2)+'\n');
