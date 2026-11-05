const labelKey = entry => JSON.stringify([entry.suites ?? [entry.suite], entry.title ?? entry.test]);

// Source positions identify declarations independently of backend copies and
// repeated titles. A source checksum binds every import to the pinned contents.
export function sourceCoverage(sha256, declarations, manifests) {
 const byPosition = new Map(declarations.map(entry => [entry.sourceStart, entry]));
 const byLabel = new Map();
 for (const declaration of declarations) {
  const key = labelKey(declaration);
  const matches = byLabel.get(key) ?? [];
  matches.push(declaration); byLabel.set(key, matches);
 }
 const selected = new Set();
 for (const manifest of manifests) {
  if (manifest.sha256 !== sha256) throw new Error('Imported source file checksum mismatch');
  for (const record of manifest.tests) {
   let declaration;
   if (record.sourceStart !== undefined) {
    if (!Number.isInteger(record.sourceStart)) throw new Error('Invalid imported declaration position');
    declaration = byPosition.get(record.sourceStart);
    if (!declaration || labelKey(declaration) !== labelKey(record) || record.sourceLine !== undefined && record.sourceLine !== declaration.line) throw new Error('Imported declaration metadata does not match source');
   } else {
    // Old manifests without positions can only identify unambiguous labels.
    const candidates = byLabel.get(labelKey(record)) ?? [];
    if (candidates.length === 1) declaration = candidates[0];
   }
   if (record.selected && declaration) selected.add(declaration.sourceStart);
  }
 }
 return {
  status: manifests.length === 0 ? 'unported' : selected.size === declarations.length ? 'imported-complete-file' : 'imported-partial-file',
  importedDeclarations: selected.size,
  unportedDeclarations: declarations.length - selected.size,
 };
}
