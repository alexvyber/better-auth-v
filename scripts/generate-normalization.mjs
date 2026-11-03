import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const directory = resolve(process.argv[2] ?? ".upstream/unicode17");
const names = [
  "UnicodeData.txt",
  "DerivedNormalizationProps.txt",
  "NormalizationTest.txt",
];
const sources = Object.fromEntries(
  names.map((name) => [name, readFileSync(resolve(directory, name), "utf8")]),
);
if (
  !sources["DerivedNormalizationProps.txt"].includes(
    "DerivedNormalizationProps-17.0.0.txt",
  )
)
  throw new Error("Expected Unicode 17.0.0 data");
const excluded = new Set();
for (const line of sources["DerivedNormalizationProps.txt"].split("\n")) {
  const [range, property] = line
    .split("#")[0]
    .split(";")
    .map((value) => value.trim());
  if (property !== "Full_Composition_Exclusion") continue;
  const [first, last = first] = range
    .split("..")
    .map((value) => parseInt(value, 16));
  for (let codepoint = first; codepoint <= last; codepoint++)
    excluded.add(codepoint);
}
const records = [];
let decompositionCount = 0,
  combiningCount = 0,
  compositionCount = 0;
for (const line of sources["UnicodeData.txt"].split("\n")) {
  if (!line) continue;
  const fields = line.split(";");
  const codepoint = parseInt(fields[0], 16);
  const combiningClass = Number(fields[3]);
  if (combiningClass) {
    records.push(`C;${fields[0]};${combiningClass}`);
    combiningCount++;
  }
  const raw = fields[5];
  if (!raw) continue;
  const decomposition = raw.replace(/^<[^>]+>\s*/, "").split(" ");
  records.push(`D;${fields[0]};${decomposition.join(" ")}`);
  decompositionCount++;
  if (
    !raw.startsWith("<") &&
    decomposition.length === 2 &&
    !excluded.has(codepoint)
  ) {
    records.push(`P;${decomposition[0]};${decomposition[1]};${fields[0]}`);
    compositionCount++;
  }
}
const vectors = sources["NormalizationTest.txt"]
  .split("\n")
  .map((line) => line.split("#")[0].trim())
  .filter((line) => line && !line.startsWith("@"))
  .map((line) =>
    line
      .split(";")
      .slice(0, 5)
      .map((value) => value.trim())
      .join(";"),
  );
mkdirSync("normalization/data", { recursive: true });
writeFileSync("normalization/data/tables.txt", records.join("\n") + "\n");
writeFileSync("normalization/data/conformance.txt", vectors.join("\n") + "\n");
writeFileSync(
  "normalization/data/manifest.json",
  JSON.stringify(
    {
      version: "17.0.0",
      algorithm:
        "UAX #15 NFKC (compatibility decomposition, canonical ordering, canonical composition)",
      decompositionCount,
      combiningCount,
      compositionCount,
      conformanceVectors: vectors.length,
      sources: names.map((name) => ({
        url: `https://www.unicode.org/Public/17.0.0/ucd/${name}`,
        sha256: createHash("sha256").update(sources[name]).digest("hex"),
      })),
    },
    null,
    2,
  ) + "\n",
);
console.log(
  `Generated ${records.length} table records and ${vectors.length} Unicode NFKC conformance vectors.`,
);
