import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";

const lock = JSON.parse(readFileSync("upstream.lock.json", "utf8"));
const archive = resolve(".upstream/source.tar.gz");
const destination = resolve(".upstream/better-auth");
mkdirSync(".upstream", { recursive: true });
if (!existsSync(archive)) {
  const response = await fetch(lock.archiveUrl, {
    signal: AbortSignal.timeout(90000),
  });
  if (!response.ok)
    throw new Error(`Source download failed: ${response.status}`);
  writeFileSync(
    archive + ".part",
    new Uint8Array(await response.arrayBuffer()),
  );
  renameSync(archive + ".part", archive);
}
const digest = createHash("sha256").update(readFileSync(archive)).digest("hex");
if (digest !== lock.archiveSha256)
  throw new Error(
    "Upstream source archive checksum does not match upstream.lock.json",
  );
// Extraction is isolated; an existing working source tree is never overwritten.
if (!existsSync(destination)) {
  execFileSync("tar", ["-xzf", archive, "-C", resolve(".upstream")]);
  renameSync(resolve(`.upstream/better-auth-${lock.commit}`), destination);
  writeFileSync(resolve(destination, ".source-commit"), lock.commit + "\n");
}
const marker = resolve(destination, ".source-commit");
if (
  !existsSync(marker) ||
  readFileSync(marker, "utf8").trim() !== lock.commit
) {
  throw new Error(
    "Existing source tree does not have the expected commit marker",
  );
}
rmSync(archive + ".part", { force: true });
console.log(`Verified upstream source ${lock.commit} at ${destination}`);
