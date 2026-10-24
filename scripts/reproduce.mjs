// Reproducibility check for the site build: builds the working tree twice,
// from two differently shaped directory layouts, and requires byte-identical
// output. A build that embeds its own source path (or any other property of
// the staging location) fails here before it ships.
//
// Each stage is a copy of the working tree — not a git archive — so the check
// covers the tree as it stands, committed or not. The copies carry no .git,
// so both stamp the footer's "unknown" snapshot fallback; the commit-stamped
// path is covered by the CI reproduce job, which compares a runner build
// against a build inside the pinned dev image at the same commit.
//
// What the build consumes is copied; everything else is excluded:
// .git, node_modules (symlinked back instead), the crates' target/ dirs,
// _site/, .cache, and the generated root-level artifacts a previous build
// may have left behind.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const SKIP_DIR = new Set([".git", "node_modules", "target", "_site", ".cache"]);
const SKIP_ROOT_FILE = (name) =>
  /^entropylab(?:-\d+(?:\.\d+)*)?\.html$/.test(name) ||
  ["service-worker.js", "SHA256SUMS.txt", "WASM-SHA256SUMS.txt", "CID.txt", "versions.json"].includes(name);

const filter = (src) => {
  const parts = relative(root, src).split(sep);
  if (!parts[0]) return true;
  if (parts.some((part) => SKIP_DIR.has(part))) return false;
  return parts.length > 1 || !SKIP_ROOT_FILE(parts[0]);
};

if (!existsSync(join(root, "node_modules", "esbuild"))) {
  throw new Error("node_modules is missing esbuild — run `npm ci` first");
}

const stage = (dir) => {
  cpSync(root, dir, { recursive: true, filter });
  // "junction" needs no privilege on Windows and is a plain symlink elsewhere.
  symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "junction");
  execFileSync(process.execPath, [join(dir, "scripts", "build.mjs")], { stdio: "inherit" });
};

const digest = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

// Two path shapes, one shallow and one deep, so a leaked absolute path or a
// length-dependent layout shows up as a digest mismatch.
const work = mkdtempSync(join(tmpdir(), "entropylab-repro-"));
const dirs = [join(work, "a"), join(work, "nested", "deeper", "b")];
try {
  for (const dir of dirs) stage(dir);
  let failed = false;
  for (const name of ["entropylab.html", "service-worker.js"]) {
    const digests = dirs.map((dir) => digest(join(dir, name)));
    const bytes = readFileSync(join(dirs[0], name)).length;
    const match = digests[0] === digests[1];
    console.log(`${match ? "match" : "MISMATCH"}  ${name} (${bytes} bytes)`);
    console.log(`  ${digests[0]}  ${dirs[0]}`);
    console.log(`  ${digests[1]}  ${dirs[1]}`);
    if (!match) failed = true;
  }
  if (failed) {
    console.error("Reproducibility check FAILED: the build depends on its staging path.");
    process.exitCode = 1;
  } else {
    console.log("Reproducible: two builds from different paths are byte-identical.");
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
