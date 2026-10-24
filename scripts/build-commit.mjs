// The commit the footer stamps: the most recent commit that changed a build
// input, not HEAD. A commit that touches none of them (docs, the changelog,
// release signatures) then leaves entropylab.html byte-identical, so the sums
// signed for a release stay valid once they land on rock instead of being
// invalidated by the very commit that adds the signatures.
//
// Every file scripts/build.mjs reads lives under one of these paths; the
// dependencies esbuild bundles (and esbuild itself) are pinned by
// package-lock.json. The Rust crate sources are build inputs too: the WASM
// modules embedded in the page are compiled from them, even though the
// generated modules are committed separately by the artifact job.
import { execFileSync } from "node:child_process";

export const BUILD_INPUTS = [
  "src",
  "assets/favicon.png",
  "assets/favicon.svg",
  "assets/logo-dark.svg",
  "assets/logo-light.svg",
  "manifest.webmanifest",
  "package.json",
  "package-lock.json",
  "scripts/build.mjs",
  "scripts/build-commit.mjs",
  "entropylab-wasm",
  "psbt-wasm",
  "vanity-wasm",
];

// Generated from the Rust crates and committed by the post-merge artifact job.
// A commit that only refreshes these derived files must leave the footer's
// source-commit stamp where it is, or the published page stops being
// reproducible from the artifact commit that contains it.
export const GENERATED_WASM = [
  "src/js/entropylab-wasm-b64.js",
  "src/js/psbt-wasm-b64.js",
  "src/js/vanity-wasm-b64.js",
];

// Returns the commit id, or "unknown" for a snapshot without git metadata.
// Throws in a shallow clone: its oldest commit appears to add every file, so
// the lookup would name that commit instead of the real one.
export function buildCommit(root) {
  const git = (...args) =>
    execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  let shallow;
  try {
    shallow = git("rev-parse", "--is-shallow-repository");
  } catch {
    return "unknown";
  }
  if (shallow === "true") {
    throw new Error("Cannot resolve the build commit in a shallow clone: fetch the full history (actions/checkout fetch-depth: 0)");
  }
  // A dirty build input is not any commit: stamping the last committed one
  // would claim provenance the bytes do not have. Generated WASM modules are
  // excluded because CI deliberately refreshes them from the same sources.
  // Untracked files under a build input count as dirty too (an editor backup
  // under src/, say), so a local build with one stamps "unknown" — remove or
  // ignore the stray file and the stamp returns.
  let dirty;
  try {
    dirty = git("status", "--porcelain", "--", ...BUILD_INPUTS)
      .split("\n")
      .some((line) => line && !GENERATED_WASM.some((path) => line.endsWith(path)));
  } catch {
    return "unknown";
  }
  if (dirty) return "unknown";
  try {
    return git("log", "-1", "--format=%H", "--", ...BUILD_INPUTS, ...GENERATED_WASM.map((path) => `:(exclude)${path}`)) || "unknown";
  } catch {
    return "unknown";
  }
}
