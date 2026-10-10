// The commit the footer stamps: the most recent commit that changed a build
// input, not HEAD. A commit that touches none of them (docs, the changelog,
// release signatures) then leaves entropylab.html byte-identical, so the sums
// signed for a release stay valid once they land on rock instead of being
// invalidated by the very commit that adds the signatures.
//
// Every file scripts/build.mjs reads lives under one of these paths; the
// dependencies esbuild bundles (and esbuild itself) are pinned by
// package-lock.json.
import { execFileSync } from "node:child_process";

export const BUILD_INPUTS = [
  "src",
  "assets/favicon.png",
  "manifest.webmanifest",
  "package.json",
  "package-lock.json",
  "scripts/build.mjs",
  "scripts/build-commit.mjs",
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
  try {
    return git("log", "-1", "--format=%H", "--", ...BUILD_INPUTS) || "unknown";
  } catch {
    return "unknown";
  }
}
