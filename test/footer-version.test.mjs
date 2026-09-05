// The footer build stamp: the page closes with the version, the short commit
// hash and a LifeHash of the commit, so any downloaded copy identifies the
// exact source revision it was built from. The build stamps the tokens
// (git rev-parse HEAD, "unknown" without git metadata); the app renders the
// LifeHash at boot from the stamped data-commit. The ui-defaults suite owns
// the footer markup shape; this suite owns the stamping and wiring.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("the build stamps the commit tokens from git, with a snapshot fallback", () => {
  const build = read("scripts/build.mjs");
  assert.match(build, /execFileSync\("git", \["rev-parse", "HEAD"\]/);
  assert.match(build, /return "unknown";/);
  assert.match(build, /!\/\^\(\?:\[0-9a-f\]\{40\}\|unknown\)\$\/\.test\(commit\)/);
  assert.match(build, /\.split\("\{\{COMMIT\}\}"\)\.join\(commit\)/);
  assert.match(build, /\.split\("\{\{COMMIT_SHORT\}\}"\)\.join\(commit === "unknown" \? "unknown" : commit\.slice\(0, 7\)\)/);
  // The leftover-token guard must know the new tokens, or an unstamped
  // footer would ship silently.
  assert.match(build, /\{\{\(\?:VERSION\|PWA_VERSION\|COMMIT\|COMMIT_SHORT\)\}\}/);
});

test("both footers carry the build stamp and the LifeHash target", () => {
  for (const markup of [read("src/shell.html")]) {
    assert.match(markup, /<span class="page-footer-build">v\{\{VERSION\}\} · commit <code>\{\{COMMIT_SHORT\}\}<\/code> <img class="page-footer-lifehash" id="page-footer-lifehash" data-commit="\{\{COMMIT\}\}" width="20" height="20" alt="LifeHash of the build commit" hidden><\/span>/);
  }
});

test("the app renders the commit LifeHash on page load, only for a real commit", () => {
  const app = read("src/js/app.js");
  assert.match(app, /function hodlInitFooterBuild\(\)/);
  // On window load, not boot: the WASM-ready boot can run before the later
  // classic script tags (lifehash.js included) execute.
  assert.match(app, /addEventListener\("load", hodlInitFooterBuild\)/);
  assert.doesNotMatch(app, /hodlInitSegmentedControls\(\);\s*\n\s*hodlInitFooterBuild\(\)/);
  // The 40-hex guard keeps "unknown" snapshot builds image-less.
  assert.match(app, /!\/\^\[0-9a-f\]\{40\}\$\/\.test\(commit\)\) return;/);
  assert.match(app, /hodlLifeHash\s*\n?\s*\.fromFingerprint\(commit\)/);
});

test("the footer LifeHash is styled as an inline identicon", () => {
  const css = read("src/css/styles.css");
  assert.match(css, /\.page-footer-lifehash \{[^}]*border-radius: 3px;/);
  assert.match(css, /\.page-footer-build code \{ font-family: var\(--mono\); \}/);
});
