// The footer build stamp: the page closes with the version, the short commit
// hash and a LifeHash of the commit, so any downloaded copy identifies the
// exact source revision it was built from. The build stamps the tokens
// (the last commit that changed a build input, "unknown" without git
// metadata; build-commit.test.mjs owns which commit); the app renders the
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
  assert.match(read("scripts/build-commit.mjs"), /return "unknown";/);
  assert.match(build, /!\/\^\(\?:\[0-9a-f\]\{40\}\|unknown\)\$\/\.test\(commit\)/);
  assert.match(build, /\.split\("\{\{COMMIT\}\}"\)\.join\(commit\)/);
  assert.match(build, /\.split\("\{\{COMMIT_SHORT\}\}"\)\.join\(commit === "unknown" \? "unknown" : commit\.slice\(0, 7\)\)/);
  // The leftover-token guard must know the new tokens, or an unstamped
  // footer would ship silently.
  assert.match(build, /\{\{\(\?:VERSION\|PWA_VERSION\|COMMIT\|COMMIT_SHORT\)\}\}/);
});

test("a push build fails if the page did not stamp a source commit", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const build = workflow.match(/^  build:\n[\s\S]*?(?=^  [\w-]+:)/m)?.[0] ?? "";
  // "unknown" means a build input was dirty in CI; a release must never ship it.
  assert.match(build, /name: Check the footer stamped a source commit\n\s+if: github\.event_name == 'push'\n\s+run: grep -q 'data-commit="\[0-9a-f\]\\\{40\\\}"' entropylab\.html/);
});

test("both footers carry the build stamp and the LifeHash target", () => {
  for (const markup of [read("src/shell.html")]) {
    assert.match(markup, /<span class="page-footer-build">v\{\{VERSION\}\} · commit <code>\{\{COMMIT_SHORT\}\}<\/code> <img class="page-footer-lifehash" id="page-footer-lifehash" data-commit="\{\{COMMIT\}\}" width="20" height="20" src="data:[^"]*" alt="LifeHash of the build commit" hidden><\/span>/);
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


test("a release refuses a -dev page, and its check matches the real footer", () => {
  // #1406: a published release never says -dev. The check is a grep in
  // release-assets.yml; if the footer markup moved, the grep would stop
  // matching and pass every page. So run its exact pattern against the
  // shell's own footer, stamped both ways (round-1 review: DeepSeek, GLM,
  // Kimi and MiniMax).
  const workflow = read(".github/workflows/release-assets.yml");
  const check = workflow.match(/if grep -q '([^']+)' entropylab\.html; then\n[^\n]*::error title=Development version::[^\n]*\n\s*exit 1/);
  assert.ok(check, "release-assets.yml has no failing -dev check on entropylab.html");
  const pattern = new RegExp(check[1]);
  const footer = read("src/shell.html").split("\n").find((line) => line.includes('class="page-footer-build"'));
  assert.ok(footer?.includes("v{{VERSION}} "), "the footer no longer stamps v{{VERSION}} followed by a space");
  const stamp = (version) => footer.split("{{VERSION}}").join(version).split("{{COMMIT_SHORT}}").join("abc1234").split("{{COMMIT}}").join("a".repeat(40));
  assert.match(stamp("1.1.0-dev"), pattern, "a -dev page passes the release check");
  assert.doesNotMatch(stamp("1.1.0"), pattern, "a release page fails the release check");
  assert.doesNotMatch(stamp("1.1.0-rc1"), pattern, "a release candidate is not a -dev build");
});
