// CI completeness guard: every test suite in test/ must actually run in CI.
//
// `npm test` globs test/*.test.mjs, but CI runs the explicit file list in the
// test:ci script (plus the browser suites via test:browser). A suite that is
// added to the repo but never listed there passes locally and silently never
// gates a pull request. This check is the non-WASM analogue of the WASM gate
// in validate.test.mjs: it diffs the directory against the wiring and fails
// on any orphan or stale entry.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const pkg = JSON.parse(read("package.json"));
const workflow = read(".github/workflows/ci-cd.yml");

// Suites that launch a real browser have their own CI job and script: the
// test-browser job prepares the runner for headless Chromium (sandbox opt-out,
// the runner's broken Edge removed) and the dependency-free test:ci gate does
// neither. Every other suite must ride the test:ci gate.
const BROWSER_SUITES = Object.freeze(["test/browser.test.mjs", "test/residue-browser.test.mjs"]);

const suitesIn = (script) => [...String(script ?? "").matchAll(/test\/[\w.-]+\.test\.mjs/g)].map((match) => match[0]);

// Returns every way the CI wiring is incomplete, so the same check can be
// exercised against doctored inputs below. A guard that cannot fail is not a
// guard.
function ciCoverageProblems(testCiScript, testBrowserScript, workflowText, filesOnDisk) {
  const problems = [];
  const wired = suitesIn(testCiScript);
  const wiredSet = new Set(wired);
  for (const file of filesOnDisk) {
    if (BROWSER_SUITES.includes(file)) continue;
    if (!wiredSet.has(file)) problems.push(`${file} is on disk but never runs in CI (missing from the test:ci script)`);
  }
  for (const name of wiredSet) {
    if (!filesOnDisk.includes(name)) problems.push(`the test:ci script references ${name}, which does not exist`);
    if (BROWSER_SUITES.includes(name)) problems.push(`${name} launches a browser; run it in test:browser, not the dependency-free test:ci gate`);
  }
  for (const name of wired) {
    if (wired.indexOf(name) !== wired.lastIndexOf(name)) problems.push(`the test:ci script runs ${name} twice`);
  }
  const browserSuites = BROWSER_SUITES.filter((suite) => filesOnDisk.includes(suite));
  for (const suite of browserSuites) {
    if (!suitesIn(testBrowserScript).includes(suite)) problems.push(`the test:browser script must run ${suite}`);
  }
  if (browserSuites.length) {
    const job = workflowText.match(/^  test-browser:\n(?:.|\n)*?(?=^  [a-z-]+:|\Z)/m)?.[0] ?? "";
    if (!job) problems.push("the test-browser CI job is missing");
    else if (!/npm run test:browser/.test(job)) problems.push("the test-browser CI job does not run the browser suites");
  }
  const gate = workflowText.match(/^  test-ci:\n(?:.|\n)*?(?=^  [a-z-]+:|\Z)/m)?.[0] ?? "";
  if (!gate) problems.push("the test-ci CI job is missing");
  else if (!/npm run test:ci/.test(gate)) problems.push("the test-ci CI job does not run npm run test:ci");
  return problems;
}

// CI checks out the tracked tree, so the guard compares the wiring against
// the tracked suites: an untracked work-in-progress suite on a developer
// machine is not CI's concern until it is added to the index.
const filesOnDisk = execFileSync("git", ["ls-files", "test/*.test.mjs"], { cwd: root, encoding: "utf8" })
  .split("\n")
  .filter(Boolean)
  .sort();

test("every test suite is wired into CI", () => {
  assert.ok(filesOnDisk.length > 30, `expected the test suite barrage, found ${filesOnDisk.length} suites`);
  assert.deepEqual(ciCoverageProblems(pkg.scripts["test:ci"], pkg.scripts["test:browser"], workflow, filesOnDisk), []);
});

test("npm test runs the full directory so local runs match CI", () => {
  assert.equal(pkg.scripts.test, "node --test test/*.test.mjs", "the test script must glob every suite in test/");
});

test("the CI completeness guard detects its own failure modes", () => {
  const script = pkg.scripts["test:ci"];
  const victim = suitesIn(script).find((name) => !BROWSER_SUITES.includes(name));
  assert.ok(victim, "fixture: test:ci lists at least one suite");
  const dropped = script.replace(` ${victim}`, "");
  assert.notEqual(dropped, script, "fixture: the suite name must appear in the script");
  assert.ok(
    ciCoverageProblems(dropped, pkg.scripts["test:browser"], workflow, filesOnDisk).some((problem) => problem.includes(victim)),
    "dropping a suite from test:ci must be detected",
  );
  const stale = `${script} test/no-such-suite.test.mjs`;
  assert.ok(
    ciCoverageProblems(stale, pkg.scripts["test:browser"], workflow, filesOnDisk).some((problem) => problem.includes("no-such-suite")),
    "a stale test:ci entry must be detected",
  );
  const doubled = `${script} ${victim}`;
  assert.ok(
    ciCoverageProblems(doubled, pkg.scripts["test:browser"], workflow, filesOnDisk).some((problem) => problem.includes("twice")),
    "a duplicate test:ci entry must be detected",
  );
  const browserScript = pkg.scripts["test:browser"];
  for (const suite of BROWSER_SUITES) {
    assert.ok(filesOnDisk.includes(suite), `fixture: ${suite} is tracked`);
    assert.ok(
      ciCoverageProblems(`${script} ${suite}`, browserScript, workflow, filesOnDisk).some((problem) => problem.includes(suite) && problem.includes("launches a browser")),
      `${suite} in the dependency-free test:ci gate must be detected`,
    );
    const unwired = browserScript.replace(` ${suite}`, "").replace(`${suite} `, "");
    assert.notEqual(unwired, browserScript, `fixture: test:browser runs ${suite}`);
    assert.ok(
      ciCoverageProblems(script, unwired, workflow, filesOnDisk).some((problem) => problem.includes(`must run ${suite}`)),
      `dropping ${suite} from test:browser must be detected`,
    );
  }
  const noBrowser = workflow.replace("npm run test:browser", "npm run test:network");
  assert.notEqual(noBrowser, workflow, "fixture: the test-browser job must run the browser suites");
  assert.ok(
    ciCoverageProblems(script, browserScript, noBrowser, filesOnDisk).some((problem) => problem.includes("test-browser")),
    "a test-browser job that stops running the browser suites must be detected",
  );
  const noGate = workflow.replace("npm run test:ci", "npm run test:network");
  assert.notEqual(noGate, workflow, "fixture: the test-ci job must run test:ci");
  assert.ok(
    ciCoverageProblems(script, pkg.scripts["test:browser"], noGate, filesOnDisk).some((problem) => problem.includes("test-ci")),
    "a test-ci job that stops running test:ci must be detected",
  );
});
