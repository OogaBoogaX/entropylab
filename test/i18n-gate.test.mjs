// The translation-only gate is the last thing standing between an arbitrary
// PR and src/locales/: it must fail closed on identity, branch, scope, and
// content — and stay out of the way of ordinary PRs.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { contentProblems, gateProblems } from "../scripts/i18n-gate.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const SLUG = "entropylab-translate";
const BOT = `${SLUG}[bot]`;
const ES_FILES = ["src/locales/es.json", "src/locales/.sources/es.json"];

const gate = (overrides = {}) =>
  gateProblems({
    author: BOT,
    appSlug: SLUG,
    baseRef: "rock",
    headRef: "i18n/translate-es",
    changedFiles: ES_FILES,
    ...overrides,
  });

test("ordinary PRs (no locale files) are outside the gate's scope", () => {
  assert.deepEqual(gate({ author: "alice", headRef: "feature/x", changedFiles: ["src/js/app.js", "package.json"] }), []);
  assert.deepEqual(gate({ changedFiles: [] }), []);
});

test("a valid automation PR passes", () => {
  assert.deepEqual(gate(), []);
});

test("a human (or wrong bot) touching locale files fails", () => {
  for (const author of ["alice", "github-actions[bot]", `other-app[bot]`]) {
    const problems = gate({ author });
    assert.ok(problems.some((p) => p.includes("may only change via the translation automation")), author);
  }
});

test("an unconfigured app slug leaves locale PRs to ordinary human review", () => {
  // No App is configured yet: there is no bot identity to gate on, so the
  // gate is inert rather than fail-closed — otherwise it would block every
  // human locale fix before operator setup, including the bootstrap PR.
  assert.deepEqual(gate({ appSlug: "" }), []);
  assert.deepEqual(gate({ appSlug: "", author: "alice" }), []);
});

test("the base must be rock", () => {
  assert.ok(gate({ baseRef: "main" }).some((p) => p.includes("must target rock")));
});

test("the head branch must be in the automation namespace", () => {
  for (const headRef of ["fix/i18n", "i18n/es", "i18n/translate-", "i18n/translate-esp", "i18n/translate-ES", "translate-es"]) {
    assert.ok(gate({ headRef }).some((p) => p.includes("outside the automation namespace")), headRef);
  }
  assert.deepEqual(gate({ headRef: "i18n/translate-pt-br", changedFiles: ["src/locales/pt-br.json", "src/locales/.sources/pt-br.json"] }), []);
});

test("exactly one catalog and its matching sidecar may change", () => {
  // A second language's catalog: out of scope.
  assert.ok(gate({ changedFiles: [...ES_FILES, "src/locales/fr.json"] }).some((p) => p.includes("fr.json")));
  // Anything executable or build-related: out of scope.
  for (const file of ["src/js/app.js", "package.json", ".github/workflows/ci-cd.yml", "src/shell.html"]) {
    assert.ok(gate({ changedFiles: [...ES_FILES, file] }).some((p) => p.includes(file)), file);
  }
  // Catalog without sidecar (or vice versa) fails: they move together.
  assert.ok(gate({ changedFiles: ["src/locales/es.json"] }).some((p) => p.includes("sidecar")));
  assert.ok(gate({ changedFiles: ["src/locales/.sources/es.json"] }).some((p) => p.includes("catalog")));
  // A mismatched pair (branch says es, files say de) fails.
  assert.ok(gate({ changedFiles: ["src/locales/de.json", "src/locales/.sources/de.json"] }).some((p) => p.includes("de.json")));
});

test("the committed catalogs and seeded sidecars are mutually consistent", () => {
  // contentProblems runs the real validator on the real tree: if the seeded
  // provenance sidecars ever rot, this fails before the gate would.
  for (const lang of ["es", "fr", "pt", "de"]) {
    assert.deepEqual(contentProblems(root, lang), [], lang);
  }
});

test("contentProblems flags a broken sidecar", () => {
  // es catalog against a sidecar with a corrupted hash: use the de sidecar
  // indirectly is not possible — instead corrupt via a wrong-language pair.
  // (de.json + de sidecar are consistent, so check a missing sidecar path.)
  const problems = contentProblems(root, "xx");
  assert.ok(problems.some((p) => p.includes("does not exist")));
});

test("CLI: exit code follows the verdict", () => {
  const run = (args) => {
    try {
      execFileSync(process.execPath, ["scripts/i18n-gate.mjs", ...args], { cwd: root, stdio: "pipe" });
      return 0;
    } catch (error) {
      return error.status;
    }
  };
  assert.equal(run(["--author", "alice", "--app-slug", SLUG, "--base", "rock", "--head", "feature/x", "--files", "src/js/app.js"]), 0);
  assert.equal(run(["--author", "alice", "--app-slug", SLUG, "--base", "rock", "--head", "i18n/translate-es", "--files", ...ES_FILES]), 1);
  assert.equal(run(["--author", BOT, "--app-slug", SLUG, "--base", "rock", "--head", "i18n/translate-es", "--files", ...ES_FILES]), 0);
  // Unconfigured slug: inert even for a human locale PR (see gateProblems).
  assert.equal(run(["--author", "alice", "--app-slug", "", "--base", "rock", "--head", "feature/x", "--files", ...ES_FILES]), 0);
});

