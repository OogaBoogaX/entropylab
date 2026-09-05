// Static checks on the translation automation wiring (issue #286). The
// workflow's security boundaries are declared in YAML — the LLM secret must
// never reach the write-capable job, the App token must never reach the
// LLM-calling job, every action must stay SHA-pinned, and the gate must be
// part of the PR checks. A textual guard cannot parse YAML, but it fails the
// moment any of these lines move, which is exactly the review signal wanted.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");

const translate = read(".github/workflows/translate.yml");
const cicd = read(".github/workflows/ci-cd.yml");

// JavaScript has no \Z: end-of-input is (?![\s\S]).
const jobBlock = (workflow, name) =>
  workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [a-z-]+:|(?![\\s\\S]))`, "m"))?.[0] ?? "";

test("the translate workflow is a post-merge side loop with three triggers", () => {
  assert.match(translate, /^name: Translation automation$/m);
  assert.match(translate, /^on:\n {2}push:\n {4}branches: \[rock\]\n {4}paths:/m);
  assert.ok(translate.includes('"src/locales/**"'), "locale merges retrigger the loop");
  assert.match(translate, /schedule:\n( {4}#.*\n)? {4}- cron: "/, "weekly catch-up");
  assert.match(translate, /workflow_dispatch:/);
  assert.match(translate, /^permissions:\n {2}contents: read$/m, "default token is read-only");
});

test("every action used by the automation is pinned to a full commit SHA", () => {
  for (const uses of translate.matchAll(/uses: ([^ ]+)/g)) {
    assert.match(uses[1], /@[0-9a-f]{40}$/, `${uses[1]} is not SHA-pinned`);
  }
});

test("job A holds the LLM secret but no write access and no App token", () => {
  const job = jobBlock(translate, "translate");
  assert.ok(job, "translate job exists");
  assert.match(job, /permissions:\n {6}contents: read/);
  assert.ok(job.includes("secrets.TRANSLATE_API_KEY"), "the LLM key lives here");
  assert.ok(!job.includes("create-github-app-token"), "job A must not mint App tokens");
  assert.ok(!job.includes("TRANSLATION_APP_PRIVATE_KEY"));
  assert.ok(job.includes("i18n-translate.mjs"), "runs the generator");
  assert.ok(job.includes("i18n-validate.mjs"), "and validates before upload");
});

test("job B holds the App token but never the LLM secret, and revalidates", () => {
  const job = jobBlock(translate, "publish");
  assert.ok(job, "publish job exists");
  assert.match(job, /needs: \[translate\]/);
  assert.ok(job.includes("create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"), "pinned App-token action");
  assert.ok(job.includes("secrets.TRANSLATION_APP_PRIVATE_KEY"));
  assert.ok(!job.includes("TRANSLATE_API_KEY"), "the LLM secret never crosses into the write-capable job");
  assert.ok(job.includes("i18n-publish.mjs"), "runs the publisher");
  assert.ok(job.indexOf("i18n-validate.mjs") < job.indexOf("i18n-publish.mjs"), "revalidation precedes publishing");
});

test("the translation gate is part of the PR checks in ci-cd.yml", () => {
  const job = jobBlock(cicd, "translation-gate");
  assert.ok(job, "translation-gate job exists");
  assert.ok(job.includes("pull_request"), "PR-only");
  assert.ok(job.includes("i18n-gate.mjs"), "runs the gate");
  assert.ok(job.includes("github.event.pull_request.user.login"), "checks the App identity");
  assert.ok(job.includes("vars.TRANSLATION_APP_SLUG"), "configured slug");
  assert.ok(job.includes("git diff --name-only"), "scopes the changed files");
});

test("the operator runbook documents the App, secrets, label, and branch protection", () => {
  const doc = "docs/Translation_Automation_Setup.md";
  assert.ok(existsSync(join(root, doc)), `${doc} exists`);
  const text = read(doc);
  for (const needle of [
    "TRANSLATION_APP_ID",
    "TRANSLATION_APP_PRIVATE_KEY",
    "TRANSLATION_APP_SLUG",
    "TRANSLATE_API_KEY",
    "TRANSLATE_MODEL",
    "translation-automated",
    "auto-merge",
    "translation-gate",
  ]) {
    assert.ok(text.includes(needle), `${doc} documents ${needle}`);
  }
});

