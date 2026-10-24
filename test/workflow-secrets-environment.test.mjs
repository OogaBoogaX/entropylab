// Audit SC-1: repository secrets are readable by any job a collaborator's
// branch can run. Every job that reads a secret other than the per-run
// GITHUB_TOKEN must instead take it from the `release` Environment, whose
// deployment-branch policy admits only rock. A textual guard cannot parse
// YAML, but it fails the moment a secret-reading job loses its environment.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflowsDir = join(root, ".github/workflows");
const workflows = readdirSync(workflowsDir)
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => ({ name, text: readFileSync(join(workflowsDir, name), "utf8") }));

// Each top-level job under `jobs:` as { job, block }.
const jobsOf = (text) => {
  const body = text.split(/^jobs:\n/m)[1] ?? "";
  return [...body.matchAll(/^ {2}([a-z0-9_-]+):\n([\s\S]*?)(?=^ {2}[a-z0-9_-]+:\n|(?![\s\S]))/gm)].map(
    ([, job, block]) => ({ job, block }),
  );
};

const secretsRead = (block) =>
  [...block.matchAll(/secrets\.([A-Z0-9_]+)/g)].map(([, name]) => name).filter((name) => name !== "GITHUB_TOKEN");

const secretJobs = workflows.flatMap(({ name, text }) =>
  jobsOf(text)
    .map(({ job, block }) => ({ workflow: name, job, block, secrets: secretsRead(block) }))
    .filter(({ secrets }) => secrets.length > 0),
);

test("the guard sees the secret-reading jobs it is meant to cover", () => {
  const found = secretJobs.map(({ workflow, job }) => `${workflow}:${job}`).sort();
  // The OTS client no longer shares a job with the push token: the secret
  // moved to the *-push jobs, so the guard must see those instead.
  for (const expected of [
    "ci-cd.yml:artifact",
    "ci-cd.yml:timestamp-push",
    "jev-adversarial.yml:adversarial",
    "ots-upgrade.yml:upgrade-push",
    "translate.yml:publish",
    "translate.yml:translate",
  ]) {
    assert.ok(found.includes(expected), `${expected} reads a secret and must be covered`);
  }
});

test("every job that reads a repository secret runs in the release environment", () => {
  for (const { workflow, job, block, secrets } of secretJobs) {
    assert.match(
      block,
      /^ {4}environment: release$/m,
      `${workflow}:${job} reads ${secrets.join(", ")} outside the release environment`,
    );
  }
});

test("no job holding the release environment can run on a pull request", () => {
  for (const { workflow, job, block } of secretJobs) {
    const { text } = workflows.find(({ name }) => name === workflow);
    const on = text.match(/^on:\n([\s\S]*?)^\S/m)?.[1] ?? "";
    assert.ok(!/^ {2}pull_request_target:/m.test(on), `${workflow} must not use pull_request_target`);
    if (/^ {2}pull_request:/m.test(on)) {
      assert.match(
        block,
        /^ {4}if: .*github\.event_name == 'push'/m,
        `${workflow}:${job} must be gated off pull_request events`,
      );
    }
  }
});
