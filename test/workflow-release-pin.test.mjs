// Issue #1406: production (entropylab.online) must show only the latest
// published, non-prerelease signed release, and a merge to rock must never
// change it. A separate -dev preview site is built from rock. These are
// text-level guards in the style of workflow-ots-supply-chain.test.mjs: they
// cannot parse YAML, but they fail the moment any of these lines move.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");

const workflows = readdirSync(join(root, ".github/workflows"))
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => ({ name, text: read(`.github/workflows/${name}`) }));

const jobBlock = (workflow, name) =>
  workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [a-z0-9_-]+:\\n|(?![\\s\\S]))`, "m"))?.[0] ?? "";
const steps = (job) => job.split(/^ {6}- /m).slice(1);

const pagesRelease = read(".github/workflows/pages-release.yml");
const cicd = read(".github/workflows/ci-cd.yml");
const releaseAssets = read(".github/workflows/release-assets.yml");

test("only pages-release.yml deploys GitHub Pages", () => {
  for (const { name, text } of workflows) {
    if (name === "pages-release.yml") continue;
    assert.doesNotMatch(text, /actions\/deploy-pages@/, `${name} must not deploy GitHub Pages`);
    assert.doesNotMatch(text, /^\s*name: github-pages\s*$/m, `${name} must not hold the github-pages environment`);
    assert.doesNotMatch(text, /^\s*environment: github-pages\s*$/m, `${name} must not hold the github-pages environment`);
  }
});

test("pages-release.yml runs only on a published release", () => {
  const on = pagesRelease.match(/^on:\n([\s\S]*?)^\S/m)?.[1] ?? "";
  assert.match(on, /^ {2}release:\n {4}types: \[published\]$/m, "the only trigger is a published release");
  assert.doesNotMatch(on, /^ {2}(push|pull_request|pull_request_target|workflow_dispatch|schedule):/m, "no other trigger may deploy production");
});

test("pages-release.yml refuses prereleases and drafts", () => {
  assert.ok(
    pagesRelease.includes("github.event.release.prerelease == false && github.event.release.draft == false"),
    "the job condition must exclude prereleases and drafts",
  );
});

test("pages-release.yml never builds the app and reads no repository secret", () => {
  assert.doesNotMatch(pagesRelease, /\bnpm\b/, "the release deploy must not run npm");
  assert.doesNotMatch(pagesRelease, /node scripts\/build/, "the release deploy must not run the build");
  assert.doesNotMatch(pagesRelease, /secrets\./, "the release deploy uses only github.token");
});

test("every check runs before the Pages artifact is uploaded, and the deploy is last", () => {
  const verify = jobBlock(pagesRelease, "verify");
  assert.ok(verify, "the verify job exists");
  const all = steps(verify);
  const index = (needle) => all.findIndex((step) => step.includes(needle));
  const upload = index("actions/upload-pages-artifact@");
  assert.ok(upload > 0, "the verify job uploads the Pages artifact");
  for (const [label, needle] of [
    ["checksum", "sha256sum -c SHA256SUMS.txt"],
    ["gpg status", "--status-fd 1 --verify"],
    ["footer", "scripts/release-footer.mjs"],
    ["service worker", "{{PWA_VERSION}}"],
  ]) {
    const at = index(needle);
    assert.ok(at >= 0, `the ${label} step exists`);
    assert.ok(at < upload, `the ${label} check runs before the artifact is uploaded`);
  }
  const deploy = jobBlock(pagesRelease, "deploy");
  assert.match(deploy, /^ {4}needs: \[verify, ots\]$/m, "the deploy waits for the asset checks and the timestamp check");
  const deploySteps = steps(deploy);
  assert.equal(deploySteps.length, 1, "the deploy job runs one step");
  assert.match(deploySteps[0], /actions\/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346/, "the deploy is the pinned deploy-pages action");
  assert.ok(
    pagesRelease.indexOf("actions/deploy-pages@") > pagesRelease.indexOf("actions/upload-pages-artifact@"),
    "the deploy comes after the upload",
  );
});

// The OpenTimestamps client is third-party code the repo treats as hostile
// (workflow-ots-supply-chain.test.mjs): a step boundary is not isolation, so
// it must never run in the job that assembles the bytes production serves.
test("the OpenTimestamps client runs in its own job, never beside the Pages artifact", () => {
  const verify = jobBlock(pagesRelease, "verify");
  assert.doesNotMatch(verify, /ots-requirements\.txt|\/ots\/bin\//, "the verify job neither installs nor runs the client");
  const ots = jobBlock(pagesRelease, "ots");
  assert.ok(ots, "an ots job exists");
  assert.match(ots, /^ {4}needs: \[verify\]$/m, "it starts after verify has uploaded the artifact");
  assert.ok(ots.includes('ots" info entropylab.html.ots'), "it reads the proof");
  assert.ok(ots.includes("EXPECTED: ${{ needs.verify.outputs.html-sha256 }}"), "it checks the proof against the digest verify confirmed");
  assert.ok(ots.includes("--pattern entropylab.html.ots"), "it downloads only the proof, never the HTML");
  assert.doesNotMatch(ots, /upload-pages-artifact|deploy-pages|environment:/, "it cannot publish anything");
  assert.match(jobBlock(pagesRelease, "verify"), /html-sha256=\$\(sha256sum entropylab\.html/, "verify passes on the digest of the bytes it checked");
});

test("a revoked or expired key, or an expired signature, never counts toward min-signers", () => {
  const verify = jobBlock(pagesRelease, "verify");
  assert.ok(verify.includes('$2 == "REVKEYSIG" || $2 == "EXPKEYSIG" || $2 == "EXPSIG"'), "gpg's revoked-key, expired-key and expired-signature results are excluded");
  assert.ok(verify.includes(`$2 == "r" || $2 == "e"`), "a pub record that gpg marks revoked or expired is excluded");
  assert.ok(verify.includes('REVIEWED="$GITHUB_WORKSPACE/trust"'), "the default branch's reviewed copy is checked out");
  assert.ok(verify.includes('cmp -s "$TAGTREE/.github/release-signers.txt" "$REVIEWED/.github/release-signers.txt"'), "the tag's signer list must equal the reviewed one");
  assert.doesNotMatch(verify, /--import\s+"?KEYS/, "the release's KEYS asset is never imported");
});

test("pages-release.yml serialises production deploys", () => {
  assert.match(pagesRelease, /^concurrency:\n {2}group: pages-production\n {2}cancel-in-progress: false$/m);
});

// A fingerprint as SECURITY.md writes it: ten groups of four hex digits.
const FPR = /\b[0-9A-F]{4}(?: [0-9A-F]{4}){9}\b/g;

test("release-signers.txt matches the signer list in SECURITY.md", () => {
  const security = read("SECURITY.md");
  const section = security.match(/^## Release signing keys\n([\s\S]*?)(?=^## |(?![\s\S]))/m)?.[1] ?? "";
  assert.ok(section.length > 0, "SECURITY.md documents the release signing keys");
  const active = new Set();
  const revoked = new Set();
  for (const line of section.split("\n")) {
    for (const match of line.matchAll(FPR)) {
      (line.includes("revoked") ? revoked : active).add(match[0].replace(/ /g, ""));
    }
  }
  assert.ok(active.size >= 3, "SECURITY.md lists at least three active signers");
  assert.ok(revoked.size >= 1, "SECURITY.md marks the compromised key revoked");

  const signers = read(".github/release-signers.txt");
  const rows = signers.split("\n").filter((line) => line.trim() && !line.trim().startsWith("#"));
  const minLine = rows.find((line) => /^min-signers \d+$/.test(line.trim()));
  assert.ok(minLine, "release-signers.txt declares min-signers");
  const fileActive = new Set();
  const fileRevoked = new Set();
  for (const line of rows) {
    const match = line.trim().match(/^([0-9A-F]{40}) (\S+) (active|revoked)$/);
    if (!match) continue;
    (match[3] === "revoked" ? fileRevoked : fileActive).add(match[1]);
  }
  assert.deepEqual([...fileActive].sort(), [...active].sort(), "the active signers match SECURITY.md");
  assert.deepEqual([...fileRevoked].sort(), [...revoked].sort(), "the revoked signers match SECURITY.md");
  assert.equal(Number(minLine.trim().split(" ")[1]), 3, "the release needs three good signatures");
});

test("the preview job publishes rock to the preview repository only", () => {
  const job = jobBlock(cicd, "preview");
  assert.ok(job, "ci-cd.yml has a preview job");
  assert.match(job, /^ {4}if: github\.ref == 'refs\/heads\/rock' && github\.event_name == 'push'$/m, "push to rock only");
  assert.match(job, /^ {4}environment: release$/m, "it reads a secret, so it runs in the release environment");
  assert.match(job, /^ {4}concurrency:\n {6}group: pages-preview$/m, "its own concurrency group");
  const secrets = [...job.matchAll(/secrets\.([A-Z0-9_]+)/g)].map(([, name]) => name);
  assert.deepEqual([...new Set(secrets)], ["PREVIEW_DEPLOY_KEY"], "it reads only the preview deploy key");
  assert.ok(job.includes('echo "::notice title=Preview not deployed::PREVIEW_DEPLOY_KEY is not set"'), "an unset key skips with a notice");
  assert.ok(job.includes("StrictHostKeyChecking=yes"), "the host key is pinned");
  assert.ok(job.includes("IdentitiesOnly=yes"), "only the deploy key is offered");
  assert.ok(job.includes("git@github.com:OogaBoogaX/entropylab-preview.git"), "it targets the preview repository");
  assert.ok(job.includes("! -name CNAME"), "the CNAME is kept");
  assert.doesNotMatch(job, /--force/, "it never force-pushes");
  assert.doesNotMatch(job, /actions\/deploy-pages@/, "it does not deploy production");
});

test("release-assets.yml checks the footer against the tag", () => {
  const job = jobBlock(releaseAssets, "check");
  assert.ok(job, "the check job exists");
  assert.match(job, /fetch-depth: 0/, "the tag's history must be available");
  assert.match(job, /rev-parse "\$TAG\^\{commit\}"/, "the tag's commit is resolved");
  assert.match(job, /scripts\/release-footer\.mjs/, "the footer is read by the shared parser");
  assert.match(job, /TAG: \$\{\{ github\.event\.release\.tag_name \|\| inputs\.tag \}\}/, "the step knows the tag");
});
