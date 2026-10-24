// Audit SC-2: the timestamp, OTS upgrade and release-asset jobs install the
// OpenTimestamps client from PyPI. Pinning only the top-level package left its
// eight dependencies floating and nothing hash-checked, in jobs that also hold
// the release-push token. The install must take exactly the locked wheels or
// fail, and no step that runs the client may see the push token. A textual
// guard cannot parse YAML, but it fails the moment any of these lines move.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");
const lockPath = ".github/ots-requirements.txt";
const workflows = readdirSync(join(root, ".github/workflows"))
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => ({ name, text: read(`.github/workflows/${name}`) }));

const jobBlock = (workflow, name) =>
  workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [a-z0-9_-]+:\\n|(?![\\s\\S]))`, "m"))?.[0] ?? "";
const steps = (job) => job.split(/^ {6}- /m).slice(1);

// Each top-level job under `jobs:` as { job, block }.
const jobsOf = (text) => {
  const body = text.split(/^jobs:\n/m)[1] ?? "";
  return [...body.matchAll(/^ {2}([a-z0-9_-]+):\n([\s\S]*?)(?=^ {2}[a-z0-9_-]+:\n|(?![\s\S]))/gm)].map(
    ([, job, block]) => ({ job, block }),
  );
};

// The two workflows that push a proof (the OTS client runs in a third,
// release-assets.yml, whose job holds no secret; see the guard below).
const otsWorkflows = ["ci-cd.yml", "ots-upgrade.yml"].map((name) => ({
  name,
  text: read(`.github/workflows/${name}`),
}));

// A job "runs the OTS client" when it creates the venv, invokes the binary or
// installs the wheels.
const runsOtsClient = (block) => /\$RUNNER_TEMP\/ots|\$OTS\b|\bpip3?"? install\b/.test(block);

// opentimestamps-client 0.7.2's dependency closure, from the requires_dist
// metadata PyPI publishes for it and for each dependency in turn.
const closure = [
  "opentimestamps-client",
  "opentimestamps",
  "python-bitcoinlib",
  "pycryptodomex",
  "GitPython",
  "gitdb",
  "smmap",
  "PySocks",
  "appdirs",
];

const lockEntries = () =>
  read(lockPath)
    .replace(/\\\n\s*/g, " ")
    .split("\n")
    .filter((line) => line.trim() && !line.trim().startsWith("#"));

test("the OTS lock pins every package of the client's closure by version and wheel hash", () => {
  const entries = lockEntries();
  const names = [];
  for (const entry of entries) {
    const match = entry.match(/^([A-Za-z0-9._-]+)==([0-9][0-9A-Za-z.]*)((?: +--hash=sha256:[0-9a-f]{64})+)\s*$/);
    assert.ok(match, `${entry} must be name==version with sha256 hashes and nothing else`);
    names.push(match[1].toLowerCase());
  }
  assert.ok(entries.some((entry) => entry.startsWith("opentimestamps-client==0.7.2 ")), "the client stays at 0.7.2");
  assert.deepEqual([...names].sort(), closure.map((name) => name.toLowerCase()).sort(), "the lock is exactly the closure");
});

test("every pip install in CI takes only the hash-locked OTS wheels", () => {
  let installs = 0;
  for (const { name, text } of workflows) {
    for (const [line] of text.matchAll(/^.*\bpip3?"? install\b.*$/gm)) {
      installs += 1;
      for (const flag of ["--require-hashes", "--no-deps", "--only-binary :all:", `-r "$GITHUB_WORKSPACE/${lockPath}"`]) {
        assert.ok(line.includes(flag), `${name}: ${line.trim()} lacks ${flag}`);
      }
      assert.doesNotMatch(line, /==/, `${name}: pins belong in ${lockPath}, not on the command line`);
    }
  }
  assert.equal(installs, 3, "the timestamp, upgrade and release-asset jobs each install the client once");
});

// The old guard checked that the push was a later *step* of the same job. A
// step boundary is not isolation: the client can write .git/hooks/pre-push or
// leave a background process in the workspace the push token later enters.
// The client and the token must live in different jobs on different runners.
// Every workflow, not only the two that push a proof: release-assets.yml runs
// the client too, and so would any workflow added later.
test("no job that installs or runs the OTS client can reach a secret or the release environment", () => {
  const clientJobs = [];
  for (const { name, text } of workflows) {
    for (const { job, block } of jobsOf(text).filter(({ block }) => runsOtsClient(block))) {
      clientJobs.push(`${name}:${job}`);
      assert.doesNotMatch(block, /^ {4}environment:/m, `${name}:${job} runs the OTS client and must not hold an environment`);
      assert.doesNotMatch(block, /secrets\./, `${name}:${job} runs the OTS client and must not read a secret`);
      assert.doesNotMatch(block, /PUSH_TOKEN/, `${name}:${job} runs the OTS client and must not hold the push token`);
    }
  }
  assert.deepEqual(
    clientJobs.sort(),
    ["ci-cd.yml:timestamp", "ots-upgrade.yml:upgrade", "release-assets.yml:check"],
    "the timestamp, upgrade and release-asset jobs are the only ones that run the client",
  );
});

test("no job that holds the push token or the release environment runs the OTS client", () => {
  for (const { name, text } of otsWorkflows) {
    const jobs = jobsOf(text).filter(({ block }) => /PUSH_TOKEN|^ {4}environment: release$/m.test(block));
    assert.ok(jobs.length > 0, `${name} has a job that pushes the proof`);
    for (const { job, block } of jobs) {
      assert.doesNotMatch(
        block,
        /\$RUNNER_TEMP\/ots|\$OTS\b|\bpip3?"? install\b/,
        `${name}:${job} holds the push token and must not install or run the OTS client`,
      );
    }
  }
});

test("the push job validates the proof and pushes with hooks disabled and an explicit refspec", () => {
  for (const [file, job] of [
    ["ci-cd.yml", "timestamp-push"],
    ["ots-upgrade.yml", "upgrade-push"],
  ]) {
    const block = jobBlock(read(`.github/workflows/${file}`), job);
    assert.ok(block, `${file}:${job} exists`);
    const all = steps(block);
    const checkout = all.find((step) => step.includes("actions/checkout@"));
    assert.match(checkout, /persist-credentials: false/, `${file}:${job} must not leave GITHUB_TOKEN in .git/config`);
    const validate = all.find((step) => step.includes("stat -c %s"));
    assert.ok(validate, `${file}:${job} validates the proof size`);
    assert.match(validate, /65536/, "the size limit is enforced");
    assert.match(
      validate,
      /004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108/,
      "the 31-byte magic, major version 1 and the SHA-256 op tag are pinned",
    );
    assert.match(validate, /head -c 33/, "the header is read");
    assert.match(validate, /head -c 65/, "the digest is read");
    assert.match(validate, /tail -c 32/, "the digest is the 32 bytes after the header");
    // The push job checks rock out after the OTS job finished: the proof must
    // cover the HTML rock carries now, not only the digest the run expected.
    assert.match(validate, /sha256sum entropylab\.html/, `${file}:${job} compares the proof with rock's entropylab.html`);
    const commit = all.find((step) => step.includes("git commit"));
    assert.ok(commit, `${file}:${job} commits the proof`);
    assert.ok(all.indexOf(validate) < all.indexOf(commit), "validation runs before the commit");
    assert.match(commit, /git add entropylab\.html\.ots\n/, "only the proof is staged");
    assert.match(commit, /rev-list --count origin\/rock\.\.HEAD/, "exactly one commit may be ahead of rock");
    assert.match(commit, /diff --name-only origin\/rock\.\.HEAD/, "that commit may change only the proof");
    const push = all.find((step) => step.includes("push origin HEAD:rock"));
    assert.ok(push, `${file}:${job} pushes the explicit refspec HEAD:rock`);
    assert.ok(all.indexOf(commit) < all.indexOf(push), "the push comes after the checked commit");
    // "Already on rock" exits 0 without a commit; the push must not run then.
    assert.match(commit, /^ {8}id: proof$/m, `${file}:${job} names the commit step`);
    assert.ok(
      commit.lastIndexOf('echo "committed=true" >> "$GITHUB_OUTPUT"') > commit.lastIndexOf("diff --name-only origin/rock..HEAD"),
      "committed=true is set only after the one-commit and proof-only checks",
    );
    assert.match(push, /^ {8}if: steps\.proof\.outputs\.committed == 'true'$/m, `${file}:${job} pushes only after a checked commit`);
    assert.match(push, /core\.hooksPath=\/dev\/null/, "hooks are disabled for the push");
    assert.match(push, /^ {8}env:\n {10}PUSH_TOKEN: \$\{\{ secrets\.RELEASE_PUSH_TOKEN \}\}$/m, "the token arrives through env, not inlined into the script");
    assert.doesNotMatch(push.split(/\n {8}run: /)[1] ?? "", /\$\{\{/, "the push script has no expression substitution");
    assert.equal(all.filter((step) => step.includes("secrets.RELEASE_PUSH_TOKEN")).length, 1, `${file}:${job} reads the token in exactly one step`);
  }
});

test("the upgrade job binds the committed proof to rock's entropylab.html digest (audit L8)", () => {
  // ots-upgrade upgrades and republishes whatever proof sits on rock. Without
  // a digest check, a proof left on rock for bytes the tree no longer carries
  // (an admin push, a reverted stamp commit) would be upgraded into a full
  // Bitcoin attestation of the wrong artifact; only release-assets.yml would
  // notice, at release time. The stamp job already compares digests the same
  // way before deciding to re-stamp (ci-cd.yml, timestamp job).
  const block = jobBlock(read(".github/workflows/ots-upgrade.yml"), "upgrade");
  assert.ok(block, "ots-upgrade.yml:upgrade exists");
  const upgrade = steps(block).find((step) => step.includes('"$OTS" upgrade'));
  assert.ok(upgrade, "the upgrade step exists");
  assert.match(upgrade, /sha256sum entropylab\.html/, "the checkout's HTML digest must be computed");
  assert.match(upgrade, /"\$OTS" info entropylab\.html\.ots/, "the committed proof's digest must be read");
  assert.match(upgrade, /if \[ "\$EXISTING" != "\$ACTUAL" \]/, "a digest mismatch must be refused before any upgrade");
});

test("the upgrade push refuses a proof that drops or changes a Bitcoin attestation of the committed one", () => {
  // DeepSeek's red-team of #1047 (OTS-2): the untrusted client could hand
  // back a fresh pending proof for the same digest, which passes the header
  // and digest checks and would replace a completed Bitcoin attestation.
  const block = jobBlock(read(".github/workflows/ots-upgrade.yml"), "upgrade-push");
  const all = steps(block);
  const validate = all.find((step) => step.includes("stat -c %s"));
  assert.match(
    validate,
    /if ! python3 scripts\/ots-attestations\.py --preserves entropylab\.html\.ots "\$PROOF"; then\n\s+echo "::error::[^"]*"\n\s+exit 1/,
    "the committed proof's attestations must all survive in the upload, or the job fails",
  );
  assert.match(validate, /^ {10}set -euo pipefail$/m, "a malformed proof (the counter exits 1) fails the job");
  assert.ok(all.indexOf(validate) < all.findIndex((step) => step.includes("git commit")), "before the commit");
});

test("the attestation counter walks the proof structure", (t) => {
  // Crafted proofs with counts worked out by hand; the script also gives 0
  // for rock's pending proof and 3 for the upgraded proof of 27362f2. The
  // tag's bytes inside an append argument (DeepSeek's red-team of 2e213f0)
  // are not an attestation.
  const script = join(root, "scripts", "ots-attestations.py");
  const python = ["python3", "python"].find((name) => !spawnSync(name, ["--version"]).error);
  if (!python) return t.skip("python is not available");
  const run = (...proofs) => {
    const dir = mkdtempSync(join(tmpdir(), "ots-"));
    const files = proofs.map((bytes, index) => {
      const file = join(dir, `p${index}.ots`);
      writeFileSync(file, Buffer.from(bytes));
      return file;
    });
    const result = spawnSync(python, [script, ...(files.length === 2 ? ["--preserves", ...files] : files)]);
    rmSync(dir, { recursive: true, force: true });
    return result.status === 0 ? Number(String(result.stdout).trim()) : `exit ${result.status}`;
  };
  const count = (bytes) => run(bytes);
  const varbytes = (bytes) => [bytes.length, ...bytes];
  const BTC = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
  const PENDING = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
  const header = [0x00, ...Buffer.from("OpenTimestamps"), 0x00, 0x00, ...Buffer.from("Proof"), 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08, ...new Array(32).fill(0x11)];
  const pending = [0x00, ...PENDING, ...varbytes([...Buffer.from("https://a.pool.opentimestamps.org")])];
  assert.equal(count([...header, ...pending]), 0, "a pending-only proof");
  // fork: an attestation, then append -> sha256 -> attestation
  assert.equal(count([...header, 0xff, 0x00, ...BTC, ...varbytes([0x01]), 0xf0, ...varbytes([0xaa]), 0x08, 0x00, ...BTC, ...varbytes([0x02])]), 2, "two attestations on two branches");
  assert.equal(count([...header, 0xf0, ...varbytes([...BTC, 0x78]), ...pending]), 0, "the tag inside an op argument is not an attestation");
  assert.equal(count([...header, ...pending.slice(0, 20)]), "exit 1", "a truncated proof is refused");
  assert.equal(count([...header, ...pending, 0x00]), "exit 1", "trailing bytes are refused");
  assert.equal(count([...header.slice(0, 32), 0x09, ...header.slice(33), ...pending]), "exit 1", "a proof whose file hash is not SHA-256 is refused");
  assert.equal(count([...header, 0x99, ...pending]), "exit 1", "an unknown op is refused");
});

test("the preserve check passes an upgrade that adds and refuses one that drops or swaps an attestation", (t) => {
  // DeepSeek's red-team of #1047 (7da47ea): a count cannot tell a real
  // attestation from a fake, so the guard requires every attestation of the
  // committed proof (op path and payload) to survive. The same rule on the
  // repository's own upgraded proof (27362f2): unchanged passes, one height
  // byte changed (still 3 attestations) fails, rock's pending proof as the
  // upload fails.
  const script = join(root, "scripts", "ots-attestations.py");
  const python = ["python3", "python"].find((name) => !spawnSync(name, ["--version"]).error);
  if (!python) return t.skip("python is not available");
  const preserves = (committed, upgraded) => {
    const dir = mkdtempSync(join(tmpdir(), "ots-"));
    const [a, b] = [committed, upgraded].map((bytes, index) => {
      const file = join(dir, `p${index}.ots`);
      writeFileSync(file, Buffer.from(bytes));
      return file;
    });
    const result = spawnSync(python, [script, "--preserves", a, b]);
    rmSync(dir, { recursive: true, force: true });
    return result.status;
  };
  const varbytes = (bytes) => [bytes.length, ...bytes];
  const BTC = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
  const PENDING = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
  const header = [0x00, ...Buffer.from("OpenTimestamps"), 0x00, 0x00, ...Buffer.from("Proof"), 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08, ...new Array(32).fill(0x11)];
  const attest = (height) => [0x00, ...BTC, ...varbytes([height])];
  const pending = [0x00, ...PENDING, ...varbytes([...Buffer.from("https://a.pool.opentimestamps.org")])];
  // Two attestations on two branches: append 0xaa -> sha256 -> att(1); sha256 -> att(2).
  const two = [...header, 0xff, 0xf0, ...varbytes([0xaa]), 0x08, ...attest(1), 0x08, ...attest(2)];
  const three = [...header, 0xff, 0xf0, ...varbytes([0xaa]), 0x08, ...attest(1), 0xff, 0x08, ...attest(2), 0xf1, ...varbytes([0xbb]), 0x08, ...attest(3)];
  assert.equal(preserves(two, two), 0, "unchanged");
  assert.equal(preserves(two, three), 0, "an added attestation");
  assert.equal(preserves([...header, ...pending], two), 1, "an upgrade that drops the pending calendar entry (ots upgrade keeps it)");
  assert.equal(preserves(two, [...header, ...pending]), 1, "a completed proof swapped for a pending one");
  // Pending calendar attestations are preserved too (DeepSeek red-team of
  // cf1a3c2): a pending proof cannot be traded for one that points at
  // other calendars, while a real upgrade keeps them beside the new ones.
  const otherCalendar = [0x00, ...PENDING, ...varbytes([...Buffer.from("https://attacker.example.org")])];
  assert.equal(preserves([...header, ...pending], [...header, ...otherCalendar]), 1, "a pending proof swapped for one at another calendar");
  assert.equal(preserves([...header, ...pending], [...header, 0xff, ...pending, 0x08, ...attest(5)]), 0, "a pending proof upgraded, keeping its calendar entry");
  assert.equal(preserves(two, [...header, 0xff, 0xf0, ...varbytes([0xaa]), 0x08, ...attest(1), 0x08, ...attest(9)]), 1, "one attestation swapped, same count");
  assert.equal(preserves(two, [...header, 0xff, 0xf0, ...varbytes([0xab]), 0x08, ...attest(1), 0x08, ...attest(2)]), 1, "an attestation moved to another op path");
  assert.equal(preserves(two, [...header, 0x99]), 1, "a malformed upload");
});

test("timestamp-push walks the proof and never replaces a proof on rock that already covers this HTML", () => {
  // Reviews of #1047 (a9ff8d7): Muse Spark and GLM 5.3 (no structural check
  // after byte 65), Nemotron 3 Ultra (a delayed push could replace a proof
  // that ots-upgrade had completed since).
  const all = steps(jobBlock(read(".github/workflows/ci-cd.yml"), "timestamp-push"));
  const validate = all.find((step) => step.includes("stat -c %s"));
  assert.match(validate, /if ! python3 scripts\/ots-attestations\.py "\$PROOF" > \/dev\/null; then\n\s+echo "::error::[^"]*"\n\s+exit 1/, "the stamped proof is walked");
  const commit = all.find((step) => step.includes("git commit"));
  assert.match(commit, /^ {8}env:\n {10}EXPECTED: \$\{\{ needs\.build\.outputs\.sha256 \}\}$/m, "the commit step knows the tested digest");
  const keep = commit.indexOf('= "$EXPECTED" ]'), copy = commit.indexOf('cp "$RUNNER_TEMP/entropylab.html.ots"');
  assert.ok(keep > 0 && keep < copy, "a proof on rock covering the tested digest is kept, checked before the copy");
  assert.match(commit.slice(keep, copy), /exit 0\n/, "and the step ends without committing (no committed=true, so no push)");
  assert.match(commit.slice(keep, keep + 140), /= "\$EXPECTED" \] && python3 scripts\/ots-attestations\.py entropylab\.html\.ots > \/dev\/null 2>&1; then/, "only a well-formed proof on rock is kept (DeepSeek red-team of cf1a3c2)");
});

test("the attestation walker refuses the same op twice at one node", (t) => {
  const script = join(root, "scripts", "ots-attestations.py");
  const python = ["python3", "python"].find((name) => !spawnSync(name, ["--version"]).error);
  if (!python) return t.skip("python is not available");
  const header = [0x00, ...Buffer.from("OpenTimestamps"), 0x00, 0x00, ...Buffer.from("Proof"), 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08, ...new Array(32).fill(0x11)];
  const BTC = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
  const status = (bytes) => {
    const dir = mkdtempSync(join(tmpdir(), "ots-"));
    const file = join(dir, "p.ots");
    writeFileSync(file, Buffer.from(bytes));
    const result = spawnSync(python, [script, file]);
    rmSync(dir, { recursive: true, force: true });
    return result.status;
  };
  const att = (height) => [0x00, ...BTC, 1, height];
  assert.equal(status([...header, 0xff, 0x08, ...att(1), 0x08, ...att(2)]), 1, "sha256 twice at one node");
  assert.equal(status([...header, 0xff, 0xf0, 1, 0xaa, ...att(1), 0xf0, 1, 0xaa, ...att(2)]), 1, "the same append twice at one node");
  assert.equal(status([...header, 0xff, 0xf0, 1, 0xaa, ...att(1), 0xf0, 1, 0xbb, ...att(2)]), 0, "two different appends at one node");
  assert.equal(status([...header, 0x08, 0x08, ...att(1)]), 0, "sha256 under sha256 (different nodes)");
});

test("the proof push survives a rock that moved: bounded retry, re-checked commit, no force", () => {
  // Rock CI run 39990729021: the translation bot pushed between the job's
  // fetch and its push, so the proof push was rejected and the run went red
  // although the site had built and deployed. A moved rock is re-fetched and
  // the proof rebased and re-checked, a bounded number of times.
  const all = steps(jobBlock(read(".github/workflows/ci-cd.yml"), "timestamp-push"));
  const push = all.find((step) => step.includes("push origin HEAD:rock"));
  assert.ok(push, "the push step exists");
  // Bounded retry: a fixed number of retries, then a clear error.
  assert.match(push, /^ {10}MAX_RETRIES=3$/m, "the retry is bounded");
  assert.match(
    push,
    /if \[ "\$attempt" -ge "\$MAX_RETRIES" \]; then\n\s+echo "::error::[^"]*"\n\s+exit 1/,
    "exhausting the retries is an error, not a silent success",
  );
  // Only a rejected push is retried; an auth or network error fails at once.
  assert.match(push, /grep -Eq '[^']*rejected[^']*'/, "only a rejected push is retried");
  assert.match(push, /echo "::error::pushing the proof failed for a reason other than a moved rock"/, "any other push error fails at once");
  // A moved rock is fetched again and its HTML digest read from the ref, not
  // from the working tree (which is the rock this job started from).
  assert.match(push, /git fetch --quiet origin rock/, "the moved rock is fetched again");
  assert.match(push, /git show origin\/rock:entropylab\.html \| sha256sum/, "the digest comes from origin/rock");
  // A newer site build supersedes this proof: push nothing, exit 0.
  assert.match(
    push,
    /if \[ "\$ON_ROCK" != "\$EXPECTED" \]; then\n\s+echo "[^"]*superseded[^"]*"\n\s+exit 0/,
    "a superseded proof exits 0 without pushing",
  );
  // A well-formed proof already on rock is kept, as in "Commit the proof".
  assert.match(push, /git show origin\/rock:entropylab\.html\.ots/, "rock's proof is read from the ref");
  assert.match(push, /python3 "\$WALKER" "\$RUNNER_TEMP\/rock\.ots"/, "the same attestation walk decides");
  // The single proof commit is replayed, then the same two checks run.
  assert.match(push, /git -c core\.hooksPath=\/dev\/null rebase origin\/rock/, "the proof commit is rebased with hooks disabled");
  const rebase = push.indexOf("rebase origin/rock");
  assert.ok(push.indexOf("rev-list --count origin/rock..HEAD", rebase) > rebase, "one commit ahead is re-checked after the rebase");
  assert.ok(push.indexOf("diff --name-only origin/rock..HEAD", rebase) > rebase, "the proof-only rule is re-checked after the rebase");
  // Never force-push, and never push anything but the one proof commit.
  assert.doesNotMatch(push, /--force|force-with-lease|\+HEAD:rock/, "no force push");
  assert.doesNotMatch(push, /push\s+-f\b/, "no short force flag");
});

test("the proof push re-checks the rebased proof's blob, annotates a superseded or kept proof, retries only a moved rock and masks the auth header", () => {
  // Round 2 of #1127: the retry loop re-checked the commit's shape but not the
  // proof's bytes, so a rebase that resolved a conflict could push a proof
  // this job never validated; a green run that pushed nothing said so only in
  // the log; "cannot lock ref" is a local lock error, not a moved rock; and
  // the base64 auth header was never masked.
  const all = steps(jobBlock(read(".github/workflows/ci-cd.yml"), "timestamp-push"));
  const push = all.find((step) => step.includes("push origin HEAD:rock"));
  assert.ok(push, "the push step exists");
  // 1. The validated proof's blob id is recorded before the loop, and every
  //    rebase must replay exactly those bytes.
  const blob = push.indexOf("PROOF_BLOB=$(git rev-parse HEAD:entropylab.html.ots)");
  assert.ok(blob > 0, "the validated proof's blob id is recorded");
  assert.ok(blob < push.indexOf("while :; do"), "before the retry loop");
  const rebase = push.indexOf("rebase origin/rock");
  assert.ok(
    push.indexOf('if [ "$(git rev-parse HEAD:entropylab.html.ots)" != "$PROOF_BLOB" ]; then', rebase) > rebase,
    "the rebased proof must be the validated blob",
  );
  assert.match(
    push,
    /if \[ "\$\(git rev-parse HEAD:entropylab\.html\.ots\)" != "\$PROOF_BLOB" \]; then\n\s+echo "::error::[^"]*differs from the validated[^"]*"\n\s+exit 1/,
    "a rebased proof that differs from the validated one fails",
  );
  // 2. A green run that pushed nothing says why, as an annotation.
  assert.match(
    push,
    /echo "::notice title=Proof superseded::[^"]*superseded[^"]*"/,
    "a superseded proof is annotated",
  );
  assert.match(
    push,
    /echo "::notice title=Proof kept::[^"]*"/,
    "a kept proof on rock is annotated",
  );
  // 3. Only a moved rock is retried; a local lock error fails at once.
  assert.doesNotMatch(push, /cannot lock ref/, "a local lock error is not a moved rock");
  assert.match(push, /grep -Eq '[^']*rejected[^']*'/, "only a rejected push is retried");
  // 4. The base64 auth header is masked before any push.
  const auth = push.indexOf("AUTH_B64=$(echo -n x-access-token:$PUSH_TOKEN | base64)");
  const mask = push.indexOf('echo "::add-mask::$AUTH_B64"');
  assert.ok(auth > 0, "the base64 value is computed once");
  assert.ok(mask > auth, "the base64 value is masked");
  assert.ok(mask < push.indexOf("while :; do"), "before any push");
  assert.match(push, /AUTHORIZATION: basic \$AUTH_B64/, "the header uses the variable");
  assert.doesNotMatch(push, /AUTHORIZATION: basic \$\(echo -n x-access-token:\$PUSH_TOKEN \| base64\)/, "the header is not recomputed inline");
});
