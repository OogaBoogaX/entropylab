// Source validation and security invariants for the EntropyLab repository.
// Run with `npm run test:validate` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const pkg = JSON.parse(read("package.json"));
const appVersion = pkg.version;
const appFile = "entropylab.html";

// entropylab.html is a CI-generated artifact, not a committed source. Tests
// that read it require a fresh local build.
const ensureBuild = () => {
  if (!existsSync(join(root, appFile))) {
    execFileSync(process.execPath, [join(root, "scripts/build.mjs")], { stdio: "inherit" });
  }
};

const requiredFiles = [
  "README.md",
  "LICENSE",
  "package.json",
  "package-lock.json",
  "robots.txt",
  "sitemap.xml",
  "llms.txt",
  "assets/favicon.png",
  "assets/entropylab-darkmode.png",
  "assets/entropylab-social.png",
  "scripts/build.mjs",
  "scripts/cid.mjs",
  "scripts/verify-site.mjs",
  "test/validate.test.mjs",
  "test/browser.test.mjs",
  "test/browser-instrumentation.html",
  "test/browser-suite.html",
  "src/index.html",
  "src/shell.html",
  "src/assets/logo-dark.svg",
  "src/assets/logo-light.svg",
  "src/assets/favicon.svg",
  "src/css/styles.css",
  "src/js/app.js",
  "src/js/psbt-editor.js",
  "src/js/journal.js",
  "src/js/psbt-wasm.js",
  "src/js/psbt-wasm-b64.js",
  "src/js/bip85.js",
  "src/js/online.js",
  "src/js/network-check.js",
  "src/js/browser-check.js",
  "src/js/enhanced-inputs.js",
  "src/js/repeat-inputs.js",
  "src/js/sqlite-writer.js",
  "src/js/wallet-export.js",
  "src/js/core-importdescriptors.js",
  "src/js/msig-policy-sheet.js",
  "src/js/bip388-policy.js",
  "test/sqlite-writer.test.mjs",
  "test/wallet-export.test.mjs",
  "test/wallet-export-reference.mjs",
  "test/core-importdescriptors.test.mjs",
  "test/msig-policy-sheet.test.mjs",
  "test/bip388-policy.test.mjs",
  "test/browser-check.test.mjs",
  "test/psbt-metadata.test.mjs",
  "test/secret-clear.test.mjs",
  "test/cid.test.mjs",
  "test/journal.test.mjs",
  "test/wipe-wasm.test.mjs",
  ".github/workflows/ci-cd.yml",
];

for (const file of requiredFiles) {
  test(`${file} exists`, () => {
    const path = join(root, file);
    assert.ok(existsSync(path) && statSync(path).isFile(), `${file} is missing or not a file`);
  });
}

test("package.json declares a valid version and the expected scripts", () => {
  assert.match(appVersion, /^\d+(\.\d+)*$/, `invalid version: ${appVersion}`);
  for (const script of ["build", "clean", "test", "verify", "ci"]) {
    assert.equal(typeof pkg.scripts?.[script], "string", `package.json is missing the "${script}" script`);
  }
});

test("dependencies and build tooling are exactly locked", () => {
  assert.match(pkg.packageManager, /^npm@\d+\.\d+\.\d+$/);
  for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
    assert.match(version, /^\d+\.\d+\.\d+$/, `${name} must use an exact version`);
  }
  const lock = JSON.parse(read("package-lock.json"));
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages[""].dependencies, pkg.dependencies);
  assert.deepEqual(lock.packages[""].devDependencies, pkg.devDependencies);
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || entry.link) continue;
    assert.match(entry.integrity ?? "", /^sha512-/, `${path} has no SHA-512 package integrity`);
  }
  assert.equal(existsSync(join(root, "src/js/vendor.js")), false, "opaque vendor bundle must not return");
});

test("security-sensitive crypto libraries resolve to a single locked version", () => {
  // Duplicated @scure/@noble copies multiply the audit surface of key and
  // address encoding code and can drift apart unnoticed on lockfile
  // regeneration (issue #100). package.json pins one reviewed version with an
  // npm override; this test rejects any second copy anywhere in the tree.
  const lock = JSON.parse(read("package-lock.json"));
  const versions = new Map();
  for (const [path, entry] of Object.entries(lock.packages)) {
    const name = path.match(/(?:^|\/)node_modules\/(@(?:scure|noble)\/[^/]+)$/)?.[1];
    if (!name) continue;
    if (!versions.has(name)) versions.set(name, new Set());
    versions.get(name).add(entry.version);
  }
  assert.ok(versions.size > 0, "no @scure/@noble packages found in the lockfile");
  for (const [name, found] of versions) {
    assert.equal(found.size, 1, `${name} resolves to multiple locked versions: ${[...found].join(", ")}`);
  }
});

test("Node scripts and test files parse", () => {
  const nodeFiles = [
    "scripts/build.mjs",
    "scripts/cid.mjs",
    "scripts/verify-site.mjs",
    ...readdirSync(join(root, "test")).filter((name) => name.endsWith(".mjs")).map((name) => `test/${name}`),
  ];
  for (const file of nodeFiles) {
    execFileSync(process.execPath, ["--check", join(root, file)], { stdio: "pipe" });
  }
});

const readmeVersion = read("README.md").match(/^Current version: \*\*v([^*]*)\*\*$/m)?.[1] ?? "";

test("README version agrees with package.json", () => {
  assert.equal(readmeVersion, appVersion, `package.json: ${appVersion}; README: ${readmeVersion}`);
});

test("no versioned snapshots linger at the repository root", () => {
  const snapshots = readdirSync(root).filter((name) => /^entropylab-\d+(?:\.\d+)*\.html$/.test(name));
  assert.deepEqual(snapshots, [], `unexpected versioned snapshots: ${snapshots.join(", ")}`);
});

test("GitHub Pages aliases the canonical app at the site root only during deployment", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.equal(existsSync(join(root, "index.html")), false, "index.html should not be committed");
  assert.match(
    workflow,
    /^\s*cp entropylab\.html _site\/index\.html\s*$/m,
    "Pages staging must copy entropylab.html to its required index.html entry file",
  );
  assert.match(workflow, /^\s*branches: \[rock\]\s*$/m, "CI must run for pushes to the default branch");
  assert.match(
    workflow,
    /github\.ref == 'refs\/heads\/rock'/,
    "Pages deployment must be gated to the default branch",
  );
  assert.doesNotMatch(workflow, /refs\/heads\/main/, "workflow must not target the retired branch name");
});

test("the app never fetches, so the CSP forbids connections", () => {
  assert.match(read("src/index.html"), /connect-src 'none'/);
  // The secp256k1 WebAssembly module compiles inline; the CSP must allow it
  // (without 'wasm-unsafe-eval', Chrome/Safari refuse compilation).
  assert.match(read("src/index.html"), /script-src 'unsafe-inline' 'wasm-unsafe-eval'/);
  assert.doesNotMatch(read("src/js/online.js") + read("src/js/network-check.js") + read("src/js/browser-check.js"), /\bfetch\s*\(/);
});

test("the WASM boot chain has a failure path that kills the page", () => {
  const app = read("src/js/app.js");
  assert.match(
    app,
    /Promise\.all\(\[secp256k1Ready, hodlPsbtLoaded\]\)\s*\.then\(\(\[, psbtLoaded\]\) => hodlSelfTestGate\(document\.documentElement, hodlCurveFailure, psbtLoaded \? \[\.\.\.hodlSelfTests, \.\.\.hodlPsbtSelfTests\] : hodlSelfTests\) && hodlBoot\(\)\)\s*\.catch\(/,
    "app boot must catch secp256k1Ready rejection instead of leaving a dead page, and boot only after the known-answer self-test passes",
  );
  assert.match(app, /import \{ selfTestGate as hodlSelfTestGate, SELF_TESTS as hodlSelfTests, PSBT_SELF_TESTS as hodlPsbtSelfTests \} from "\.\/self-test\.js";/);
  // A PSBT module that fails to load must not kill boot (it never did: the
  // PSBT tools report it on use), so its readiness maps a rejection to false
  // rather than rejecting the chain; once loaded, its vectors join the gate.
  assert.match(app, /const hodlPsbtLoaded = psbtWasmReady\.then\(\(\) => true, \(\) => false\);/);
  // hodlBoot is declared once and called once, behind the gate: no second
  // path can wire inputs on a host that failed the self-test.
  assert.equal(app.match(/\bhodlBoot\(\)/g)?.length, 2, "hodlBoot must be declared once and called only behind the self-test gate");
  assert.match(app, /hodlCurveFailure/, "the boot rejection must render the sanity-failure kill screen");
  assert.match(app, /<tr><td>secp256k1 WebAssembly module<\/td><td>Failed<\/td><\/tr>/);
  assert.match(app, /Lockdown Mode block WebAssembly/);
  const check = read("src/js/browser-check.js");
  assert.match(check, /Lockdown Mode block WebAssembly/);
});

test("the release build attests the wallet artifact and ships a checksum manifest (issue #58)", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const build = workflow.match(/^  build:\n(?:.|\n)*?(?=^  [a-z-]+:)/m)?.[0] ?? "";
  // SHA256SUMS.txt names only the HTML, so `sha256sum -c` passes for someone
  // holding just the downloaded file. The modules get a manifest of their own.
  const wasmSums = /sha256sum \\\n\s+src\/js\/entropylab-wasm-b64\.js \\\n\s+src\/js\/psbt-wasm-b64\.js \\\n\s+src\/js\/vanity-wasm-b64\.js \\\n\s+> WASM-SHA256SUMS\.txt\n/;
  assert.match(build, /run: sha256sum entropylab\.html > SHA256SUMS\.txt\n/, "build must hash only the HTML into SHA256SUMS.txt");
  assert.match(build, wasmSums, "build must hash exactly the three WASM modules into WASM-SHA256SUMS.txt");
  assert.match(build, /name: entropylab-sha256sums\n\s+path: \|\n\s+SHA256SUMS\.txt\n\s+WASM-SHA256SUMS\.txt\n\s+CID\.txt\n/, "build must upload both manifests");
  assert.match(build, /node scripts\/cid\.mjs entropylab\.html > CID\.txt/, "build must generate CID.txt from the same HTML");
  assert.match(build, /actions\/attest-build-provenance@[0-9a-f]{40}/, "build must attest entropylab.html");
  assert.match(build, /subject-path: entropylab\.html/, "the attestation subject is the wallet HTML");
  assert.match(build, /attestations: write/, "attestation requires the attestations permission");
  // Only merges to the default branch produce release attestations.
  assert.match(build, /if: github\.ref == 'refs\/heads\/rock' && github\.event_name == 'push'\n\s*uses: actions\/attest-build-provenance/);
  const artifact = workflow.match(/^  artifact:\n(?:.|\n)*?(?=^  [a-z-]+:)/m)?.[0] ?? "";
  assert.match(artifact, /run: sha256sum entropylab\.html > SHA256SUMS\.txt\n/, "artifact must hash only the HTML into SHA256SUMS.txt");
  assert.match(artifact, wasmSums, "artifact must hash exactly the three WASM modules into WASM-SHA256SUMS.txt");
  const commitLine = artifact.match(/^\s+git add -f ([^\n]+)$/m)?.[1].split(/\s+/) ?? [];
  for (const file of ["entropylab.html", "SHA256SUMS.txt", "WASM-SHA256SUMS.txt", "CID.txt"]) {
    assert.ok(commitLine.includes(file), `the committed artifact includes ${file}`);
  }
  const readme = read("README.md");
  assert.match(readme, /^sha256sum -c SHA256SUMS\.txt$/m, "README verifies the download against the HTML-only manifest");
  assert.match(readme, /^sha256sum -c WASM-SHA256SUMS\.txt/m, "README shows how to check the committed WASM modules");
  assert.match(readme, /gh attestation verify entropylab\.html -R OogaBoogaX\/entropylab/);
  assert.match(read("README.md"), /ipfs block put --cid-codec=raw --allow-big-block/);
});

test("OpenTimestamps stamps the tested HTML off the Pages/test critical path", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const timestamp = workflowJob(workflow, "timestamp");
  assert.ok(timestamp, "timestamp job is missing");
  assert.match(timestamp, /ots stamp entropylab\.html/, "must stamp the candidate HTML");
  assert.match(timestamp, /--require-hashes --no-deps --only-binary :all: -r "\$GITHUB_WORKSPACE\/\.github\/ots-requirements\.txt"/, "install the hash-locked OTS client");
  assert.match(timestamp, /sha256sum -c -/, "must verify the candidate digest before stamping");
  assert.ok(jobNeeds(timestamp).includes("build"), "timestamp needs build (digest)");
  assert.ok(jobNeeds(timestamp).includes("artifact"), "timestamp runs after the HTML commit");
  assert.ok(!jobNeeds(workflowJob(workflow, "artifact")).includes("timestamp"), "calendars must not block the HTML commit");
  assert.ok(!jobNeeds(workflowJob(workflow, "deploy")).includes("timestamp"), "calendars must not block Pages");
  assert.doesNotMatch(timestamp, /npm run build/, "timestamp must not rebuild the wallet HTML");
  // `ots stamp` creates its output with an exclusive open, so a proof left
  // over from the previous release makes every later stamp fail.
  assert.match(timestamp, /rm -f entropylab\.html\.ots/, "stamp must clear a superseded proof first");
  const upgrade = read(".github/workflows/ots-upgrade.yml");
  assert.match(upgrade, /ots upgrade entropylab\.html\.ots/);
  // A still-pending proof exits non-zero; that is the normal state, not a
  // broken job.
  assert.match(upgrade, /if "\$OTS" upgrade entropylab\.html\.ots; then/, "a pending proof must not fail the upgrade job");
  assert.match(upgrade, /--require-hashes --no-deps --only-binary :all: -r "\$GITHUB_WORKSPACE\/\.github\/ots-requirements\.txt"/);
  assert.doesNotMatch(upgrade, /npm run build/);
  assert.doesNotMatch(upgrade, /SHA256SUMS\.txt/);
  assert.match(upgrade, /uses: actions\/checkout@[0-9a-f]{40}/, "upgrade workflow pins checkout");
  assert.match(read("README.md"), /ots verify entropylab\.html/);
  assert.match(read("README.md"), /pending/);
  assert.match(read("llms.txt"), /entropylab\.html\.ots/);
  assert.match(read("SECURITY.md"), /OpenTimestamps/);
  for (const path of ["src/js/app.js", "src/js/online.js", "src/shell.html"]) {
    assert.doesNotMatch(read(path), /opentimestamps|\.ots\b/i, `${path} must not talk to OTS calendars`);
  }
});

// Rock only ever carries a site built from the sources beneath it. A merge
// that lands while a run tests starts its own run, which builds and publishes
// the newer sources, so the older build is superseded: it is not pushed over
// them, and the timestamp job does not stamp it onto rock. Commits that start
// no run (the bot's own [skip ci] proof upgrades) change no sources, so the
// build rebases over them rather than going unpublished. The step's own script
// runs here against a scratch rock, one commit deep like the job's checkout.
//
// On Windows, the first `bash` on PATH can be WSL's launcher
// (C:\Windows\System32\bash.exe, the only one on a PowerShell PATH). It runs the
// script inside Linux, where these Windows paths and variables do not arrive,
// so use the bash that ships with the Git for Windows on PATH.
const gitBash = () => {
  const execPath = spawnSync("git", ["--exec-path"], { encoding: "utf8" }).stdout?.trim();
  const candidate = execPath && join(execPath, "..", "..", "..", "bin", "bash.exe");
  return candidate && existsSync(candidate) ? candidate : null;
};
const bash = process.platform === "win32" ? gitBash() : "bash";
const shellTools = Boolean(bash) && [bash, "git"].every((tool) => spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0);
test("the artifact commit rebases over [skip ci] commits and steps aside for newer sources", { skip: !shellTools && "needs bash and git" }, () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const artifact = workflowJob(workflow, "artifact");
  const step = workflowSteps(artifact).find((entry) => /name: Commit the generated artifact\n/.test(entry)) ?? "";
  const script = step.split(/\n +run: \|\n/)[1]?.replace(/^ {10}/gm, "").replace(/\$\{\{ secrets\.RELEASE_PUSH_TOKEN \}\}/g, "test-token");
  assert.ok(script, "the artifact commit step runs a script");

  const home = mkdtempSync(join(tmpdir(), "artifact-push-"));
  const env = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: join(home, "gitconfig") };
  delete env.GITHUB_OUTPUT;
  const git = (cwd, ...args) => execFileSync("git", args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const commit = (cwd, file, subject) => {
    writeFileSync(join(cwd, file), `${subject}\n`);
    git(cwd, "add", file);
    git(cwd, "-c", "user.name=seed", "-c", "user.email=seed@example.invalid", "commit", "--quiet", "-m", subject);
    git(cwd, "push", "--quiet", "origin", "rock");
    return git(cwd, "rev-parse", "HEAD");
  };
  const run = (name, landed) => {
    const dir = join(home, name), remote = join(dir, "rock.git"), seed = join(dir, "seed"), work = join(dir, "work");
    mkdirSync(dir);
    git(dir, "init", "--quiet", "--bare", remote);
    git(remote, "symbolic-ref", "HEAD", "refs/heads/rock");
    git(dir, "init", "--quiet", seed);
    git(seed, "checkout", "--quiet", "-b", "rock");
    git(seed, "remote", "add", "origin", remote);
    const tested = commit(seed, "source.js", "Merge pull request #1");
    git(dir, "clone", "--quiet", "--depth", "1", "--branch", "rock", pathToFileURL(remote).href, work);
    for (const file of ["entropylab.html", ...wasmModulePaths, "SHA256SUMS.txt", "WASM-SHA256SUMS.txt", "CID.txt"]) {
      mkdirSync(dirname(join(work, file)), { recursive: true });
      writeFileSync(join(work, file), `built from ${tested}\n`);
    }
    const before = landed ? commit(seed, landed.file, landed.subject) : tested;
    const output = join(dir, "github-output");
    writeFileSync(output, "");
    const result = spawnSync(bash, ["-e", "-c", script], { cwd: work, env: { ...env, GITHUB_SHA: tested, GITHUB_OUTPUT: output }, encoding: "utf8" });
    const tip = git(remote, "rev-parse", "rock");
    return {
      tested, before, tip, status: result.status, log: `${result.stdout}${result.stderr}`,
      parent: git(remote, "rev-parse", "rock^"),
      subject: git(remote, "log", "-1", "--format=%s", "rock"),
      html: spawnSync("git", ["show", "rock:entropylab.html"], { cwd: remote, env, encoding: "utf8" }).stdout.trim(),
      superseded: /^superseded=true$/m.test(readFileSync(output, "utf8")),
    };
  };
  try {
    // Nothing landed: the build goes on top of the commit it was built from.
    const quiet = run("quiet");
    assert.equal(quiet.status, 0, quiet.log);
    assert.equal(quiet.parent, quiet.tested, "the artifact sits on the tested commit");
    assert.equal(quiet.subject, "Rebuild site artifact [skip ci]");
    assert.equal(quiet.html, `built from ${quiet.tested}`);
    assert.equal(quiet.superseded, false);

    // A [skip ci] proof upgrade landed: no run will follow it, so the build
    // rebases over it and is published.
    const upgrade = run("upgrade", { file: "entropylab.html.ots", subject: "Upgrade OpenTimestamps proof for entropylab.html [skip ci]" });
    assert.equal(upgrade.status, 0, upgrade.log);
    assert.equal(upgrade.parent, upgrade.before, "the artifact rebases over the [skip ci] commit");
    assert.equal(upgrade.subject, "Rebuild site artifact [skip ci]");
    assert.equal(upgrade.html, `built from ${upgrade.tested}`);
    assert.equal(upgrade.superseded, false);

    // A merge landed: its run publishes the newer sources. This build is not
    // pushed over them, the step still succeeds, and it says it was superseded.
    const merged = run("merged", { file: "source.js", subject: "Merge pull request #2" });
    assert.equal(merged.status, 0, merged.log);
    assert.equal(merged.tip, merged.before, "a superseded build must not land on rock");
    assert.equal(merged.superseded, true, "the step records that its build was superseded");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  // The timestamp job stamps this run's candidate onto rock, so it must not
  // run for a superseded build: rock would carry a proof for HTML it does not.
  assert.match(artifact, /^    outputs:\n      superseded: \$\{\{ steps\.commit\.outputs\.superseded \}\}\n/m, "the artifact job exposes whether its build was superseded");
  assert.match(workflowJob(workflow, "timestamp"), /^    if: .*needs\.artifact\.outputs\.superseded != 'true'/m, "the timestamp job skips a superseded build");
});

// A release's assets come from two commits on rock: the HTML, its checksum
// and its CID from the artifact commit, the OpenTimestamps proof from the
// stamp commit after it. v1.0.0rc1 shipped the proof committed before its
// build, which stamps the previous HTML. The release check fails any release
// whose proof, checksum or CID describes other bytes. Its own script runs here
// against scratch releases, with a stub `ots info` that reports the digest
// each scratch proof holds.
test("the release check rejects assets that describe other bytes than the released HTML", { skip: !shellTools && "needs bash and git" }, () => {
  const workflow = read(".github/workflows/release-assets.yml");
  assert.match(workflow, /^on:\n  release:\n    types: \[published\]\n/m, "the check runs when a release is published");
  assert.match(workflow, /^permissions:\n  contents: read\n/m, "the check only reads");
  for (const [, spec] of workflow.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)) {
    assert.match(spec, /@[0-9a-f]{40}$/, `${spec} must be pinned to a 40-character commit SHA`);
  }
  assert.match(workflow, /--require-hashes --no-deps --only-binary :all: -r "\$GITHUB_WORKSPACE\/\.github\/ots-requirements\.txt"/, "install the hash-locked OTS client");
  assert.match(workflow, /gh release download "\$TAG"/, "the check reads the published assets");
  const step = workflowSteps(workflowJob(workflow, "check")).find((entry) => /name: Check the assets against the released HTML\n/.test(entry)) ?? "";
  const script = step.split(/\n +run: \|\n/)[1]?.replace(/^ {10}/gm, "");
  assert.ok(script, "the check step runs a script");

  // "hello world" and its SHA-256 and CIDv1 from the published vectors. The
  // other digest is the build before v1.0.0rc1, which its first proof
  // stamped; the other CID names the empty input.
  const html = "hello world";
  const digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
  const cid = "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e";
  const other = "b75d8bc576074e4b0756284bd18cecf83d64408ca005c0334fd26cbb9dbfc1a7";
  const otherCid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
  const stub = "#!/bin/sh\n[ \"$1\" = info ] && [ -f \"$2\" ] || exit 1\nprintf 'File sha256 hash: %s\\nTimestamp:\\n' \"$(cat \"$2\")\"\n";

  const temp = mkdtempSync(join(tmpdir(), "release-assets-"));
  const check = (name, overrides = {}) => {
    const runnerTemp = join(temp, name), release = join(runnerTemp, "release");
    mkdirSync(join(runnerTemp, "ots/bin"), { recursive: true });
    mkdirSync(release);
    writeFileSync(join(runnerTemp, "ots/bin/ots"), stub, { mode: 0o755 });
    const assets = {
      "entropylab.html": html,
      "SHA256SUMS.txt": `${digest}  entropylab.html\n`,
      "CID.txt": `${cid}  entropylab.html\n`,
      "entropylab.html.ots": digest,
      ...overrides,
    };
    for (const [file, body] of Object.entries(assets)) {
      if (body !== null) writeFileSync(join(release, file), body);
    }
    const result = spawnSync(bash, ["-c", script], { cwd: runnerTemp, env: { ...process.env, RUNNER_TEMP: runnerTemp, GITHUB_WORKSPACE: root }, encoding: "utf8" });
    return { status: result.status, log: `${result.stdout}${result.stderr}` };
  };
  try {
    const good = check("good");
    assert.equal(good.status, 0, good.log);

    const staleProof = check("stale-proof", { "entropylab.html.ots": other });
    assert.notEqual(staleProof.status, 0, "a proof of the previous build must fail the release");
    assert.match(staleProof.log, new RegExp(`title=Stale OpenTimestamps proof::.*${other}`));

    const noProof = check("no-proof", { "entropylab.html.ots": null });
    assert.notEqual(noProof.status, 0, "a release without a proof must fail");
    assert.match(noProof.log, /title=Stale OpenTimestamps proof::/);

    const staleSums = check("stale-sums", { "SHA256SUMS.txt": `${other}  entropylab.html\n` });
    assert.notEqual(staleSums.status, 0, "a checksum of other bytes must fail the release");

    const staleCid = check("stale-cid", { "CID.txt": `${otherCid}  entropylab.html\n` });
    assert.notEqual(staleCid.status, 0, "a CID of other bytes must fail the release");
    assert.match(staleCid.log, /title=Stale CID::/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("repository links follow the Team Ooga Booga ownership", () => {
  for (const path of ["README.md", "CONTRIBUTING.md", "SECURITY.md", "llms.txt", "src/index.html", "src/shell.html", "src/js/app.js"]) {
    assert.doesNotMatch(read(path), /github\.com\/(?:w-s-bitcoin|Team-Ooga-Booga)\/entropylab/, `${path} still links through a former owner`);
  }
  assert.match(read("src/shell.html"), /https:\/\/github\.com\/OogaBoogaX\/entropylab/);
});

test("the GHCR image name is normalized for mixed-case organization logins", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.match(workflow, /id: ghcr-image\n\s+run: echo "name=ghcr\.io\/\$\{GITHUB_REPOSITORY,,\}" >> "\$GITHUB_OUTPUT"/);
  assert.match(workflow, /\$\{\{ steps\.ghcr-image\.outputs\.name \}\}:latest/);
  assert.doesNotMatch(workflow, /ghcr\.io\/\$\{\{ github\.repository \}\}/);
});

// Deliberately parse the workflow's simple job/step layout, not arbitrary YAML.
// Bound sections before matching so another job's needs or upload cannot pass.
function workflowJob(workflow, name) {
  return workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [\\w-]+:|(?![\\s\\S]))`, "m"))?.[0] ?? "";
}
const workflowSteps = (job) => job.match(/^      - [\s\S]*?(?=^      - |(?![\s\S]))/gm) ?? [];
const jobNeeds = (job) => (job.match(/^    needs: \[([^\]\n]*)\]/m)?.[1] ?? "").split(",").map(value => value.trim());
const wasmModulePaths = ["src/js/entropylab-wasm-b64.js", "src/js/psbt-wasm-b64.js", "src/js/vanity-wasm-b64.js"];
const candidateConsumers = {
  "test-ci": "npm run test:ci",
  "test-browser": "npm run test:browser",
  "test-browser-check": "npm run test:browser-check",
  "test-invariants": "npm run test:invariants",
  verify: "npm run verify",
  artifact: "git add -f entropylab.html",
  timestamp: "ots stamp entropylab.html",
};

function wasmArtifactFlowProblems(workflow) {
  const problems = [];
  const requireNeeds = (name, dependencies) => {
    for (const dependency of dependencies) {
      if (!jobNeeds(workflowJob(workflow, name)).includes(dependency)) problems.push(`${name} needs ${dependency}`);
    }
  };
  const artifactStep = (steps, action, name) => steps.findIndex(step =>
    step.includes(`uses: actions/${action}@`) && step.includes(`          name: ${name}\n`));
  const upload = (steps, name, paths) => {
    const index = artifactStep(steps, "upload-artifact", name);
    const step = steps[index] ?? "";
    const actual = (step.match(/^          path: \|\n((?:^            [^\n]+\n)+)/m)?.[1] ?? "")
      .trim().split("\n").map(path => path.trim());
    if (index < 0) problems.push(`missing ${name} upload`);
    if (actual.length !== paths.length || paths.some(path => !actual.includes(path))) problems.push(`${name} must upload the explicit file paths`);
    // This fails an empty upload; the explicit path guard catches omissions
    // from the workflow, not individual missing files on a runner's disk.
    if (!/^          if-no-files-found: error$/m.test(step)) problems.push(`${name} must fail an empty upload`);
    return index;
  };
  requireNeeds("build", ["build-wasm"]);
  const producer = workflowSteps(workflowJob(workflow, "build-wasm"));
  const uploaded = upload(producer, "entropylab-wasm", wasmModulePaths);
  const tested = producer.findIndex(step => /^        run: node --test /m.test(step));
  if (tested < 0 || uploaded <= tested) problems.push("WASM upload must follow fresh tests");
  const build = workflowSteps(workflowJob(workflow, "build"));
  const downloaded = artifactStep(build, "download-artifact", "entropylab-wasm");
  const compiled = build.findIndex(step => /^        run: npm run build$/m.test(step));
  const checkout = build.findIndex(step => step.includes("uses: actions/checkout@"));
  if (downloaded < 0 || !/^          path: src\/js$/m.test(build[downloaded] ?? "")) problems.push("build must download entropylab-wasm into src/js");
  if (checkout < 0 || downloaded <= checkout || compiled <= downloaded) problems.push("build must checkout, download WASM, then compile");
  const candidate = upload(build, "entropylab-candidate", ["entropylab.html", "service-worker.js", ...wasmModulePaths]);
  if (compiled < 0 || candidate <= compiled) problems.push("candidate upload must follow compilation");
  for (const [name, command] of Object.entries(candidateConsumers)) {
    requireNeeds(name, ["build"]);
    const job = workflowJob(workflow, name);
    const steps = workflowSteps(job);
    const download = artifactStep(steps, "download-artifact", "entropylab-candidate");
    const checkout = steps.findIndex(step => step.includes("uses: actions/checkout@"));
    const consume = steps.findIndex(step => step.includes(command));
    const destination = steps[download]?.match(/^          path: (.+)$/m)?.[1];
    if (download < 0 || (destination !== undefined && destination !== ".")) problems.push(`${name} must download candidate into the workspace root`);
    if (checkout < 0 || download <= checkout || consume <= download) problems.push(`${name} must checkout, download candidate, then consume it`);
    if (/npm run build:wasm/.test(job)) problems.push(`${name} must not recompile WASM`);
  }
  return problems;
}

test("fresh WASM travels through the single candidate to every consumer", () => {
  assert.deepEqual(wasmArtifactFlowProblems(read(".github/workflows/ci-cd.yml")), []);
});

test("the WASM artifact flow guard detects broken handoffs", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.deepEqual(wasmArtifactFlowProblems(workflow), [], "mutation baseline satisfies the contract");
  const reject = (name, mutate, expected) => {
    const original = workflowJob(workflow, name);
    const changed = mutate(original);
    assert.notEqual(changed, original, `${name}: mutation must change its fixture`);
    const problems = wasmArtifactFlowProblems(workflow.replace(original, changed));
    assert.ok(problems.some(problem => problem.includes(expected)), `${name}: expected ${expected}; got ${problems.join("; ")}`);
  };
  const moveStepBefore = (job, moving, before) => {
    const steps = workflowSteps(job);
    const source = steps.find(step => step.includes(moving));
    const target = steps.find(step => step.includes(before));
    assert.ok(source && target && source !== target, "reordering fixture has distinct steps");
    return job.replace(source, "").replace(target, source + target);
  };
  reject("build", job => job.replace("needs: [build-wasm]", "needs: []"), "build needs build-wasm");
  for (const [name, artifact] of [["build-wasm", "entropylab-wasm"], ["build", "entropylab-candidate"]]) {
    for (const path of name === "build" ? ["entropylab.html", "service-worker.js", ...wasmModulePaths] : wasmModulePaths) {
      reject(name, job => job.replace(`            ${path}\n`, ""), `${artifact} must upload the explicit file paths`);
    }
    reject(name, job => job.replace("if-no-files-found: error", "if-no-files-found: warn"), `${artifact} must fail an empty upload`);
    reject(name, job => {
      const step = workflowSteps(job).find(step => step.includes(`          name: ${artifact}\n`));
      return job.replace(step, "");
    }, `missing ${artifact} upload`);
  }
  reject("build-wasm", job => moveStepBefore(job, "          name: entropylab-wasm\n", "run: node --test"), "WASM upload must follow fresh tests");
  reject("build", job => job.replace("name: entropylab-wasm\n", "name: wrong-wasm\n"), "build must download entropylab-wasm");
  reject("build", job => job.replace("path: src/js\n", "path: .\n"), "build must download entropylab-wasm into src/js");
  reject("build", job => moveStepBefore(job, "run: npm run build\n", "          name: entropylab-wasm\n"), "then compile");
  reject("build", job => moveStepBefore(job, "          name: entropylab-candidate\n", "run: npm run build\n"), "candidate upload must follow compilation");
  for (const [name, command] of Object.entries(candidateConsumers)) {
    // Later jobs still have needs: [build]; they must never mask this loss.
    reject(name, job => job.replace(/^(    needs: \[)build(?:, )?/m, "$1"), `${name} needs build`);
    reject(name, job => job.replace("name: entropylab-candidate\n", "name: wrong-candidate\n"), `${name} must download candidate`);
    reject(name, job => job.replace("name: entropylab-candidate\n", "name: entropylab-candidate\n          path: src/js\n"), `${name} must download candidate`);
    reject(name, job => moveStepBefore(job, "          name: entropylab-candidate\n", "uses: actions/checkout@"), `${name} must checkout`);
    reject(name, job => moveStepBefore(job, command, "          name: entropylab-candidate\n"), `${name} must checkout`);
  }
  reject("artifact", job => job + "      - run: npm run build:wasm\n", "artifact must not recompile WASM");
  assert.equal(workflowJob("  first:\n    needs: []\n  last:\n    needs: [build]", "first"), "  first:\n    needs: []\n");
  assert.deepEqual(jobNeeds(workflowJob("  last:\n    needs: [build]", "last")), ["build"], "last job works without a trailing newline");
});

test("every gate and publication path consumes the single tested candidate (issue #93)", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  // One build records the candidate's SHA-256 and shares the exact object.
  assert.match(workflowJob(workflow, "build"), /^    outputs:\n\s*sha256: \$\{\{ steps\.digest\.outputs\.sha256 \}\}/m);
  assert.match(workflow, /actions\/upload-artifact@[0-9a-f]{40}/);
  // Each job that reads the compiled artifact downloads that object and
  // verifies its digest instead of rebuilding it.
  for (const job of ["test-ci", "test-browser", "test-browser-check", "test-invariants", "verify", "artifact", "timestamp"]) {
    const section = workflowJob(workflow, job);
    assert.ok(section, `${job} job is missing`);
    assert.match(section, /actions\/download-artifact@[0-9a-f]{40}/, `${job} must download the tested candidate`);
    assert.match(section, /sha256sum -c -/, `${job} must verify the candidate digest`);
    assert.doesNotMatch(section, /^\s+run: npm run build\s*$/m, `${job} must not rebuild the wallet HTML`);
  }
  // The repository artifact cannot be committed when unit or browser tests
  // fail, or when a second in-image WASM build disagrees with the candidate.
  for (const dependency of ["build", "verify", "test-ci", "test-browser", "build-wasm", "fuzz-lifehash", "fuzz-msig", "reproduce"]) {
    assert.ok(jobNeeds(workflowJob(workflow, "artifact")).includes(dependency), `artifact needs ${dependency}`);
  }
});

test("third-party actions are immutable and deployment is test-gated", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.doesNotMatch(workflow, /^\s*uses:\s*[^\s]+@(?![0-9a-f]{40}(?:\s|$))/m);
  for (const job of ["test-ci", "test-browser"]) {
    for (const dependency of ["build", "setup"]) assert.ok(jobNeeds(workflowJob(workflow, job)).includes(dependency), `${job} needs ${dependency}`);
  }
  // The WASM gate must rebuild the bindings from the Rust sources inside the
  // pinned dev image, test the fresh build, and block both the artifact commit
  // and the Pages deploy.
  const rebuild = workflowSteps(workflowJob(workflow, "build-wasm")).find((step) => BUILD_WASM_COMMAND.test(step)) ?? "";
  assert.match(rebuild, IN_IMAGE_BUILD, "build-wasm rebuilds the bindings inside the pinned dev image");
  assert.deepEqual(wasmGateProblems(workflow), []);
  for (const dependency of ["build", "verify", "test-ci", "test-browser", "build-wasm", "fuzz-lifehash", "fuzz-msig", "reproduce"]) {
    assert.ok(jobNeeds(workflowJob(workflow, "deploy")).includes(dependency), `deploy needs ${dependency}`);
  }
});

// The rebuild only counts as `npm run build:wasm` alone on its own line — a
// step's `run:` or a line of its script — never a comment or an argument that
// merely mentions it. It must also run in the pinned dev image, whose clang
// produces the release bytes, not on the runner.
const BUILD_WASM_COMMAND = /^ +(?:run: )?npm run build:wasm$/m;
const IN_IMAGE_BUILD = /docker run --rm --platform linux\/amd64 [\s\S]*?entropylab-dev:local[\s\S]*?^ +npm run build:wasm$/m;

// The build-wasm gate only guards the crate if (a) the job rebuilds the
// bindings, in the pinned image, before testing them, (b) the test step lives
// in the build-wasm job itself, and (c) every suite that exercises the WASM
// boundary runs against that fresh build. Returns the list of ways the gate is
// broken, so the same check can be exercised against doctored workflows below.
function wasmGateProblems(workflow) {
  const problems = [];
  const job = workflowJob(workflow, "build-wasm");
  if (!job) return ["the build-wasm job is missing"];
  const buildStep = workflowSteps(job).find((step) => BUILD_WASM_COMMAND.test(step));
  const buildAt = buildStep ? job.indexOf(buildStep) : -1;
  const testAt = job.search(/^\s*run: node --test /m);
  if (buildAt === -1) problems.push("the build-wasm job never rebuilds the bindings from the Rust sources");
  else if (!IN_IMAGE_BUILD.test(buildStep)) problems.push("the build-wasm rebuild does not run inside the pinned dev image");
  if (testAt === -1) {
    problems.push("the build-wasm job runs no test suites against the fresh build");
    return problems;
  }
  if (buildAt !== -1 && buildAt > testAt) {
    problems.push("build-wasm tests run before the rebuild, so they exercise the committed artifact instead");
  }
  const step = job.match(/^\s*run: node --test ([^\n]+)$/m)[1];
  for (const suite of readdirSync(join(root, "test")).filter((name) => name.endsWith("-wasm.test.mjs"))) {
    if (!step.includes(`test/${suite}`)) problems.push(`build-wasm must run test/${suite} against the fresh build`);
  }
  return problems;
}

test("the WASM gate check detects its own failure modes", () => {
  // A gate assertion that cannot fail is not a gate. Doctor the real workflow
  // each way the check exists to catch and require detection every time.
  const workflow = read(".github/workflows/ci-cd.yml");
  const suite = readdirSync(join(root, "test")).find((name) => name.endsWith("-wasm.test.mjs"));
  const dropped = workflow.replace(` test/${suite}`, "");
  assert.notEqual(dropped, workflow, "fixture: the suite name must appear in the workflow");
  assert.ok(
    wasmGateProblems(dropped).some((problem) => problem.includes(suite)),
    "dropping a WASM suite from the gate must be detected",
  );
  const reordered = workflow.replace(
    /( {6}- name: Rebuild the WASM artifacts inside the pinned image\n[\s\S]*?cargo test --locked --lib'\n)( {6}- name: Test the freshly built bindings\n {8}run: node --test [^\n]+\n)/,
    "$2$1",
  );
  assert.notEqual(reordered, workflow, "fixture: the build and test steps must be reorderable");
  assert.ok(
    wasmGateProblems(reordered).some((problem) => problem.includes("before the rebuild")),
    "testing before rebuilding must be detected",
  );
  const noTest = workflow.replace(/^\s*- name: Test the freshly built bindings\n\s*run: node --test [^\n]+\n/m, "");
  assert.notEqual(noTest, workflow, "fixture: the fresh-build test step must exist");
  assert.ok(
    wasmGateProblems(noTest).some((problem) => problem.includes("no test suites")),
    "deleting the fresh-build test step must be detected",
  );
  // A rebuild that survives only as a comment is no rebuild: the node suites
  // would then test, and the job would upload, the committed modules.
  const gateJob = workflowJob(workflow, "build-wasm");
  const commented = workflow.replace(gateJob, gateJob.replace(/^( +)npm run build:wasm$/m, "$1true # npm run build:wasm"));
  assert.notEqual(commented, workflow, "fixture: the in-image rebuild command must exist");
  assert.ok(
    wasmGateProblems(commented).some((problem) => problem.includes("never rebuilds")),
    "a commented-out rebuild must be detected",
  );
  // A rebuild on the runner compiles with the runner's clang, not the image's.
  const onRunner = workflow.replace(
    /( {6}- name: Rebuild the WASM artifacts inside the pinned image\n)[\s\S]*?cargo test --locked --lib'\n/,
    "$1        run: npm run build:wasm\n",
  );
  assert.notEqual(onRunner, workflow, "fixture: the in-image rebuild step must be replaceable");
  assert.ok(
    wasmGateProblems(onRunner).some((problem) => problem.includes("pinned dev image")),
    "a rebuild outside the pinned image must be detected",
  );
  // test:ci also exercises the fresh modules delivered with the candidate.
  const ciScript = pkg.scripts["test:ci"];
  for (const suiteName of readdirSync(join(root, "test")).filter((name) => name.endsWith("-wasm.test.mjs"))) {
    assert.ok(ciScript.includes(`test/${suiteName}`), `test:ci must also run test/${suiteName} against the candidate modules`);
  }
});

test("the intentional low-entropy recovery behavior is documented", () => {
  const security = read("SECURITY.md");
  assert.match(security, /low-entropy dice and card transcripts are accepted intentionally/i);
  assert.match(security, /does not claim that hashing a short input\s+makes it secure/i);
});

test("the limits of memory erasure are documented", () => {
  const security = read("SECURITY.md");
  const section = security.split(/^## What the page can and cannot erase$/m)[1]?.split(/^## /m)[0];
  assert.ok(section, "SECURITY.md has no section on what the page cannot erase");
  // The limits themselves, not the advice after them, which names some too.
  const limits = section.split(/^\*\*What the page cannot erase\.\*\*/m)[1]?.split(/^\*\*/m)[0];
  assert.ok(limits, "the section does not list what the page cannot erase");
  for (const limit of [/typed? or paste/i, /clipboard history/i, /hibernation/i, /BigInt/]) assert.match(limits, limit);
  assert.match(security, /\(#what-the-page-can-and-cannot-erase\)/);
});

// CI cannot be the second machine, so the cross-machine claim rests on the
// reproductions log: every row names a date, a commit and a full SHA-256, the
// docs that make the claim point at the log, and a WASM claim needs a WASM
// module rebuilt in the pinned image.
test("cross-machine reproduction claims rest on the reproductions log", () => {
  const log = read("docs/Reproductions.md");
  const rows = log.split("\n").filter((line) => /^\| \d/.test(line));
  assert.ok(rows.length > 0, "the log records no reproduction");
  for (const row of rows) {
    assert.match(row, /^\| \d{4}-\d{2}-\d{2} \| `[0-9a-f]{7,40}`[^|]*\|[^|]+\| `[0-9a-f]{64}` \|[^|]+\|[^|]+\|$/, `malformed row: ${row}`);
  }
  for (const file of ["SECURITY.md", "README.md", "CONTRIBUTING.md"]) {
    const text = read(file);
    assert.doesNotMatch(text, /Cross-machine (byte )?identity is not claimed/i, `${file} still disclaims what the log records`);
    assert.match(text, /docs\/Reproductions\.md/, `${file} makes the claim without pointing at the log`);
  }
  assert.ok(rows.some((row) => /wasm-b64\.js/.test(row) && /dev image/i.test(row)), "the WASM claim needs a module rebuilt in the dev image");
});

const htmlFiles = [appFile];

ensureBuild();

for (const file of htmlFiles) {
  test(`${file} declares HTML5`, () => {
    assert.match(read(file), /^<!DOCTYPE html>/);
  });
  test(`${file} has a closing html element`, () => {
    assert.match(read(file), /<\/html>\s*$/);
  });
  test(`${file} includes the offline content security policy`, () => {
    assert.ok(read(file).includes("default-src 'none'"), `${file} is missing the offline CSP`);
  });
  test(`${file} contains application JavaScript`, () => {
    assert.ok(read(file).includes("<script>"), `${file} has no inline script`);
  });
  test(`${file} has no remote executable subresources`, () => {
    const html = read(file);
    assert.doesNotMatch(html, /<(script|iframe)[^>]+src=["' ]*https?:\/\//i);
    assert.doesNotMatch(html, /<link(?![^>]*rel="canonical")[^>]+href=["' ]*https?:\/\//i);
  });
  test(`${file} inlines the favicon from the published asset`, () => {
    const inlined = read(file).match(/<link rel="icon" type="image\/png" sizes="64x64" href="data:image\/png;base64,([A-Za-z0-9+/=]+)">/);
    assert.ok(inlined, `${file} has no inlined favicon`);
    assert.ok(
      Buffer.from(inlined[1], "base64").equals(readFileSync(join(root, "assets/favicon.png"))),
      `${file} favicon does not match assets/favicon.png`,
    );
  });
  test(`${file} ships none of the test-only browser-suite bridge`, () => {
    // The __entropyLabCrypto hook lets the browser suite reach app internals;
    // it is compiled in only for the harness's --test-hooks staging variant.
    const html = read(file);
    assert.doesNotMatch(html, /__ENTROPYLAB_TEST_HOOKS__|__entropyLabTest|__entropyLabCrypto|test-keys|Test dice/);
  });
  test(`${file} never fetches the header logo or favicon from assets`, () => {
    // The downloaded file has no assets/ beside it, so both have to travel
    // inside the document or the fixed header renders empty when air-gapped.
    // Asserted as an absence so it holds for the committed artifact on a pull
    // request too, which CI rebuilds only after the merge (see the head test
    // below); the inlined SVG markup itself is asserted on the sources.
    assert.doesNotMatch(read(file), /assets\/(logo-(dark|light)|favicon)\.(png|svg)/);
  });
}

test("the build inlines the header logo and SVG favicon from src/assets", () => {
  // Asserted on the sources rather than the committed artifact, which on a
  // pull request predates the change (CI rebuilds it only after the merge).
  const build = read("scripts/build.mjs");
  const template = read("src/index.html");
  for (const name of ["logo-dark", "logo-light", "favicon"]) {
    assert.ok(existsSync(join(root, "src/assets", `${name}.svg`)), `src/assets/${name}.svg is missing`);
  }
  assert.match(read("src/assets/favicon.svg"), /^<svg /);
  assert.match(build, /logoSvg\("logo-dark"\)/);
  assert.match(build, /logoSvg\("logo-light"\)/);
  assert.match(build, /read\("assets\/favicon\.svg"\)/);
  assert.match(build, /\.split\(siteLogoSpan\)\.join\(siteLogo\)/);
  assert.match(read("src/shell.html"), /<span class="site-logo" aria-hidden="true"><\/span>/);
  assert.match(template, /<link rel="icon" type="image\/svg\+xml" href="data:image\/svg\+xml,\/\*@@FAVICON_SVG@@\*\/">/);
});

test("the browser-suite crypto bridge is gated out of the release build", () => {
  // The artifact check above is the invariant; this pins the mechanism so the
  // gate cannot be dropped without a red test: the hook in app.js must sit
  // behind the build-time flag, and the build must default that flag off and
  // refuse to write a hooks build over the release artifact.
  assert.match(read("src/js/app.js"), /if \(__ENTROPYLAB_TEST_HOOKS__ && globalThis\.__entropyLabTest\) globalThis\.__entropyLabCrypto = /);
  const build = read("scripts/build.mjs");
  assert.match(build, /define: \{ __ENTROPYLAB_TEST_HOOKS__: testHooks \? "true" : "false" \}/);
  assert.match(build, /--test-hooks requires --out outside the repository root/);
});

test("the document head declares its link-preview card", () => {
  // Asserted on the template, not the committed artifact: CI rebuilds and
  // commits entropylab.html only after a merge, so the committed artifact on a
  // pull request predates any head change. The build stamps this markup into
  // the output verbatim.
  // The og:image URL is fetched only by link-preview crawlers, never by the
  // app; browsers do not load it, so the offline CSP and the no-egress rule
  // are unaffected. The asset ships in the deployed assets/ directory.
  const template = read("src/index.html");
  for (const tag of [
    '<meta name="description" content="',
    '<meta property="og:title" content="EntropyLab">',
    '<meta property="og:type" content="website">',
    '<meta property="og:url" content="https://entropylab.online/">',
    '<meta property="og:description" content="',
    '<meta property="og:image" content="https://entropylab.online/assets/entropylab-social.png">',
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    '<meta name="twitter:card" content="summary_large_image">',
    '<meta name="twitter:image" content="https://entropylab.online/assets/entropylab-social.png">',
  ]) {
    assert.ok(template.includes(tag), `src/index.html is missing ${tag}`);
  }
});

test("the link-preview card asset is a 1200x630 PNG", () => {
  const png = readFileSync(join(root, "assets/entropylab-social.png"));
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.ok(png.subarray(0, 8).equals(signature), "not a PNG file");
  // IHDR width and height are the big-endian uint32s at bytes 16 and 20.
  assert.equal(png.readUInt32BE(16), 1200, "social card width must be 1200");
  assert.equal(png.readUInt32BE(20), 630, "social card height must be 630");
});

test("repository source has no unresolved merge markers", () => {
  const offenders = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const name = entry.name;
      const path = join(dir, name);
      if (name === ".git" || name === "node_modules" || name.endsWith(".png")) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        walk(path);
      } else {
        const lines = readFileSync(path, "utf8").split("\n");
        if (lines.some((line) => /^(<<<<<<<|=======|>>>>>>>)/.test(line))) {
          offenders.push(relative(root, path));
        }
      }
    }
  };
  walk(root);
  assert.deepEqual(offenders, [], `unresolved merge markers in: ${offenders.join(", ")}`);
});

test("GitHub Actions are pinned to commit SHAs", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const uses = [...workflow.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].map((match) => match[1]);
  assert.ok(uses.length >= 5, "expected third-party actions in ci-cd.yml");
  for (const spec of uses) {
    assert.match(spec, /@[0-9a-f]{40}$/, `${spec} must be pinned to a 40-character commit SHA`);
  }
  assert.match(read(".github/dependabot.yml"), /package-ecosystem:\s*github-actions/);
});
