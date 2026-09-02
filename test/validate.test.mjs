// Source validation and security invariants for the EntropyLab repository.
// Run with `npm run test:validate` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

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
  "scripts/verify-site.mjs",
  "test/validate.test.mjs",
  "test/browser.test.mjs",
  "test/browser-instrumentation.html",
  "test/browser-suite.html",
  "src/index.html",
  "src/assets/logo-dark.svg",
  "src/assets/logo-light.svg",
  "src/assets/favicon.svg",
  "src/css/styles.css",
  "src/js/app.js",
  "src/js/psbt-editor.js",
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
  "test/sqlite-writer.test.mjs",
  "test/wallet-export.test.mjs",
  "test/wallet-export-reference.mjs",
  "test/browser-check.test.mjs",
  "test/psbt-metadata.test.mjs",
  "test/secret-clear.test.mjs",
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
    /secp256k1Ready\.then\(hodlBoot\)\.catch\(/,
    "app boot must catch secp256k1Ready rejection instead of leaving a dead page",
  );
  assert.match(app, /hodlCurveFailure/, "the boot rejection must render the sanity-failure kill screen");
  assert.match(app, /<tr><td>secp256k1 WebAssembly module<\/td><td>Failed<\/td><\/tr>/);
  assert.match(app, /Lockdown Mode block WebAssembly/);
  const check = read("src/js/browser-check.js");
  assert.match(check, /Lockdown Mode block WebAssembly/);
});

test("the release build attests the wallet artifact and ships a checksum manifest (issue #58)", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const build = workflow.match(/^  build:\n(?:.|\n)*?(?=^  [a-z-]+:)/m)?.[0] ?? "";
  assert.match(build, /sha256sum entropylab\.html > SHA256SUMS\.txt/, "build must generate SHA256SUMS.txt");
  assert.match(build, /actions\/attest-build-provenance@[0-9a-f]{40}/, "build must attest entropylab.html");
  assert.match(build, /subject-path: entropylab\.html/, "the attestation subject is the wallet HTML");
  assert.match(build, /attestations: write/, "attestation requires the attestations permission");
  // Only merges to the default branch produce release attestations.
  assert.match(build, /if: github\.ref == 'refs\/heads\/rock' && github\.event_name == 'push'\n\s*uses: actions\/attest-build-provenance/);
  const artifact = workflow.match(/^  artifact:\n(?:.|\n)*?(?=^  [a-z-]+:)/m)?.[0] ?? "";
  assert.match(artifact, /SHA256SUMS\.txt/, "the committed artifact includes the checksum manifest");
  assert.match(read("README.md"), /gh attestation verify entropylab\.html -R w-s-bitcoin\/entropylab/);
});

test("every gate and publication path consumes the single tested candidate (issue #93)", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  // One build records the candidate's SHA-256 and shares the exact object.
  assert.match(workflow, /^\s{2}build:\n(?:.|\n)*?^\s{4}outputs:\n\s*sha256: \$\{\{ steps\.digest\.outputs\.sha256 \}\}/m);
  assert.match(workflow, /actions\/upload-artifact@[0-9a-f]{40}/);
  // Each job that reads the compiled artifact downloads that object and
  // verifies its digest instead of rebuilding it.
  for (const job of ["test-ci", "test-browser", "test-browser-check", "test-invariants", "verify", "artifact"]) {
    const section = workflow.match(new RegExp(`^  ${job}:\\n(?:.|\\n)*?(?=^  [a-z-]+:|\\Z)`, "m"))?.[0] ?? "";
    assert.ok(section, `${job} job is missing`);
    assert.match(section, /actions\/download-artifact@[0-9a-f]{40}/, `${job} must download the tested candidate`);
    assert.match(section, /sha256sum -c -/, `${job} must verify the candidate digest`);
    assert.doesNotMatch(section, /^\s+run: npm run build\s*$/m, `${job} must not rebuild the wallet HTML`);
  }
  // The repository artifact cannot be committed when unit or browser tests fail.
  assert.match(workflow, /^\s{2}artifact:\n(?:.|\n)*?^\s{4}needs: \[build, verify, test-ci, test-browser, build-wasm, fuzz-lifehash, fuzz-msig\]$/m);
});

test("third-party actions are immutable and deployment is test-gated", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.doesNotMatch(workflow, /^\s*uses:\s*[^\s]+@(?![0-9a-f]{40}(?:\s|$))/m);
  assert.match(workflow, /^\s{2}test-ci:\n(?:.|\n)*?^\s{4}needs: \[build\]$/m);
  assert.match(workflow, /^\s{2}test-browser:\n(?:.|\n)*?^\s{4}needs: \[build\]$/m);
  // The WASM gate must rebuild the bindings from the Rust sources, test the
  // fresh build, and block both the artifact commit and the Pages deploy.
  assert.match(workflow, /^\s{2}build-wasm:\n(?:.|\n)*?npm run build:wasm\n/m);
  assert.deepEqual(wasmGateProblems(workflow), []);
  assert.match(workflow, /^\s{2}deploy:\n(?:.|\n)*?^\s{4}needs: \[build, verify, test-ci, test-browser, build-wasm, fuzz-lifehash, fuzz-msig\]$/m);
});

// The build-wasm gate only guards the crate if (a) the job rebuilds the
// bindings before testing them, (b) the test step lives in the build-wasm job
// itself, and (c) every suite that exercises the WASM boundary runs against
// that fresh build. Returns the list of ways the gate is broken, so the same
// check can be exercised against doctored workflows below.
function wasmGateProblems(workflow) {
  const problems = [];
  const job = workflow.match(/^  build-wasm:\n([\s\S]*?)(?=^  \w)/m);
  if (!job) return ["the build-wasm job is missing"];
  const buildAt = job[1].search(/^\s*run: npm run build:wasm$/m);
  const testAt = job[1].search(/^\s*run: node --test /m);
  if (buildAt === -1) problems.push("the build-wasm job never rebuilds the bindings from the Rust sources");
  if (testAt === -1) {
    problems.push("the build-wasm job runs no test suites against the fresh build");
    return problems;
  }
  if (buildAt !== -1 && buildAt > testAt) {
    problems.push("build-wasm tests run before the rebuild, so they exercise the committed artifact instead");
  }
  const step = job[1].match(/^\s*run: node --test ([^\n]+)$/m)[1];
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
    /(\s*run: )(npm run build:wasm)\n(\s*- name: [^\n]+\n\s*run: )(node --test [^\n]+)/,
    "$1$4\n$3$2"
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
  // The committed artifact is gated by test:ci; a WASM suite that runs only
  // against the fresh build would let a broken committed artifact deploy.
  const ciScript = pkg.scripts["test:ci"];
  for (const suiteName of readdirSync(join(root, "test")).filter((name) => name.endsWith("-wasm.test.mjs"))) {
    assert.ok(ciScript.includes(`test/${suiteName}`), `test:ci must also run test/${suiteName} against the committed artifact`);
  }
});

test("the intentional low-entropy recovery behavior is documented", () => {
  const security = read("SECURITY.md");
  assert.match(security, /low-entropy dice and card transcripts are accepted intentionally/i);
  assert.match(security, /does not claim that hashing a short input\s+makes it secure/i);
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
  assert.match(template, /<span class="site-logo" aria-hidden="true"><\/span>/);
  assert.match(template, /<link rel="icon" type="image\/svg\+xml" href="data:image\/svg\+xml,\/\*@@FAVICON_SVG@@\*\/">/);
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
