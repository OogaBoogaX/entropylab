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
const versionedFile = `entropylab-${appVersion}.html`;

const requiredFiles = [
  "README.md",
  "LICENSE",
  "package.json",
  "index.html",
  versionedFile,
  "versions.json",
  "assets/favicon.png",
  "assets/entropylab_dark.png",
  "assets/entropylab_light.png",
  "assets/entropylab_banner.png",
  "scripts/build.mjs",
  "scripts/verify-site.mjs",
  "test/validate.test.mjs",
  "test/browser.test.mjs",
  "test/browser-instrumentation.html",
  "test/browser-suite.html",
  "src/index.html",
  "src/css/styles.css",
  "src/js/vendor.js",
  "src/js/app.js",
  "src/js/online.js",
  "src/js/network-check.js",
  "src/js/enhanced-inputs.js",
  "src/js/repeat-inputs.js",
  "src/js/virtual-keyboard.js",
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

test("the current release snapshot exists and matches the compiled app", () => {
  const snapshot = join(root, versionedFile);
  assert.ok(existsSync(snapshot), `${versionedFile} is missing`);
  assert.ok(
    readFileSync(join(root, "index.html")).equals(readFileSync(snapshot)),
    `index.html does not match ${versionedFile}`,
  );
});

test("versions.json lists the current snapshot", () => {
  assert.deepEqual(
    JSON.parse(read("versions.json")),
    { versions: [{ version: `v${appVersion}`, file: versionedFile }] },
  );
});

const htmlFiles = ["index.html", versionedFile];

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
    assert.doesNotMatch(html, /<link[^>]+href=["' ]*https?:\/\//i);
  });
}

test("repository source has no unresolved merge markers", () => {
  const offenders = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const name = entry.name;
      const path = join(dir, name);
      if (name === ".git" || name.endsWith(".png")) continue;
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
