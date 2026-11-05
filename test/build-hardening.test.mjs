// Build and release hardening (red-team sweep 0eed735, lows). The build
// inlines committed files into one page whose CSP allows inline script, so it
// refuses input that would run or break out where it lands: a "*/" or
// "</script" in the QR-capture license banner, a "</script" in a classic
// script, script or handler markup in a logo SVG, and a symbolic link among
// the inputs. verify-site.mjs and the Pages release step refuse a published
// symbolic link. (The footer gate's half is in release-footer.test.mjs.)
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const COPIED = ["src", "scripts", "assets", "manifest.webmanifest", "package.json"];
const remove = (path) => rmSync(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });

// Builds a copy of the sources after `edit(dir)` has changed it. Returns the
// build's exit status, its log, and whether it wrote a page.
const buildWith = (edit) => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-build-inputs-"));
  try {
    for (const path of COPIED) cpSync(join(root, path), join(dir, path), { recursive: true });
    symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "junction");
    edit(dir);
    const out = join(dir, "out");
    const result = spawnSync(process.execPath, [join(dir, "scripts/build.mjs"), "--out", out], { cwd: dir, encoding: "utf8" });
    return { status: result.status, log: `${result.stdout}${result.stderr}`, wrote: existsSync(join(out, "entropylab.html")) };
  } finally {
    remove(dir);
  }
};
const refused = ({ status, log, wrote }, what) => {
  assert.notEqual(status, 0, `${what}: the build must fail\n${log}`);
  assert.equal(wrote, false, `${what}: no page is written`);
};

test("an unchanged copy of the sources builds, so the refusals below are not vacuous", { timeout: 300000 }, () => {
  const { status, log, wrote } = buildWith(() => {});
  assert.equal(status, 0, log);
  assert.equal(wrote, true);
});

test("a license banner that would end its comment or its script fails the build", { timeout: 600000 }, () => {
  for (const text of ["*/ globalThis.ran = 1; /*", "</script><script>globalThis.ran = 1</script>", "<!-- <script>"]) {
    refused(buildWith((dir) => appendFileSync(join(dir, "src/licenses/ur2.txt"), `\n${text}\n`)), JSON.stringify(text));
  }
});

test("a classic script that would end its <script> element fails the build", { timeout: 300000 }, () => {
  refused(buildWith((dir) => appendFileSync(join(dir, "src/js/online.js"), '\nvar markup = "</script><script>globalThis.ran = 1</script>";\n')), "</script in online.js");
});

test("a logo SVG with script, a handler or template-literal characters fails the build", { timeout: 900000 }, () => {
  for (const insert of [
    "<script>globalThis.ran = 1</script>",
    '<g onload="globalThis.ran = 1"></g>',
    '<g/onload="globalThis.ran = 1"></g>',
    '<rect id="x"onclick="globalThis.ran = 1"/>',
    '<a href="java\tscript:void 0"></a>',
    '<a href="java\nscript:void 0"></a>',
    '<a href="&#106;avascript:void 0"></a>',
    "<text>it's</text>",
    '<a href="javascript:void 0"></a>',
    "<foreignObject></foreignObject>",
    "<text>`${globalThis.ran = 1}`</text>",
    "<text>\\u0041</text>",
  ]) {
    refused(buildWith((dir) => {
      const path = join(dir, "src/assets/logo-dark.svg");
      writeFileSync(path, readFileSync(path, "utf8").replace("</svg>", `${insert}</svg>`));
    }), insert);
  }
});

test("a stylesheet that would end its <style> element fails the build", { timeout: 300000 }, () => {
  refused(buildWith((dir) => appendFileSync(join(dir, "src/css/styles.css"), "\n</style><script>globalThis.ran = 1</script><style>\n")), "</style in styles.css");
});

test("a symbolic link among the build inputs fails the build", { timeout: 300000 }, () => {
  const outside = mkdtempSync(join(tmpdir(), "entropylab-outside-"));
  try {
    refused(buildWith((dir) => {
      // A directory junction needs no extra rights on Windows; elsewhere it
      // is an ordinary directory link.
      cpSync(join(dir, "src/licenses"), join(outside, "licenses"), { recursive: true });
      remove(join(dir, "src/licenses"));
      symlinkSync(join(outside, "licenses"), join(dir, "src/licenses"), "junction");
    }), "src/licenses linked to a directory outside the checkout");
  } finally {
    remove(outside);
  }
});

// A minimal built site that scripts/verify-site.mjs accepts: the page and the
// worker share one PWA version, and every asset it lists is non-empty.
const siteFixture = () => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-verify-site-"));
  mkdirSync(join(dir, "scripts"));
  cpSync(join(root, "scripts/verify-site.mjs"), join(dir, "scripts/verify-site.mjs"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ version: "1.1.0" }));
  writeFileSync(join(dir, "entropylab.html"), '<script src="service-worker.js?v=0123456789abcdef"></script>');
  writeFileSync(join(dir, "service-worker.js"), 'const VERSION = "0123456789abcdef";');
  writeFileSync(join(dir, "manifest.webmanifest"), "{}");
  mkdirSync(join(dir, "assets"));
  for (const name of ["favicon.png", "entropylab-darkmode.png", "pwa-icon-180.png", "pwa-icon-192.png", "pwa-icon-512.png"]) {
    writeFileSync(join(dir, "assets", name), "png");
  }
  return dir;
};
const verifySite = (dir) => spawnSync(process.execPath, [join(dir, "scripts/verify-site.mjs")], { cwd: dir, encoding: "utf8" });

// File links need extra rights on Windows; directory junctions do not.
const fileLinks = (() => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-link-probe-"));
  try {
    writeFileSync(join(dir, "target"), "x");
    symlinkSync(join(dir, "target"), join(dir, "link"), "file");
    return true;
  } catch {
    return false;
  } finally {
    remove(dir);
  }
})();

test("the site check refuses an assets directory that is a symbolic link", () => {
  const dir = siteFixture(), outside = mkdtempSync(join(tmpdir(), "entropylab-outside-"));
  try {
    const plain = verifySite(dir);
    assert.equal(plain.status, 0, `the fixture passes as it is\n${plain.stdout}${plain.stderr}`);
    renameSync(join(dir, "assets"), join(outside, "assets"));
    symlinkSync(join(outside, "assets"), join(dir, "assets"), "junction");
    assert.notEqual(verifySite(dir).status, 0, "assets/ linked to a directory outside the site");
  } finally {
    remove(dir);
    remove(outside);
  }
});

test("the site check refuses a page, worker or manifest that is a symbolic link", { skip: !fileLinks && "file links need extra rights on this system" }, () => {
  for (const name of ["entropylab.html", "service-worker.js", "manifest.webmanifest"]) {
    const dir = siteFixture(), outside = mkdtempSync(join(tmpdir(), "entropylab-outside-"));
    try {
      renameSync(join(dir, name), join(outside, name));
      symlinkSync(join(outside, name), join(dir, name), "file");
      assert.notEqual(verifySite(dir).status, 0, `${name} linked to a file outside the site`);
    } finally {
      remove(dir);
      remove(outside);
    }
  }
});

// The run: script of a named step in a workflow, as the runner executes it.
const stepScript = (workflowPath, stepName) => {
  const text = readFileSync(join(root, workflowPath), "utf8");
  const start = text.indexOf(`      - name: ${stepName}\n`);
  assert.ok(start >= 0, `${workflowPath} has the step "${stepName}"`);
  const rest = text.slice(start + 1);
  const end = rest.search(/^      - /m);
  const script = (end >= 0 ? rest.slice(0, end) : rest).split(/\n +run: \|\n/)[1];
  assert.ok(script, `"${stepName}" runs a script`);
  return script.replace(/^ {10}/gm, "");
};
const git = (cwd, ...args) => execFileSync("git", ["-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" }).trim();
const shellTools = process.platform !== "win32" && ["bash", "git", "tar"].every((tool) => spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0);

test("the Pages release step refuses to publish a committed symbolic link", { skip: !shellTools && "needs bash, git and tar" }, () => {
  const temp = mkdtempSync(join(tmpdir(), "entropylab-pages-site-"));
  try {
    // A workspace whose commits carry the files the step archives; the
    // second commit adds a symbolic link under assets/.
    const workspace = join(temp, "workspace");
    mkdirSync(join(workspace, "assets"), { recursive: true });
    mkdirSync(join(workspace, "src"));
    for (const name of ["robots.txt", "sitemap.xml", "llms.txt", "manifest.webmanifest", "assets/favicon.png"]) writeFileSync(join(workspace, name), "x\n");
    writeFileSync(join(workspace, "src/service-worker.js"), 'const VERSION = "{{PWA_VERSION}}";\n');
    git(temp, "init", "-q", workspace);
    git(workspace, "add", "-A");
    git(workspace, "commit", "-qm", "site");
    const plain = git(workspace, "rev-parse", "HEAD");
    symlinkSync("../robots.txt", join(workspace, "assets/linked.txt"));
    git(workspace, "add", "-A");
    git(workspace, "commit", "-qm", "a link");
    const linked = git(workspace, "rev-parse", "HEAD");
    // A top-level file as a link: cp would follow it and publish its target.
    git(workspace, "checkout", "-q", plain);
    rmSync(join(workspace, "manifest.webmanifest"));
    symlinkSync(join(temp, "outside.txt"), join(workspace, "manifest.webmanifest"));
    writeFileSync(join(temp, "outside.txt"), "outside the repository\n");
    git(workspace, "add", "-A");
    git(workspace, "commit", "-qm", "a top-level link");
    const topLinked = git(workspace, "rev-parse", "HEAD");

    const script = stepScript(".github/workflows/pages-release.yml", "Build the site");
    const run = (name, footerCommit) => {
      const runnerTemp = join(temp, name);
      mkdirSync(join(runnerTemp, "release"), { recursive: true });
      writeFileSync(join(runnerTemp, "release/entropylab.html"), '<script src="service-worker.js?v=0123456789abcdef"></script>');
      remove(join(workspace, "_site"));
      const result = spawnSync("bash", ["-c", script], { cwd: runnerTemp, env: { ...process.env, RUNNER_TEMP: runnerTemp, GITHUB_WORKSPACE: workspace, FOOTER_COMMIT: footerCommit }, encoding: "utf8" });
      return { status: result.status, log: `${result.stdout}${result.stderr}` };
    };
    const good = run("plain", plain);
    assert.equal(good.status, 0, good.log);
    const bad = run("linked", linked);
    assert.notEqual(bad.status, 0, "a committed link must stop the site build");
    assert.match(bad.log, /title=Symbolic link::/);
    const top = run("top-linked", topLinked);
    assert.notEqual(top.status, 0, "a top-level link must stop it before cp follows it");
    assert.match(top.log, /title=Symbolic link::/);
    assert.equal(existsSync(join(workspace, "_site/manifest.webmanifest")), false, "nothing was copied");
  } finally {
    remove(temp);
  }
});
