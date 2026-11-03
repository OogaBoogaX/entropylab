// The release checks (pages-release.yml, release-assets.yml) read the build
// footer through scripts/release-footer.mjs (#1406). These tests pin that
// parser to the real markup (the template in src/shell.html and the committed
// build, where the commit sits inside <code>), and run both workflows' real
// footer steps against a throwaway repository with a tag. A parser that
// stopped at the first "<" would find no commit and fail every release.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { releaseFooter } from "../scripts/release-footer.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");
const footerHtml = (version, commit) => `<html><span class="page-footer-build">v${version} · commit <code>${commit}</code> <img hidden></span></html>`;

test("the parser reads the footer the template renders", () => {
  const shell = read("src/shell.html");
  assert.ok(shell.includes('<span class="page-footer-build">v{{VERSION}} · commit <code>{{COMMIT_SHORT}}</code>'), "src/shell.html still renders the footer this parser reads");
  const rendered = shell.replaceAll("{{VERSION}}", "1.1.0").replaceAll("{{COMMIT_SHORT}}", "0123abc");
  assert.deepEqual(releaseFooter(rendered), { version: "1.1.0", commit: "0123abc" });
});

test("the parser reads the committed build's footer", () => {
  const footer = releaseFooter(read("entropylab.html"));
  assert.ok(!footer.error, footer.error);
  assert.match(footer.version, /^\d+\.\d+\.\d+(-dev)?$/, "a release-shaped version");
  assert.match(footer.commit, /^[0-9a-f]{7,40}$/, "a short commit");
});

test("the parser fails closed", () => {
  const good = footerHtml("1.1.0", "0123abc");
  assert.ok(releaseFooter("<html></html>").error, "no footer");
  assert.deepEqual(releaseFooter(good + good), { version: "1.1.0", commit: "0123abc" }, "copies that agree are one footer");
  assert.ok(releaseFooter(good + footerHtml("1.1.0", "4567def")).error, "copies that disagree");
  assert.ok(releaseFooter('<span class="page-footer-build">v1.1.0 · commit 0123abc</span>').error, "a commit outside <code>");
  assert.ok(releaseFooter('<span class="page-footer-build">v1.1.0 · commit <code>xyz</code>').error, "a commit that is not hex");
  assert.deepEqual(releaseFooter(good), { version: "1.1.0", commit: "0123abc" });
  assert.deepEqual(releaseFooter(footerHtml("1.1.0-dev", "0123abc")), { version: "1.1.0-dev", commit: "0123abc" });
});

test("the command line prints '<version> <commit>', which the workflows split on the space", () => {
  const out = execFileSync(process.execPath, [join(root, "scripts/release-footer.mjs"), join(root, "entropylab.html")], { encoding: "utf8" }).trim();
  const footer = releaseFooter(read("entropylab.html"));
  assert.equal(out, `${footer.version} ${footer.commit}`);
  assert.equal(out.split(" ").length, 2, "exactly one space, so the workflows can split it");
});

// The run: script of a named step, as the runner would execute it.
const stepScript = (workflowPath, stepName) => {
  const text = read(workflowPath);
  const start = text.indexOf(`      - name: ${stepName}\n`);
  assert.ok(start >= 0, `${workflowPath} has the step "${stepName}"`);
  const rest = text.slice(start + 1);
  const end = rest.search(/^      - /m);
  const step = end >= 0 ? rest.slice(0, end) : rest;
  const script = step.split(/\n +run: \|\n/)[1];
  assert.ok(script, `"${stepName}" runs a script`);
  return script.replace(/^ {10}/gm, "");
};

const git = (cwd, ...args) => execFileSync("git", ["-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", ...args], { encoding: "utf8" }).trim();
const shellTools = process.platform !== "win32" && ["bash", "git"].every((tool) => spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0);

test("both workflows' footer steps accept the release's own footer and refuse any other", { skip: !shellTools && "needs bash and git" }, () => {
  const temp = mkdtempSync(join(tmpdir(), "release-footer-"));
  try {
    // A workspace with the parser, a tagged commit and a commit off the tag.
    const workspace = join(temp, "workspace");
    mkdirSync(join(workspace, "scripts"), { recursive: true });
    copyFileSync(join(root, "scripts/release-footer.mjs"), join(workspace, "scripts/release-footer.mjs"));
    git(temp, "init", "-q", workspace);
    git(workspace, "add", "-A");
    git(workspace, "commit", "-qm", "release");
    git(workspace, "tag", "v9.9.9");
    const tagged = git(workspace, "rev-parse", "--short=7", "HEAD");
    // pages-release.yml's resolve step hands the footer step the tag's commit
    // through GITHUB_ENV; release-assets.yml resolves it in the step itself.
    const tagCommit = git(workspace, "rev-parse", "v9.9.9^{commit}");
    git(workspace, "checkout", "-qb", "elsewhere");
    writeFileSync(join(workspace, "other.txt"), "not in the tag's history\n");
    git(workspace, "add", "-A");
    git(workspace, "commit", "-qm", "elsewhere");
    const elsewhere = git(workspace, "rev-parse", "--short=7", "HEAD");
    git(workspace, "checkout", "-q", "v9.9.9");

    for (const [path, step] of [
      [".github/workflows/pages-release.yml", "Check the footer names this release"],
      [".github/workflows/release-assets.yml", "Check the footer names this release"],
    ]) {
      const script = stepScript(path, step);
      const run = (name, html) => {
        const runnerTemp = join(temp, `${name}-${path.split("/").pop()}`);
        mkdirSync(join(runnerTemp, "release"), { recursive: true });
        writeFileSync(join(runnerTemp, "release/entropylab.html"), html);
        const githubEnv = join(runnerTemp, "github-env");
        writeFileSync(githubEnv, "");
        const result = spawnSync("bash", ["-c", script], { cwd: runnerTemp, env: { ...process.env, RUNNER_TEMP: runnerTemp, GITHUB_WORKSPACE: workspace, TAG: "v9.9.9", TAG_COMMIT: tagCommit, GITHUB_ENV: githubEnv }, encoding: "utf8" });
        return { status: result.status, log: `${result.stdout}${result.stderr}`, env: readFileSync(githubEnv, "utf8") };
      };
      const good = run("good", footerHtml("9.9.9", tagged));
      assert.equal(good.status, 0, `${path}: ${good.log}`);
      if (path.endsWith("pages-release.yml")) {
        assert.match(good.env, new RegExp(`^FOOTER_COMMIT=${tagCommit}$`, "m"), "the footer's commit is handed to the build step");
      }
      const wrongVersion = run("version", footerHtml("9.9.8", tagged));
      assert.notEqual(wrongVersion.status, 0, `${path}: another version must fail`);
      assert.match(wrongVersion.log, /title=Footer version::/);
      const offTag = run("history", footerHtml("9.9.9", elsewhere));
      assert.notEqual(offTag.status, 0, `${path}: a commit outside the tag's history must fail`);
      assert.match(offTag.log, /title=Footer commit::/);
      const noFooter = run("none", "<html></html>");
      assert.notEqual(noFooter.status, 0, `${path}: a page without a footer must fail`);
      assert.match(noFooter.log, /title=Footer::/);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
