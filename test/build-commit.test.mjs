// The footer stamps the last commit that changed a build input, not HEAD.
// Contract: a commit that touches no build input (docs, the changelog,
// release signatures) must leave entropylab.html byte-identical, so the sums
// signed for a release stay valid after they land on rock; a commit that
// touches any build input must move the stamp to itself; and a build must
// refuse a shallow clone, where the lookup cannot see past the truncated
// history and would name the wrong commit.
//
// Each case builds a throwaway git repository holding a copy of the build's
// sources, so the expected commit is the one the test itself just made and
// the suite does not depend on this checkout's history (CI checkouts may be
// shallow). Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const COPIED = ["src", "scripts", "assets", "manifest.webmanifest", "package.json", "package-lock.json"];

const git = (cwd, ...args) => execFileSync("git", [
  "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
  "-c", "core.autocrlf=false", ...args,
], { cwd, encoding: "utf8" }).trim();

const linkModules = (dir) => symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "junction");

const commit = (repo, message) => {
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", message);
  return git(repo, "rev-parse", "HEAD");
};

const build = (repo, out, ...flags) => spawnSync(process.execPath, [join(repo, "scripts/build.mjs"), "--out", out, ...flags], { cwd: repo, encoding: "utf8" });

const stampOf = (html) => {
  const match = html.match(/data-commit="([0-9a-f]{40}|unknown)"/);
  assert.ok(match, "the built page carries a data-commit stamp");
  return match[1];
};

const buildStamp = (repo, out) => {
  const result = build(repo, out);
  assert.equal(result.status, 0, result.stderr);
  const html = readFileSync(join(out, "entropylab.html"), "utf8");
  return { html, stamp: stampOf(html) };
};

const withRepo = (fn) => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-build-commit-"));
  try {
    const repo = join(dir, "repo");
    for (const path of COPIED) cpSync(join(root, path), join(repo, path), { recursive: true });
    git(repo, "init", "-q");
    // node_modules is linked, not committed, so commits record the sources alone
    writeFileSync(join(repo, ".gitignore"), "node_modules\n");
    linkModules(repo);
    return fn({ dir, repo, sources: commit(repo, "sources") });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

test("a commit that touches no build input leaves the artifact byte-identical", { timeout: 120000 }, () => {
  withRepo(({ dir, repo, sources }) => {
    const before = buildStamp(repo, join(dir, "out-before"));
    assert.equal(before.stamp, sources);

    writeFileSync(join(repo, "CHANGELOG.md"), "# Changelog\n");
    writeFileSync(join(repo, "SHA256SUMS.asc"), "signature\n");
    const docs = commit(repo, "docs and signatures only");
    assert.notEqual(docs, sources);

    const after = buildStamp(repo, join(dir, "out-after"));
    assert.equal(after.stamp, sources, "the stamp stays on the last commit that changed a build input");
    assert.equal(after.html, before.html, "entropylab.html must not change when no build input did");
  });
});

test("a commit to any build input moves the stamp to that commit", { timeout: 300000 }, () => {
  withRepo(({ dir, repo }) => {
    // one file from each kind of input the build reads: the bundled sources,
    // the root assets it inlines, the dependency pins, and the build itself
    const touches = {
      "src/css/styles.css": "\n",
      "assets/favicon.png": "\0",
      "manifest.webmanifest": "\n",
      "package.json": "\n",
      "package-lock.json": "\n",
      "scripts/build.mjs": "\n// touched\n",
    };
    for (const [path, suffix] of Object.entries(touches)) {
      appendFileSync(join(repo, path), suffix);
      const changed = commit(repo, `touch ${path}`);
      writeFileSync(join(repo, "NOTES.md"), `after ${path}\n`);
      commit(repo, "docs after the change");
      assert.equal(buildStamp(repo, join(dir, `out-${path.replace(/\W/g, "-")}`)).stamp, changed, `a change to ${path} must move the stamp`);
    }
  });
});

test("a build refuses a shallow clone, release and test-hook staging alike", { timeout: 120000 }, () => {
  withRepo(({ dir, repo }) => {
    writeFileSync(join(repo, "NOTES.md"), "docs\n");
    commit(repo, "docs");
    const shallow = join(dir, "shallow");
    git(dir, "clone", "-q", "--depth", "1", pathToFileURL(repo).href, shallow);
    linkModules(shallow);

    for (const flags of [[], ["--test-hooks"]]) {
      const result = build(shallow, join(dir, "out-shallow"), ...flags);
      assert.notEqual(result.status, 0, `a build (${flags.join(" ") || "release"}) must not guess the commit from truncated history`);
      assert.match(result.stderr, /shallow/);
    }
  });
});
