// The v1.0.0 release assets and the files committed inside its tag are
// different artifacts. The release page and manifest carry SIGNED, and the
// release signatures verify. The tag tree instead carries the earlier
// TAG_TREE page and a manifest for it, but a stale signature file that does
// not verify. The record must keep those two cases distinct: verification
// instructions use the release assets, never the tag-tree copies.
//
// Pin the tag-tree facts against the immutable tag itself. Those lookups
// skip when a shallow checkout lacks the tag or the required tools. Run with
// `npm test`.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");
const TAG_TREE = "3804d57898224b8cfccfcacc8aa7c32cd93d514896de7e045e14ed35c22cf2f7";
const TAG_FOOTER = "108becadc6824b08b59a34a721a33d7fcc6540c6";
const SIGNED = "bdf048ebbf9286a3b18998f28e1cccef1f9f9a0284a880c1864875f903adeb8d";
// This immutable commit carries the same SHA256SUMS.asc as the v1.0.0
// release asset; the stale file inside the v1.0.0 tag is a different file.
const RELEASE_SIGNATURES = "488f533c6433b484d6db05c616bd47190b4c0869";

const section = (text, heading) => {
  const start = text.indexOf(heading);
  assert.ok(start >= 0, `${heading} exists`);
  const end = text.indexOf("\n## ", start + 1);
  return end >= 0 ? text.slice(start, end) : text.slice(start);
};

const gitShowAt = (revision, path) => {
  try {
    return execFileSync("git", ["show", `${revision}:${path}`], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null;
  }
};
const gitShow = (path) => gitShowAt("v1.0.0", path);

test("the v1.0.0 record names the signed release asset, not the tag-tree page, as the release", () => {
  const changelog = section(read("CHANGELOG.md"), "## v1.0.0 — ");
  assert.match(changelog, new RegExp(SIGNED));
  assert.match(changelog, /release asset/);
  const guide = section(read("docs/Verify_Your_Download.md"), "### Known issue: v1.0.0");
  assert.match(guide, new RegExp(SIGNED));
  assert.match(guide, /release downloads are consistent/);
});

test("the known-issue record identifies the stale tag-tree artifact separately", () => {
  const changelog = section(read("CHANGELOG.md"), "## v1.0.0 — ");
  const guide = section(read("docs/Verify_Your_Download.md"), "### Known issue: v1.0.0");
  for (const text of [changelog, guide]) {
    assert.match(text, new RegExp(TAG_TREE));
    assert.match(text, /tag/);
    assert.match(text, /stale signature file does not verify/);
  }
  assert.match(guide, new RegExp(TAG_FOOTER));
});

test("the tag carries the earlier page and a matching manifest, not the release page", { skip: gitShow("entropylab.html") === null && "the v1.0.0 tag is not in this checkout" }, () => {
  const html = gitShow("entropylab.html");
  const digest = createHash("sha256").update(html).digest("hex");
  assert.equal(digest, TAG_TREE);
  assert.notEqual(digest, SIGNED);
  assert.ok(html.toString("utf8").includes(`data-commit="${TAG_FOOTER}"`));
  const sums = gitShow("SHA256SUMS.txt").toString("utf8");
  assert.match(sums, new RegExp(`^${TAG_TREE}  entropylab\\.html$`, "m"));
  assert.doesNotMatch(sums, new RegExp(SIGNED));
});

const tools = process.platform !== "win32" && ["bash", "gpg"].every((tool) => spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0);

test("the tag-tree signatures fail against its sums and the release signatures pass against the release manifest", { skip: (!tools || gitShow("SHA256SUMS.asc") === null || gitShowAt(RELEASE_SIGNATURES, "SHA256SUMS.asc") === null) && "needs the release history and gpg" }, () => {
  const home = mkdtempSync(join(tmpdir(), "release-record-"));
  try {
    const gpg = (...args) => execFileSync("gpg", ["--batch", "--homedir", home, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    for (const name of readdirSync(join(root, "keys")).filter((file) => file.endsWith(".asc"))) gpg("--import", join(root, "keys", name));
    const dir = mkdtempSync(join(tmpdir(), "release-record-files-"));
    try {
      const sumsPath = join(dir, "SHA256SUMS.txt"), sigPath = join(dir, "SHA256SUMS.asc");
      writeFileSync(sumsPath, gitShow("SHA256SUMS.txt"));
      writeFileSync(sigPath, gitShow("SHA256SUMS.asc"));
      const status = spawnSync("gpg", ["--batch", "--homedir", home, "--verify", sigPath, sumsPath], { stdio: "ignore" }).status;
      assert.notEqual(status, 0, "the tag-tree signatures do not verify against the tag-tree sums");
      const releaseSums = read("test/fixtures/ots/entropylab-v1.0.0/SHA256SUMS.txt");
      assert.match(releaseSums, new RegExp(`^${SIGNED}  entropylab\\.html$`, "m"));
      writeFileSync(sumsPath, releaseSums);
      writeFileSync(sigPath, gitShowAt(RELEASE_SIGNATURES, "SHA256SUMS.asc"));
      const releaseStatus = spawnSync("gpg", ["--batch", "--homedir", home, "--verify", sigPath, sumsPath], { stdio: "ignore" }).status;
      assert.equal(releaseStatus, 0, "the published release signatures verify against the signed release manifest");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
