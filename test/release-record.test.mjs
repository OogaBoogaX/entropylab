// The v1.0.0 record was wrong: the changelog called its artifact
// byte-identical to rc3 and published the rc3 digest (`bdf048…`), but the
// tag's page is a later rebuild (`3804d578…`) whose `SHA256SUMS.txt` matches
// it while the four carried-over signatures still cover the old file. A
// reader following the documented steps therefore fails at `gpg --verify`,
// and the published digest names a different page.
//
// The tag is immutable, so the record is repaired rather than rewritten:
// the changelog must state the digest that the tag actually carries and the
// signature break, and those facts are pinned here against the tag itself.
// Run with `npm test`; the tag lookups skip when the checkout does not have
// the tag (a shallow CI checkout) or the tools are absent.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");
const ARCHIVE = "3804d57898224b8cfccfcacc8aa7c32cd93d514896de7e045e14ed35c22cf2f7";
const SIGNED = "bdf048ebbf9286a3b18998f28e1cccef1f9f9a0284a880c1864875f903adeb8d";

const section = () => {
  const changelog = read("CHANGELOG.md");
  const start = changelog.indexOf("## v1.0.0 — ");
  assert.ok(start >= 0, "CHANGELOG.md has a v1.0.0 section");
  const end = changelog.indexOf("\n## ", start + 1);
  return end >= 0 ? changelog.slice(start, end) : changelog.slice(start);
};

const gitShow = (path) => {
  try {
    return execFileSync("git", ["show", `v1.0.0:${path}`], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null;
  }
};

test("the v1.0.0 section states the digest the tag carries", () => {
  const text = section();
  assert.match(text, new RegExp(ARCHIVE), "the published artifact's SHA-256 is recorded");
  assert.match(text, /SHA-256/, "it is named as the artifact's SHA-256");
});

test("the v1.0.0 section no longer claims byte-identity with rc3", () => {
  const text = section();
  assert.doesNotMatch(text, /byte-identical to rc3/);
  assert.match(text, new RegExp(SIGNED), "the digest the signatures cover is still named for context");
});

test("the v1.0.0 section says the signatures do not verify", () => {
  assert.match(section(), /(do not verify|not valid|fail)/i, "the signature break is stated");
});

test("the recorded digest is the tag's page, and its sums agree", { skip: gitShow("entropylab.html") === null && "the v1.0.0 tag is not in this checkout" }, () => {
  const html = gitShow("entropylab.html");
  const digest = execFileSync("sha256sum", { input: html, encoding: "utf8" }).split(" ")[0];
  assert.equal(digest, ARCHIVE, "the changelog names the page the tag actually contains");
  const sums = gitShow("SHA256SUMS.txt").toString("utf8");
  assert.match(sums, new RegExp(`^${ARCHIVE}  entropylab\\.html$`, "m"), "the tag's manifest agrees with the page");
});

const tools = process.platform !== "win32" && ["bash", "gpg"].every((tool) => spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0);

test("the tag's signatures are known-bad, as the record says", { skip: (!tools || gitShow("SHA256SUMS.asc") === null) && "needs the tag and gpg" }, () => {
  const home = mkdtempSync(join(tmpdir(), "release-record-"));
  try {
    const gpg = (...args) => execFileSync("gpg", ["--batch", "--homedir", home, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    for (const name of readdirSync(join(root, "keys")).filter((file) => file.endsWith(".asc"))) gpg("--import", join(root, "keys", name));
    const dir = mkdtempSync(join(tmpdir(), "release-record-files-"));
    try {
      const sums = gitShow("SHA256SUMS.txt"), sig = gitShow("SHA256SUMS.asc");
      const verify = (files) => spawnSync("gpg", ["--batch", "--homedir", home, "--verify", ...files], { stdio: "ignore" }).status;
      const sumsPath = join(dir, "SHA256SUMS.txt"), sigPath = join(dir, "SHA256SUMS.asc");
      write(sumsPath, sums);
      write(sigPath, sig);
      assert.notEqual(verify([sigPath, sumsPath]), 0, "the tag's signatures do not verify against the tag's sums");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

const write = (path, bytes) => {
  // The git blobs are Buffers; write them verbatim.
  const { writeFileSync } = process.getBuiltinModule("node:fs");
  writeFileSync(path, bytes);
};
