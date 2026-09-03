// CIDv1 raw sha2-256 is a name for the SHA-256 we already publish.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cidV1RawSha256FromBytes, cidV1RawSha256FromDigest, cidLineForFile } from "../scripts/cid.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("hello world matches the published raw CIDv1 vector", () => {
  // printf 'hello world' | ipfs cid format --codec raw --mh-type sha2-256 --version 1
  // (same bytes as SHA-256 of the string, wrapped as CIDv1 raw).
  assert.equal(cidV1RawSha256FromBytes(Buffer.from("hello world")), "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e");
});

test("the CID is a wrapping of the SHA-256 digest, not a second hash", () => {
  const bytes = Buffer.from("hello world");
  const digest = createHash("sha256").update(bytes).digest();
  assert.equal(cidV1RawSha256FromDigest(digest), cidV1RawSha256FromBytes(bytes));
});

test("empty input has a stable CID", () => {
  assert.equal(cidV1RawSha256FromBytes(Buffer.alloc(0)), "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku");
});

test("a truncated digest is refused", () => {
  assert.throws(() => cidV1RawSha256FromDigest(Buffer.alloc(31)), /32 bytes/);
});

test("the CLI prints GNU sha256sum-shaped lines", () => {
  const out = execFileSync(process.execPath, [join(root, "scripts/cid.mjs"), join(root, "LICENSE")], { encoding: "utf8" });
  assert.match(out, /^bafkrei[a-z2-7]+  LICENSE\n$/);
  assert.equal(out, cidLineForFile(join(root, "LICENSE")));
});

test("committed CID.txt names the same bytes as SHA256SUMS.txt", () => {
  const sums = read("SHA256SUMS.txt").trim().split(/\s+/);
  assert.equal(sums[1], "entropylab.html");
  const digest = Buffer.from(sums[0], "hex");
  assert.equal(digest.length, 32);
  const cid = cidV1RawSha256FromDigest(digest);
  const line = read("CID.txt").trim();
  assert.equal(line, `${cid}  entropylab.html`);
});

test("the CID script never talks to the network, browser storage, or a CSPRNG", () => {
  const source = read("scripts/cid.mjs");
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /\bWebSocket\b/);
  assert.doesNotMatch(source, /\blocalStorage\b/);
  assert.doesNotMatch(source, /\bindexedDB\b/);
  assert.doesNotMatch(source, /\bMath\.random\b/);
  assert.doesNotMatch(source, /\bgetRandomValues\b/);
});

test("a built entropylab.html matches CID.txt when it is the published artifact", () => {
  const html = join(root, "entropylab.html");
  if (!existsSync(html)) return;
  // PRs rebuild the HTML with a different git revision stamp, so the bytes
  // (and CID) differ from the last rock artifact. CID.txt tracks SHA256SUMS.
  const published = read("SHA256SUMS.txt").trim().split(/\s+/)[0];
  const actual = createHash("sha256").update(readFileSync(html)).digest("hex");
  if (actual !== published) return;
  assert.equal(cidLineForFile(html), read("CID.txt"));
});
