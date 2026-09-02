// The two PSBT safety verdicts that were previously only regex-asserted and
// never executed: the RFC 6979 nonce replay check (plain / Core low-r grind /
// zero-entropy) and the Jade-style anti-exfil commitment check. Both run here
// against the app's real signing facade, with @noble/curves and node:crypto
// as the independent reference.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function slice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

function importLine(module) {
  const match = app.match(new RegExp(`^import \\{[^}]*\\} from "\\./${module}\\.js";$`, "m"));
  assert.ok(match, `import from ./${module}.js`);
  return match[0].replace(`"./${module}.js"`, `"../src/js/${module}.js"`);
}

const source = [
  importLine("hashes"),
  importLine("secp256k1"),
  importLine("coders"),
  importLine("i18n"),
  ...["hodlTaggedSha256", "hodlBytesToBig", "hodlPointFrom", "hodlPointBytes", "hodlEq", "hodlLe32Counter", "hodlIsLowR", "hodlRfc6979Compare", "hodlAntiExfilCommitOk"].map(slice),
  "export { hodlRfc6979Compare, hodlAntiExfilCommitOk };",
].join("\n");

const modulePath = join(root, "test", `.rfc6979-antiexfil-${process.pid}.mjs`);
writeFileSync(modulePath, source);
let api;
try {
  api = await import(pathToFileURL(modulePath).href);
} finally {
  unlinkSync(modulePath);
}
const { hodlRfc6979Compare, hodlAntiExfilCommitOk } = api;

// Fixed public material: the private key 1 and hash-sized labels. No secrets.
const KEY = new Uint8Array(32);
KEY[31] = 1;
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());

const nobleR = (sighash, extraEntropy) => noble.sign(sighash, KEY, { prehash: false, extraEntropy }).slice(0, 32);
const le32 = (n) => {
  const bytes = new Uint8Array(32);
  bytes[0] = n & 255;
  bytes[1] = (n >>> 8) & 255;
  bytes[2] = (n >>> 16) & 255;
  bytes[3] = (n >>> 24) & 255;
  return bytes;
};

// Find deterministic sighashes exercising each verdict branch.
let plainLow = null;
let grindCase = null;
for (let counter = 0; counter < 500 && (!plainLow || !grindCase); counter++) {
  const sighash = sha256(new TextEncoder().encode(`case ${counter}`));
  const plain = nobleR(sighash, false);
  if (!plainLow && plain[0] < 0x80) plainLow = { sighash, r: plain };
  if (!grindCase && plain[0] >= 0x80) {
    const retry1 = nobleR(sighash, le32(1));
    if (retry1[0] < 0x80) grindCase = { sighash, plainR: plain, grindR: retry1 };
  }
}
assert.ok(plainLow && grindCase, "fixture: 500 sighashes must cover both the low-r and the ground branches");

test("a plain RFC 6979 nonce is recognized as such, high or low", () => {
  const low = hodlRfc6979Compare(plainLow.sighash, KEY, plainLow.r);
  assert.equal(low.ok, true);
  assert.match(low.message, /plain deterministic nonce\)\.$/);
  const high = hodlRfc6979Compare(grindCase.sighash, KEY, grindCase.plainR);
  assert.equal(high.ok, true);
  assert.match(high.message, /r is high; Bitcoin Core would grind this one\./);
});

test("a Bitcoin Core low-r grind is recognized with its retry count", () => {
  const result = hodlRfc6979Compare(grindCase.sighash, KEY, grindCase.grindR);
  assert.equal(result.ok, true);
  assert.match(result.message, /low-r grind \(retry 1\)/);
});

test("a zero-entropy-mixed nonce is recognized", () => {
  const sighash = sha256(new TextEncoder().encode("zeros case"));
  const r = nobleR(sighash, new Uint8Array(32));
  const result = hodlRfc6979Compare(sighash, KEY, r);
  assert.equal(result.ok, true);
  assert.match(result.message, /32 zero extra-entropy bytes/);
});

test("an unexplained r warns without accusing", () => {
  const sighash = sha256(new TextEncoder().encode("mismatch case"));
  const result = hodlRfc6979Compare(sighash, KEY, new Uint8Array(32).fill(0x42));
  assert.equal(result.ok, false);
  assert.match(result.message, /Does not match plain RFC 6979/);
  assert.match(result.message, /not evidence of compromise/);
});

// Anti-exfil: the signer reveals opening = k·G and the host nonce; the tweak
// is the s2c/ecdsa/point tagged hash, and the signature's r must commit to
// x((k + tweak)·G). Rebuilt here from primitives.
const taggedHash = (tag, ...chunks) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(new Uint8Array([...tagHash, ...tagHash, ...chunks.flatMap((chunk) => [...chunk])]));
};
const ORDER = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const bigOf = (bytes) => BigInt(`0x${Buffer.from(bytes).toString("hex")}`);

const hostNonce = new Uint8Array(32).fill(0xaa);
const signerK = 3n;
const opening = noble.Point.BASE.multiply(signerK).toBytes(true);
const tweak = bigOf(taggedHash("s2c/ecdsa/point", opening, hostNonce)) % ORDER;
const committedR = noble.Point.BASE.multiply((signerK + tweak) % ORDER).toBytes(true).slice(1);

test("an honest anti-exfil transcript verifies", () => {
  assert.equal(hodlAntiExfilCommitOk(committedR, opening, hostNonce), true);
});

test("a wrong host nonce, tampered r, or foreign opening fails the commitment", () => {
  assert.equal(hodlAntiExfilCommitOk(committedR, opening, new Uint8Array(32).fill(0xbb)), false, "different host nonce");
  const tampered = Uint8Array.from(committedR);
  tampered[31] ^= 1;
  assert.equal(hodlAntiExfilCommitOk(tampered, opening, hostNonce), false, "r one ulp off");
  const otherOpening = noble.Point.BASE.multiply(4n).toBytes(true);
  assert.equal(hodlAntiExfilCommitOk(committedR, otherOpening, hostNonce), false, "a different opening point");
});

test("a non-point opening throws so the caller's try/catch owns the failure", () => {
  assert.throws(() => hodlAntiExfilCommitOk(committedR, new Uint8Array(33), hostNonce));
});
