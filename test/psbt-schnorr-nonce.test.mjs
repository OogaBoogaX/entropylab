import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hodlLooksSchnorr, hodlParseSchnorr, hodlTapSighashProblems, hodlCompareSchnorrNonces, hodlTapKeySigs, hodlTapScriptSigs } from "../src/js/psbt-schnorr.js";

const root = dirname(fileURLToPath(import.meta.url));

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const rA = new Uint8Array(32).fill(0x11);
const key = new Uint8Array(32).fill(0x33);

test("parses 64 and 65 byte Schnorr signatures", () => {
  const raw = new Uint8Array(64);
  raw.set(rA);
  assert.equal(hodlParseSchnorr(raw).sighash, 0);
  const raw2 = new Uint8Array(65);
  raw2.set(rA);
  raw2[64] = 0x81;
  assert.equal(hodlParseSchnorr(raw2).sighash, 0x81);
});

test("DEFAULT and ALL are safe; ANYONECANPAY is not", () => {
  const label = (p) => "0x" + p.toString(16);
  assert.deepEqual(hodlTapSighashProblems(0, 1, label), []);
  assert.ok(hodlTapSighashProblems(0x82, 0x82, label).length >= 2);
});

test("ANYONECANPAY|ALL drops input commitment while NONE/SINGLE drop outputs (issue #333)", () => {
  const label = (p) => "0x" + p.toString(16);
  const inputs = hodlTapSighashProblems(null, 0x81, label);
  assert.equal(inputs.length, 1);
  assert.ok(inputs[0].includes("does not commit to all shown inputs"), inputs[0]);
  assert.ok(!inputs[0].includes("outputs"), inputs[0]);
  for (const value of [0x02, 0x03, 0x82, 0x83]) {
    const problems = hodlTapSighashProblems(value, null, label);
    assert.ok(problems[0].includes("does not commit to all shown outputs"), `0x${value.toString(16)}: ${problems[0]}`);
  }
  const undefinedByte = hodlTapSighashProblems(null, 0x7f, label);
  assert.ok(undefinedByte[0].includes("not a defined Taproot sighash"), undefinedByte[0]);
});

test("same R on two inputs is flagged", () => {
  const scan = hodlCompareSchnorrNonces([
    { input: 0, r: rA, pubkey: key },
    { input: 1, r: rA, pubkey: key },
  ], eq);
  assert.equal(scan.possible.length, 1);
});

test("tap key sig records are collected", () => {
  const raw = new Uint8Array(64);
  raw.set(rA);
  const keys = hodlTapKeySigs([{ type: 19, keydata: new Uint8Array(), val: raw }], (e, t) => e.filter((x) => x.type === t));
  assert.equal(keys.length, 1);
});

test("looksSchnorr decides by length and suffix only, never the first signature byte (issue #333)", () => {
  assert.equal(hodlLooksSchnorr(null), false);
  assert.equal(hodlLooksSchnorr(new Uint8Array(63)), false);
  assert.equal(hodlLooksSchnorr(new Uint8Array(64)), true);
  const derLookalike = new Uint8Array(65);
  derLookalike[0] = 0x30; // DER's sequence marker is a fine R.x first byte
  derLookalike[64] = 0x01;
  assert.equal(hodlLooksSchnorr(derLookalike), true, "first byte 0x30 must not classify the signature as DER");
  // The 65th byte must be a defined Taproot sighash: explicit 0x00 is invalid
  // (DEFAULT is only ever the 64-byte form), and undefined bytes are invalid.
  const zeroSuffix = new Uint8Array(65); // suffix defaults to 0x00
  assert.equal(hodlLooksSchnorr(zeroSuffix), false, "explicit 0x00 suffix is not SIGHASH_DEFAULT");
  const undefinedSuffix = new Uint8Array(65);
  undefinedSuffix[64] = 0x04;
  assert.equal(hodlLooksSchnorr(undefinedSuffix), false, "undefined sighash byte");
  for (const defined of [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]) {
    const valid = new Uint8Array(65);
    valid[64] = defined;
    assert.equal(hodlLooksSchnorr(valid), true, `sighash 0x${defined.toString(16)}`);
  }
  assert.equal(hodlLooksSchnorr(new Uint8Array(66)), false);
  assert.equal(hodlParseSchnorr(new Uint8Array(10)), null);
});

test("parse splits r and s and defaults the sighash to DEFAULT", () => {
  const raw = new Uint8Array(64);
  raw.set(rA, 0);
  raw.set(new Uint8Array(32).fill(0x22), 32);
  const parsed = hodlParseSchnorr(raw);
  assert.deepEqual(parsed.r, rA);
  assert.deepEqual(parsed.s, new Uint8Array(32).fill(0x22));
  assert.equal(parsed.sighash, 0, "SIGHASH_DEFAULT when the suffix byte is absent");
});

test("sighash problems flag unsafe declarations, suffixes, and disagreements", () => {
  const label = (p) => "0x" + p.toString(16);
  assert.deepEqual(hodlTapSighashProblems(null, null, label), []);
  assert.deepEqual(hodlTapSighashProblems(1, 0, label), [], "DEFAULT and ALL are interchangeable");
  assert.deepEqual(hodlTapSighashProblems(0, 0x81, label).length, 2, "unsafe suffix that also disagrees with the declaration");
  assert.deepEqual(hodlTapSighashProblems(0x83, null, label).length, 1, "unsafe declaration alone");
});

test("tap script sig records slice the x-only pubkey out of the keydata", () => {
  const raw = new Uint8Array(64);
  raw.set(rA);
  const leafHash = new Uint8Array(32).fill(0x44);
  const withLeaf = hodlTapScriptSigs([{ type: 20, keydata: Uint8Array.from([...key, ...leafHash]), val: raw }], (e, t) => e.filter((x) => x.type === t));
  assert.equal(withLeaf.length, 1);
  assert.deepEqual(withLeaf[0].pubkey, key);
  assert.deepEqual(withLeaf[0].r, rA);
  assert.equal(withLeaf[0].source, "tap-script");
  const shortKeydata = hodlTapScriptSigs([{ type: 20, keydata: new Uint8Array(31), val: raw }], (e, t) => e.filter((x) => x.type === t));
  assert.deepEqual(shortKeydata[0].pubkey, new Uint8Array(), "short keydata yields no pubkey");
  const unparseable = hodlTapScriptSigs([{ type: 20, keydata: key, val: new Uint8Array(10) }], (e, t) => e.filter((x) => x.type === t));
  assert.equal(unparseable[0].r, null, "an unparseable value still records the pubkey");
  assert.deepEqual(unparseable[0].pubkey, key);
});

test("nonce compare ignores same-input pairs, key mismatches, and missing r values", () => {
  const sameInput = hodlCompareSchnorrNonces([
    { input: 0, r: rA, pubkey: key },
    { input: 0, r: rA, pubkey: key },
  ], eq);
  assert.equal(sameInput.possible.length, 0, "two signatures on the same input are not cross-input reuse");
  const differentKeys = hodlCompareSchnorrNonces([
    { input: 0, r: rA, pubkey: key },
    { input: 1, r: rA, pubkey: new Uint8Array(32).fill(0x55) },
  ], eq);
  assert.equal(differentKeys.possible.length, 0, "same R under different keys is not reuse");
  const missingR = hodlCompareSchnorrNonces([
    { input: 0, r: null, pubkey: key },
    { input: 1, r: rA, pubkey: key },
  ], eq);
  assert.equal(missingR.possible.length, 0, "unparseable records never flag");
  const flagged = hodlCompareSchnorrNonces([
    { input: 0, r: rA, pubkey: key },
    { input: 1, r: rA, pubkey: key },
    { input: 2, r: rA, pubkey: key },
  ], eq);
  assert.equal(flagged.possible.length, 3, "every cross-input pair of the shared R is reported");
  assert.deepEqual(flagged.reused, [], "definite proof is left to the ECDSA comparison");
});

test("the report counts only parseable Schnorr signatures as present (issue #333)", () => {
  // Unparseable values stay in the collection (with r null) so the policy
  // analysis can flag them…
  const keys = hodlTapKeySigs([
    { type: 19, keydata: new Uint8Array(), val: new Uint8Array(64) },
    { type: 19, keydata: new Uint8Array(), val: new Uint8Array(10) },
  ], (e, t) => e.filter((x) => x.type === t));
  assert.equal(keys.length, 2);
  assert.equal(keys.filter((sig) => sig.r).length, 1, "exactly one parses under BIP341");
  // …but the inspector's count lines run on the parseable subset: the
  // per-input "signature(s) present" line and the Taproot total both use the
  // parsed count, and the unparseable entry only shows in the policy problem.
  const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
  assert.match(app, /let parsedTapSignatures = tapSignatures\.reduce/);
  assert.match(app, /tapSignatureCount \+= parsedTapSignatures/);
  assert.match(app, /signatures\.length \+ parsedTapSignatures \? signatures\.length \+ parsedTapSignatures \+ " signature\(s\) present"/);
  assert.doesNotMatch(app, /tapSignatureCount \+= tapSignatures\.length/);
});
