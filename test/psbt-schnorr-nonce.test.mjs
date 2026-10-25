import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hodlLooksSchnorr, hodlParseSchnorr, hodlTapSighashProblems, hodlCompareSchnorrNonces, hodlTapKeySigs, hodlTapScriptPathSigs, hodlTapScriptSigs, hodlTapWitnessShape } from "../src/js/psbt-schnorr.js";

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

test("same R under the same key is reuse, across inputs or on one input (BIP341 commits to index, path and leaf)", () => {
  const leafA = new Uint8Array(32).fill(0x44);
  const leafB = new Uint8Array(32).fill(0x55);
  const cases = [
    ["two inputs", [
      { input: 0, source: "tap-key", r: rA, pubkey: key },
      { input: 1, source: "tap-key", r: rA, pubkey: key },
    ]],
    ["key path and script path on one input", [
      { input: 0, source: "tap-key", r: rA, pubkey: key },
      { input: 0, source: "tap-script", r: rA, pubkey: key, leafHash: leafA },
    ]],
    ["two different leaves on one input", [
      { input: 0, source: "tap-script", r: rA, pubkey: key, leafHash: leafA },
      { input: 0, source: "tap-script", r: rA, pubkey: key, leafHash: leafB },
    ]],
    ["identical records (an invalid PSBT map fails closed)", [
      { input: 0, source: "tap-script", r: rA, pubkey: key, leafHash: leafA },
      { input: 0, source: "tap-script", r: rA, pubkey: key, leafHash: leafA },
    ]],
  ];
  for (const [name, records] of cases) {
    const scan = hodlCompareSchnorrNonces(records, eq);
    assert.equal(scan.reused.length, 1, name);
    assert.equal(scan.incomplete, 0, name);
  }
  const spread = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, pubkey: key },
    { input: 1, source: "tap-key", r: rA, pubkey: key },
    { input: 2, source: "tap-key", r: rA, pubkey: key },
  ], eq);
  assert.equal(spread.reused.length, 3, "every pair of the shared R is reported");
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
  assert.deepEqual(withLeaf[0].leafHash, leafHash, "the record carries the leaf hash from keydata bytes 32..64");
  assert.deepEqual(withLeaf[0].r, rA);
  assert.equal(withLeaf[0].source, "tap-script");
  const shortKeydata = hodlTapScriptSigs([{ type: 20, keydata: new Uint8Array(31), val: raw }], (e, t) => e.filter((x) => x.type === t));
  assert.equal(shortKeydata.length, 0, "short keydata is a lookalike, not a script-path signature");
  const unparseable = hodlTapScriptSigs([{ type: 20, keydata: Uint8Array.from([...key, ...leafHash]), val: new Uint8Array(10) }], (e, t) => e.filter((x) => x.type === t));
  assert.equal(unparseable[0].r, null, "an unparseable value still records the pubkey");
  assert.deepEqual(unparseable[0].pubkey, key);
  assert.deepEqual(unparseable[0].leafHash, leafHash);
});

test("same R under different keys is a reused nonce, reported as cross-key; different R is not reuse", () => {
  // A reused nonce leaks related keys (an output key and its internal key,
  // one wallet's non-hardened keys): DeepSeek's red-team of #1051, F1.
  const differentKeys = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, pubkey: key },
    { input: 1, source: "tap-key", r: rA, pubkey: new Uint8Array(32).fill(0x55) },
  ], eq);
  assert.equal(differentKeys.reused.length, 1, "same R under different keys is a reused nonce");
  assert.equal(differentKeys.reused[0].sameKey, false, "and is marked cross-key");
  assert.equal(differentKeys.incomplete, 0);
  const differentR = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, pubkey: key },
    { input: 1, source: "tap-key", r: new Uint8Array(32).fill(0x22), pubkey: key },
  ], eq);
  assert.equal(differentR.reused.length, 0, "different R values never flag");
  assert.equal(differentR.incomplete, 0);
});

test("records without a parsed R or a 32-byte key count as incomplete, never skipped", () => {
  const missingR = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: null, pubkey: key },
    { input: 1, source: "tap-key", r: rA, pubkey: key },
  ], eq);
  assert.equal(missingR.reused.length, 0, "unparseable records never flag");
  assert.equal(missingR.incomplete, 1, "the unparseable record is counted");
  const missingKey = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, pubkey: new Uint8Array() },
    { input: 1, source: "tap-key", r: rA, pubkey: key },
  ], eq);
  assert.equal(missingKey.incomplete, 1, "a keyless record cannot be attributed");
  assert.equal(missingKey.reused.length, 1, "but its R still joins the comparison: a shared R is reported");
  assert.equal(missingKey.reused[0].sameKey, false);
  const shortKey = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, pubkey: new Uint8Array(31) },
    { input: 1, source: "tap-key", r: rA, pubkey: key },
  ], eq);
  assert.equal(shortKey.incomplete, 1, "a non-32-byte key is not a key");
  assert.equal(shortKey.reused.length, 1, "the shared R is still reported");
});

test("the comparison budget refuses a flood of identical R values, like the ECDSA cap", () => {
  const flood = Array.from({ length: 257 }, (_, input) => ({ input, source: "tap-key", r: rA, pubkey: key }));
  assert.throws(() => hodlCompareSchnorrNonces(flood, eq), /Nonce comparison limit exceeded: too many signatures share the same r value\./);
  const atBudget = Array.from({ length: 256 }, (_, input) => ({ input, source: "tap-key", r: rA, pubkey: key }));
  const scan = hodlCompareSchnorrNonces(atBudget, eq);
  assert.equal(scan.reused.length, 256 * 255 / 2, "256 records stay under the 32768-pair cap");
  const twoGroups = [
    ...Array.from({ length: 200 }, (_, input) => ({ input, source: "tap-key", r: rA, pubkey: key })),
    ...Array.from({ length: 200 }, (_, input) => ({ input: input + 200, source: "tap-key", r: new Uint8Array(32).fill(0x22), pubkey: key })),
  ];
  assert.throws(() => hodlCompareSchnorrNonces(twoGroups, eq), /Nonce comparison limit exceeded/, "the cap is on total candidate pairs across groups");
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
  // The condition and the number shown both count only parseable Schnorr
  // signatures; the wrapping span is presentation and may change.
  assert.match(app, /signatures\.length \+ parsedTapSignatures \? "<span class='[^']*'>" \+ hodlT\("\{count\} signature\(s\) present", \{ count: signatures\.length \+ parsedTapSignatures \}\)/);
  assert.doesNotMatch(app, /tapSignatureCount \+= tapSignatures\.length/);
});

test("one signature copied into two fields is not reuse; the same R with a different s is", () => {
  // Same R and key with the same s means the same challenge e, so the same
  // message: a copy leaks nothing. A different s under the same R and key is
  // a second message, and s1 - s2 = (e1 - e2)*d reveals the key.
  const sA = new Uint8Array(32).fill(0x61), sB = new Uint8Array(32).fill(0x62);
  const copied = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, s: sA, pubkey: key },
    { input: 1, source: "tap-key", r: rA, s: sA, pubkey: key },
  ], eq);
  assert.equal(copied.reused.length, 0, "an identical copy is not a key leak");
  assert.equal(copied.incomplete, 0, "and it was compared, not skipped");
  const second = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, s: sA, pubkey: key },
    { input: 1, source: "tap-key", r: rA, s: sB, pubkey: key },
  ], eq);
  assert.equal(second.reused.length, 1, "same R, same key, different s is reuse");
  const oneMissing = hodlCompareSchnorrNonces([
    { input: 0, source: "tap-key", r: rA, s: sA, pubkey: key },
    { input: 1, source: "tap-key", r: rA, pubkey: key },
  ], eq);
  assert.equal(oneMissing.reused.length, 1, "a missing s fails closed");
});

// --- finalized script-path spends (#1051 round 3) ---------------------------
// Real spends built and finalized by @scure/btc-signer: every signature the
// reader attributes must verify under its key against the BIP341 script-path
// sighash, which pins the reverse key order of a multi_a witness.
const scureSpend = async (leafScript, signers) => {
  const { Transaction } = await import("@scure/btc-signer");
  const { p2tr: scureP2TR } = await import("@scure/btc-signer/payment.js");
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const internal = schnorr.getPublicKey(new Uint8Array(32).fill(0x31));
  const payment = scureP2TR(internal, { script: leafScript }, undefined, true);
  const tx = new Transaction();
  tx.addInput({ txid: "11".repeat(32), index: 0, witnessUtxo: { script: payment.script, amount: 50000n }, tapInternalKey: payment.tapInternalKey, tapMerkleRoot: payment.tapMerkleRoot, tapLeafScript: payment.tapLeafScript });
  tx.addOutput({ script: Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x33)), amount: 40000n });
  for (const key of signers) tx.signIdx(key, 0);
  const message = tx.preimageWitnessV1(0, [payment.script], 0, [50000n], -1, leafScript, 0xc0);
  tx.finalizeIdx(0);
  return { witness: tx.getInput(0).finalScriptWitness, message, schnorr };
};

test("a finalized multi_a script-path witness attributes each signature to its key, in reverse stack order", async () => {
  const { p2tr_ms } = await import("@scure/btc-signer/payment.js");
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const secrets = [0x41, 0x42, 0x43].map((byte) => new Uint8Array(32).fill(byte));
  const pubs = secrets.map((secret) => schnorr.getPublicKey(secret));
  const { witness, message } = await scureSpend(p2tr_ms(2, pubs).script, [secrets[0], secrets[2]]);
  const records = hodlTapScriptPathSigs(witness);
  assert.equal(records.length, 2, "two of three keys signed");
  assert.deepEqual(records.map((record) => Buffer.from(record.pubkey).toString("hex")), [pubs[0], pubs[2]].map((pub) => Buffer.from(pub).toString("hex")));
  for (const record of records) {
    assert.ok(schnorr.verify(Uint8Array.of(...record.r, ...record.s), message, record.pubkey), "each signature verifies under the key it is attributed to");
    assert.equal(record.source, "tap-script");
  }
  assert.equal(hodlTapWitnessShape(witness), "script");
});

test("a finalized pk() script-path witness yields its one signature, keyed by the leaf key", async () => {
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const secret = new Uint8Array(32).fill(0x44), pub = schnorr.getPublicKey(secret);
  const leaf = Uint8Array.of(0x20, ...pub, 0xac);
  const { witness, message } = await scureSpend(leaf, [secret]);
  const records = hodlTapScriptPathSigs(witness);
  assert.equal(records.length, 1);
  assert.deepEqual(records[0].pubkey, pub);
  assert.ok(schnorr.verify(Uint8Array.of(...records[0].r, ...records[0].s), message, pub));
  // An annex (last element starting 0x50) is dropped first.
  assert.deepEqual(hodlTapScriptPathSigs([...witness, Uint8Array.of(0x50, 1, 2)]).map((record) => record.r), records.map((record) => record.r));
});

test("script-path witnesses the reader cannot attribute return null; shapes are told apart", () => {
  const sig = new Uint8Array(64).fill(0x07), key = new Uint8Array(32).fill(0x44);
  const pk = Uint8Array.of(0x20, ...key, 0xac), control = Uint8Array.of(0xc0, ...new Uint8Array(32).fill(0x55));
  assert.equal(hodlTapScriptPathSigs([sig, Uint8Array.of(0x51), control]), null, "an unknown leaf script");
  assert.equal(hodlTapScriptPathSigs([sig, pk, Uint8Array.of(0xc2, ...control.slice(1))]), null, "a leaf version other than tapscript");
  assert.equal(hodlTapScriptPathSigs([sig, sig, pk, control]), null, "more stack items than keys");
  assert.equal(hodlTapScriptPathSigs([new Uint8Array(), pk, control]), null, "no signature at all");
  const short = hodlTapScriptPathSigs([new Uint8Array(10), pk, control]);
  assert.equal(short.length, 1);
  assert.equal(short[0].r, null, "an unparseable signature is kept as incomplete, never skipped");
  assert.equal(hodlTapWitnessShape([sig]), "key");
  assert.equal(hodlTapWitnessShape([Uint8Array.of(...sig, 0x01)]), "key");
  assert.equal(hodlTapWitnessShape([sig, Uint8Array.of(0x50)]), "key", "key path with an annex");
  assert.equal(hodlTapWitnessShape([sig, pk, control]), "script");
  assert.equal(hodlTapWitnessShape([new Uint8Array(72).fill(0x30), new Uint8Array(33).fill(0x02)]), null, "a P2WPKH witness");
});
