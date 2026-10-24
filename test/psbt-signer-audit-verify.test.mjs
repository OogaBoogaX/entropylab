// Differential tests for the PSBT Signer Audit's signature verification
// (src/js/psbt-signer-audit-verify.js). Fixtures are built and signed with
// @scure/btc-signer and @noble/curves — independent implementations, the
// same convention as test/sighash-differential-fuzz.test.mjs — so the
// expected verdicts (a genuine signature verifies, a flipped byte cannot,
// a missing UTXO claim or an exhausted budget fails closed) never come
// from the code under test. Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as btc from "@scure/btc-signer";
import { secp256k1 as nobleSecp256k1, schnorr as nobleSchnorr } from "@noble/curves/secp256k1.js";
import { sha256 as hodlSha256, hash160 as hodlHash160 } from "../src/js/hashes.js";
import { hex as hodlHex } from "../src/js/coders.js";
import { secp256k1, secp256k1Ready } from "../src/js/secp256k1.js";
import { psbtInspectDoc, psbtWasmReady } from "../src/js/psbt-wasm.js";
import { auditSigner } from "../src/js/psbt-signer-audit.js";
import { psbtSignerAuditVerification, SIGNER_AUDIT_MAX_SIGNATURE_CHECKS, SIGNER_AUDIT_MAX_DIGEST_BYTES } from "../src/js/psbt-signer-audit-verify.js";

await Promise.all([secp256k1Ready, psbtWasmReady]);

const hex = (text) => hodlHex.decode(text);
const hexOf = (bytes) => hodlHex.encode(bytes);
// The output script of a scure payment object, across its field naming.
const spkOf = (payment) => payment.scriptPubKey ?? payment.script;

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const u32le = (n) => { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, n >>> 0, true); return out; };
const u64le = (v) => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, v, true); return out; };
// BIP-341 tagged hash, from the specification (not the code under test).
const taggedHash = (tag, ...messages) => {
  const tagHash = hodlSha256(new TextEncoder().encode(tag));
  return hodlSha256(concat(tagHash, tagHash, ...messages));
};
const leafHashOf = (script, version = 0xc0) => taggedHash("TapLeaf", Uint8Array.of(version), Uint8Array.of(script.length), script);

const PRIV = hex("01".repeat(32));
const PUB = nobleSecp256k1.getPublicKey(PRIV, true);
// A known output script: @scure/btc-signer 2.x refuses unknown output
// scripts unless allowUnknownOutputs is set. The destination is not what
// these fixtures exercise, so the fixture key's own P2WPKH script is as
// neutral.
const DEST = spkOf(btc.p2wpkh(PUB));
// @scure/btc-signer 2.x keyMap shape: an array of [pubkey, { fingerprint, path }]
// pairs (fingerprint a u32, path u32 indexes), not bitcoinjs-style objects.
const DERIVATION = [[PUB, { fingerprint: 0x12345678, path: [0x80000054, 0x80000000, 0x80000000, 0, 0] }]];

const indexOfSubarray = (haystack, needle) => {
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) { match = false; break; }
    if (match) return i;
  }
  return -1;
};
// One byte flipped inside the signature's bytes in the serialized PSBT:
// the encoding stays well-formed, so verification runs and fails.
const withFlippedSignatureByte = (psbtBytes, doc, name) => {
  const pair = doc.inputs[0].find((p) => p.name === name);
  const sig = hex(pair.value);
  const at = indexOfSubarray(psbtBytes, sig);
  assert.ok(at >= 0, "fixture: the signature appears in the PSBT bytes");
  const flipped = psbtBytes.slice();
  flipped[at + 10] ^= 1;
  return flipped;
};

const segwitFixture = () => {
  const tx = new btc.Transaction();
  tx.addInput({ txid: "11".repeat(32), index: 0, witnessUtxo: { script: spkOf(btc.p2wpkh(PUB)), amount: 100_000n } });
  tx.updateInput(0, { bip32Derivation: DERIVATION });
  tx.addOutput({ script: DEST, amount: 90_000n });
  const before = tx.toPSBT();
  tx.sign(PRIV);
  return { before, after: tx.toPSBT() };
};

const wrappedFixture = () => {
  const redeem = spkOf(btc.p2wpkh(PUB));
  const tx = new btc.Transaction();
  tx.addInput({
    txid: "44".repeat(32),
    index: 0,
    redeemScript: redeem,
    witnessUtxo: { script: spkOf(btc.p2sh(btc.p2wpkh(PUB))), amount: 100_000n },
  });
  tx.updateInput(0, { bip32Derivation: DERIVATION });
  tx.addOutput({ script: DEST, amount: 90_000n });
  const before = tx.toPSBT();
  tx.sign(PRIV);
  return { before, after: tx.toPSBT() };
};

// The previous transaction paying the fixture key's P2PKH output,
// serialized by hand: it is fixture data (the UTXO being spent), not the
// code under test.
const legacyPrevTx = () => {
  const script = spkOf(btc.p2pkh(PUB));
  const bytes = concat(
    u32le(2), Uint8Array.of(1),
    hex("99".repeat(32)), u32le(0), Uint8Array.of(1, 0x51), u32le(0xffffffff),
    Uint8Array.of(1), u64le(100_000n), Uint8Array.of(script.length), script,
    u32le(0),
  );
  const txid = hexOf(hodlSha256(hodlSha256(bytes)).slice().reverse());
  return { bytes, txid };
};
const legacyFixture = () => {
  const prev = legacyPrevTx();
  const tx = new btc.Transaction();
  tx.addInput({ txid: prev.txid, index: 0, nonWitnessUtxo: prev.bytes });
  tx.updateInput(0, { bip32Derivation: DERIVATION });
  tx.addOutput({ script: DEST, amount: 90_000n });
  const before = tx.toPSBT();
  tx.sign(PRIV);
  return { before, after: tx.toPSBT() };
};

const TAP_PRIV = hex("03".repeat(32));
const TAP_INTERNAL = nobleSchnorr.getPublicKey(TAP_PRIV);
// scure signs the key path with BIP-340 (noble's schnorr, deterministic:
// aux_rand defaults to 32 zero bytes), so this is a real BIP-340 signature
// verified through the WASM facade.
const taprootKeyFixture = () => {
  const tx = new btc.Transaction();
  tx.addInput({
    txid: "22".repeat(32),
    index: 0,
    witnessUtxo: { script: spkOf(btc.p2tr(TAP_INTERNAL)), amount: 50_000n },
    tapInternalKey: TAP_INTERNAL,
  });
  tx.addOutput({ script: DEST, amount: 40_000n });
  const before = tx.toPSBT();
  tx.sign(TAP_PRIV);
  return { before, after: tx.toPSBT() };
};

const LEAF_PRIV = hex("04".repeat(32));
const LEAF_XONLY = nobleSchnorr.getPublicKey(LEAF_PRIV);
const LEAF_SCRIPT = Uint8Array.of(0x20, ...LEAF_XONLY, 0xac); // <xonly> OP_CHECKSIG
const taprootScriptFixture = () => {
  // A lone leaf is passed as the leaf itself; in scure's TaprootScriptTree an
  // array is a branch and must have two children.
  const payment = btc.p2tr(TAP_INTERNAL, { script: LEAF_SCRIPT, leafVersion: 0xc0 });
  assert.ok(payment.tapLeafScript?.length, "fixture: scure exposes the leaf's control block");
  const tx = new btc.Transaction();
  tx.addInput({
    txid: "33".repeat(32),
    index: 0,
    witnessUtxo: { script: spkOf(payment), amount: 50_000n },
    tapInternalKey: TAP_INTERNAL,
    tapLeafScript: payment.tapLeafScript,
  });
  tx.addOutput({ script: DEST, amount: 40_000n });
  const before = tx.toPSBT();
  tx.sign(LEAF_PRIV);
  return { before, after: tx.toPSBT() };
};

test("a correctly signed segwit v0 PSBT verifies and the audit passes with no SIGNATURE_UNVERIFIED", () => {
  const { before, after } = segwitFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.complete, true);
  // The entry names the exact PSBT key it verified: the pair's keydata with
  // its type byte, which is what the engine's Phase F matches on.
  assert.deepEqual(verification.signatures, [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", key: "02" + hexOf(PUB), pubkey: hexOf(PUB), valid: true }]);
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "pass");
  assert.equal(report.checks.signatures, "valid");
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
});

test("one flipped segwit v0 signature byte is SIGNATURE_INVALID and fails the audit", () => {
  const { before, after } = segwitFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const flippedDoc = psbtInspectDoc(withFlippedSignatureByte(after, afterDoc, "PSBT_IN_PARTIAL_SIG"));
  const verification = psbtSignerAuditVerification(beforeDoc, flippedDoc);
  assert.equal(verification.signatures.length, 1);
  assert.equal(verification.signatures[0].valid, false);
  const report = auditSigner(beforeDoc, flippedDoc, { verification });
  assert.equal(report.verdict, "fail");
  assert.equal(report.checks.signatures, "invalid");
  assert.ok(report.findings.some((f) => f.code === "SIGNATURE_INVALID" && f.severity === "critical"));
  assert.ok(!report.findings.some((f) => f.code === "SIGNATURE_UNVERIFIED"));
});

test("a correctly signed wrapped P2SH-P2WPKH PSBT verifies; a flipped byte fails", () => {
  const { before, after } = wrappedFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.deepEqual(verification.signatures, [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", key: "02" + hexOf(PUB), pubkey: hexOf(PUB), valid: true }]);
  const flippedDoc = psbtInspectDoc(withFlippedSignatureByte(after, afterDoc, "PSBT_IN_PARTIAL_SIG"));
  assert.equal(psbtSignerAuditVerification(beforeDoc, flippedDoc).signatures[0].valid, false);
});

test("a correctly signed legacy P2PKH PSBT verifies; a flipped byte fails", () => {
  const { before, after } = legacyFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.deepEqual(verification.signatures, [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", key: "02" + hexOf(PUB), pubkey: hexOf(PUB), valid: true }]);
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "pass");
  const flippedDoc = psbtInspectDoc(withFlippedSignatureByte(after, afterDoc, "PSBT_IN_PARTIAL_SIG"));
  assert.equal(psbtSignerAuditVerification(beforeDoc, flippedDoc).signatures[0].valid, false);
});

test("a taproot key-path signature verifies through the WASM facade and the audit passes; a flipped one is SIGNATURE_INVALID", () => {
  const { before, after } = taprootKeyFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.complete, true);
  assert.deepEqual(verification.signatures, [{ index: 0, name: "PSBT_IN_TAP_KEY_SIG", key: "13", pubkey: null, valid: true }]);
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "pass");
  assert.equal(report.checks.signatures, "valid");
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  const flippedDoc = psbtInspectDoc(withFlippedSignatureByte(after, afterDoc, "PSBT_IN_TAP_KEY_SIG"));
  const flipped = psbtSignerAuditVerification(beforeDoc, flippedDoc);
  assert.equal(flipped.signatures[0].valid, false);
  const flippedReport = auditSigner(beforeDoc, flippedDoc, { verification: flipped });
  assert.equal(flippedReport.verdict, "fail");
  assert.ok(flippedReport.findings.some((f) => f.code === "SIGNATURE_INVALID"));
});

test("the WASM facade verifies a BIP-340 signature produced by @noble/curves (fixed key, fixed message)", () => {
  const priv = hex("03".repeat(32));
  const xonly = nobleSchnorr.getPublicKey(priv);
  const message = hodlSha256(new TextEncoder().encode("entropylab signer audit"));
  const signature = nobleSchnorr.sign(message, priv); // deterministic: aux_rand defaults to zeros
  assert.equal(secp256k1.schnorr.verify(signature, message, xonly), true);
  const flipped = signature.slice();
  flipped[0] ^= 1;
  assert.equal(secp256k1.schnorr.verify(flipped, message, xonly), false);
});

test("a taproot script-path signature verifies; a flipped one fails", () => {
  const { before, after } = taprootScriptFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.complete, true);
  assert.deepEqual(verification.signatures, [{
    index: 0,
    name: "PSBT_IN_TAP_SCRIPT_SIG",
    key: "14" + hexOf(LEAF_XONLY) + hexOf(leafHashOf(LEAF_SCRIPT)),
    pubkey: hexOf(LEAF_XONLY),
    valid: true,
  }]);
  const flippedDoc = psbtInspectDoc(withFlippedSignatureByte(after, afterDoc, "PSBT_IN_TAP_SCRIPT_SIG"));
  assert.equal(psbtSignerAuditVerification(beforeDoc, flippedDoc).signatures[0].valid, false);
});

test("a Taproot signature on an input whose spent output is not P2TR is invalid, never unverified", () => {
  const { before, after } = taprootKeyFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  // The sent PSBT claims a P2WPKH prevout for the input the signer signed
  // with a Taproot key-path signature.
  const p2wpkh = "0014" + "22".repeat(20);
  const rewritten = structuredClone(beforeDoc);
  rewritten.inputs[0] = rewritten.inputs[0].map((pair) => pair.name === "PSBT_IN_WITNESS_UTXO"
    ? {
      ...pair,
      value: hexOf(concat(u64le(50_000n), Uint8Array.of(p2wpkh.length / 2), hex(p2wpkh))),
      decoded: { value: "50000", scriptPubKey: p2wpkh },
    }
    : pair);
  const verification = psbtSignerAuditVerification(rewritten, afterDoc);
  assert.equal(verification.signatures.length, 1);
  assert.equal(verification.signatures[0].name, "PSBT_IN_TAP_KEY_SIG");
  assert.equal(verification.signatures[0].valid, false);
});

test("an entry whose key does not match the pair leaves the signature unverified", () => {
  const { before, after } = segwitFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.signatures[0].valid, true);
  const mismatched = { ...verification, signatures: verification.signatures.map((entry) => ({ ...entry, key: "02" + "00".repeat(32) })) };
  const report = auditSigner(beforeDoc, afterDoc, { verification: mismatched });
  assert.equal(report.verdict, "fail");
  assert.ok(report.findings.some((f) => f.code === "SIGNATURE_UNVERIFIED" && f.severity === "critical"));
  assert.ok(!report.findings.some((f) => f.code === "SIGNATURE_INVALID"), "a key mismatch is unverified, not invalid");
});

test("an entry without a key never matches, so the signature stays unverified", () => {
  const { before, after } = segwitFixture();
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  const keyless = { ...verification, signatures: verification.signatures.map(({ key, ...rest }) => rest) };
  const report = auditSigner(beforeDoc, afterDoc, { verification: keyless });
  assert.equal(report.verdict, "fail");
  assert.ok(report.findings.some((f) => f.code === "SIGNATURE_UNVERIFIED" && f.severity === "critical"));
});

test("a signature whose input lacks its UTXO claim is unverified, never valid", () => {
  const { before, after } = segwitFixture();
  const strip = (doc) => {
    const clone = structuredClone(doc);
    clone.inputs[0] = clone.inputs[0].filter((p) => p.name !== "PSBT_IN_WITNESS_UTXO");
    return clone;
  };
  const beforeDoc = strip(psbtInspectDoc(before)), afterDoc = strip(psbtInspectDoc(after));
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.complete, true);
  assert.equal(verification.signatures.length, 1);
  assert.equal(verification.signatures[0].valid, null);
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "fail");
  assert.ok(report.findings.some((f) => f.code === "SIGNATURE_UNVERIFIED" && f.severity === "critical"));
  assert.ok(!report.findings.some((f) => f.code === "SIGNATURE_INVALID"), "unverified is not invalid");
});

test("past the per-file check budget, signatures are unverified and never valid", () => {
  // The budget mirrors the consensus layer's MAX_SIGNATURE_CHECKS
  // (psbt-wasm/src/verify.rs), pinned there by the crate's tests.
  assert.equal(SIGNER_AUDIT_MAX_SIGNATURE_CHECKS, 256);
  const utxo = {
    key: "01",
    value: "a086010000000000" + "16" + "0014" + "22".repeat(20),
    name: "PSBT_IN_WITNESS_UTXO",
    decoded: { value: "100000", scriptPubKey: "0014" + "22".repeat(20) },
  };
  // A well-formed DER shape (30 44 02 20 R 02 20 S) plus the SIGHASH_ALL
  // byte: the engine's Phase E refuses a malformed blob before Phase F, so
  // the fixture must be shaped like a real signature for verification to
  // run at all. Its bytes are garbage, so every checked one fails.
  const der = "3044" + "0220" + "11".repeat(32) + "0220" + "11".repeat(32);
  const sigPair = (n) => {
    const pubkey = "02" + n.toString(16).padStart(64, "0");
    return { key: "02" + pubkey, value: der + "01", name: "PSBT_IN_PARTIAL_SIG", decoded: { pubkey, signature: der, sighashByte: 1, sighash: "SIGHASH_ALL" } };
  };
  const doc = (sigs) => ({
    psbtVersion: 0,
    tx: { version: 2, locktime: 0, inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: "1000", scriptPubKey: "51" }] },
    globals: [],
    inputs: [[utxo, ...sigs]],
    outputs: [[]],
  });
  const count = SIGNER_AUDIT_MAX_SIGNATURE_CHECKS + 1;
  const beforeDoc = doc([]), afterDoc = doc(Array.from({ length: count }, (_, n) => sigPair(n + 1)));
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.signatures.length, count);
  assert.equal(verification.complete, false);
  // Every signature inside the budget was actually checked (a garbage DER
  // blob fails), the first one past it is unverified, and none is valid.
  for (const entry of verification.signatures.slice(0, 256)) assert.equal(entry.valid, false);
  assert.equal(verification.signatures[256].valid, null);
  assert.ok(verification.signatures.every((entry) => entry.valid !== true));
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "fail");
  const unverified = report.findings.filter((f) => f.code === "SIGNATURE_UNVERIFIED");
  assert.equal(unverified.length, 1);
  assert.equal(unverified[0].evidence.reason, "budget_exhausted");
});

test("no added signatures: complete, empty, and the audit is untouched", () => {
  const { before } = segwitFixture();
  const beforeDoc = psbtInspectDoc(before);
  assert.deepEqual(psbtSignerAuditVerification(beforeDoc, beforeDoc), { complete: true, signatures: [] });
});

// Two P2WPKH inputs to the same key: a signer can return them in the other
// order with a fresh signature on each.
const twoInputTx = (order) => {
  const tx = new btc.Transaction();
  for (const [txid, index, amount] of order) {
    tx.addInput({ txid, index, witnessUtxo: { script: spkOf(btc.p2wpkh(PUB)), amount } });
  }
  tx.updateInput(0, { bip32Derivation: DERIVATION });
  tx.updateInput(1, { bip32Derivation: DERIVATION });
  tx.addOutput({ script: DEST, amount: 140_000n });
  return tx;
};

test("a returned PSBT with the sent inputs swapped and a new signature fails with TX_REORDERED", () => {
  const sent = twoInputTx([["11".repeat(32), 0, 100_000n], ["22".repeat(32), 1, 50_000n]]);
  const before = sent.toPSBT();
  const returned = twoInputTx([["22".repeat(32), 1, 50_000n], ["11".repeat(32), 0, 100_000n]]);
  returned.sign(PRIV);
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(returned.toPSBT());
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "fail");
  assert.ok(report.findings.some((f) => f.code === "TX_REORDERED" && f.severity === "critical"));
});

test("a returned PSBT with an input the sent one lacks fails", () => {
  const sent = new btc.Transaction();
  sent.addInput({ txid: "11".repeat(32), index: 0, witnessUtxo: { script: spkOf(btc.p2wpkh(PUB)), amount: 100_000n } });
  sent.updateInput(0, { bip32Derivation: DERIVATION });
  sent.addOutput({ script: DEST, amount: 90_000n });
  const before = sent.toPSBT();
  const returned = new btc.Transaction();
  returned.addInput({ txid: "11".repeat(32), index: 0, witnessUtxo: { script: spkOf(btc.p2wpkh(PUB)), amount: 100_000n } });
  returned.addInput({ txid: "22".repeat(32), index: 1, witnessUtxo: { script: spkOf(btc.p2wpkh(PUB)), amount: 50_000n } });
  returned.updateInput(0, { bip32Derivation: DERIVATION });
  returned.updateInput(1, { bip32Derivation: DERIVATION });
  returned.addOutput({ script: DEST, amount: 90_000n });
  returned.sign(PRIV);
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(returned.toPSBT());
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  const report = auditSigner(beforeDoc, afterDoc, { verification });
  assert.equal(report.verdict, "fail");
});

// The shipped module must not import @noble: every secp256k1 operation in
// the page goes through src/js/secp256k1.js, the facade over libsecp256k1
// compiled to WebAssembly, and every hash through src/js/hashes.js, so the
// release page carries a single vendored cryptography stack (issue #56).
// @noble/curves appears in this test file only, as the independent oracle.
// The hand-rolled BIP-340 path (FIELD_P, BigInt point math, a JS fallback)
// is gone for good: its field prime was wrong and the page never does curve
// math in JavaScript.
// ---- Wicked's review of #1118 ------------------------------------------

// scure options for scripts it does not know (witness v2, a v0 program of
// the wrong length, unexecutable witness scripts): these fixtures must
// carry exactly the bytes under test.
const SCURE_ANY = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };
const derSig = (digest) => concat(nobleSecp256k1.sign(digest, PRIV, { prehash: false, format: "der" }), Uint8Array.of(0x01));
const auditOf = ({ before, after }) => {
  const beforeDoc = psbtInspectDoc(before), afterDoc = psbtInspectDoc(after);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  return { verification, report: auditSigner(beforeDoc, afterDoc, { verification }) };
};

// A real signature over the LEGACY digest of the script the old fallback
// used: valid under that rule, so the old code reported it valid.
const legacySignedSpend = (prevSpk, redeemScript) => {
  const tx = new btc.Transaction(SCURE_ANY);
  tx.addInput({ txid: "55".repeat(32), index: 0, witnessUtxo: { script: prevSpk, amount: 100_000n }, ...(redeemScript ? { redeemScript } : {}) });
  tx.addOutput({ script: DEST, amount: 90_000n });
  const before = tx.toPSBT();
  tx.updateInput(0, { partialSig: [[PUB, derSig(tx.preimageLegacy(0, redeemScript ?? prevSpk, btc.SigHash.ALL))]] }, true);
  return { before, after: tx.toPSBT() };
};

test("an unsupported witness program is never verified with a legacy digest (native and P2SH-wrapped)", () => {
  const v2 = concat(Uint8Array.of(0x52, 0x20), hex("33".repeat(32)));
  const badV0 = hex("00021111");
  const p2shOf = (redeem) => concat(Uint8Array.of(0xa9, 0x14), hodlHash160(redeem), Uint8Array.of(0x87));
  for (const [label, spk, redeem] of [["witness v2", v2], ["v0 of length 2", badV0], ["wrapped witness v2", p2shOf(v2), v2], ["wrapped v0 of length 2", p2shOf(badV0), badV0]]) {
    const { verification, report } = auditOf(legacySignedSpend(spk, redeem));
    assert.equal(verification.signatures.length, 1, label);
    assert.notEqual(verification.signatures[0].valid, true, label);
    assert.notEqual(report.verdict, "pass", label);
  }
});

// A real BIP-143 signature over a P2WSH witness script.
const p2wshSignedSpend = (script) => {
  const tx = new btc.Transaction(SCURE_ANY);
  const spk = concat(Uint8Array.of(0x00, 0x20), hodlSha256(script));
  tx.addInput({ txid: "66".repeat(32), index: 0, witnessUtxo: { script: spk, amount: 100_000n }, witnessScript: script });
  tx.addOutput({ script: DEST, amount: 90_000n });
  const before = tx.toPSBT();
  tx.updateInput(0, { partialSig: [[PUB, derSig(tx.preimageWitnessV0(0, script, btc.SigHash.ALL, 100_000n))]] }, true);
  return { before, after: tx.toPSBT() };
};

test("a script that cannot execute never yields a valid signature; an executable one still does", () => {
  const checksig = concat(Uint8Array.of(0x21), PUB, Uint8Array.of(0xac)); // <PUB> OP_CHECKSIG
  const accepted = auditOf(p2wshSignedSpend(checksig));
  assert.equal(accepted.verification.signatures[0].valid, true, "an executable script still verifies");
  for (const [label, script] of [
    ["truncated push", concat(Uint8Array.of(0x21), PUB.slice(0, 10))],
    ["unmatched IF", concat(Uint8Array.of(0x63), checksig)],
    ["more than 201 opcodes", concat(new Uint8Array(202).fill(0x61), checksig)],
  ]) {
    const { verification, report } = auditOf(p2wshSignedSpend(script));
    assert.equal(verification.signatures.length, 1, label);
    assert.notEqual(verification.signatures[0].valid, true, label);
    assert.notEqual(report.verdict, "pass", label);
  }
});

test("the Inspector's own verdict caps the signature it names, and only that one", () => {
  const { before, after } = segwitFixture();
  const beforeDoc = psbtInspectDoc(before);
  // The decoder names a partial signature by its pubkey's first 16 hex digits.
  const mine = `partial signature (pubkey ${hexOf(PUB).slice(0, 16)}…) does not verify`;
  const other = `partial signature (pubkey ${"02" + "ab".repeat(7)}…) does not verify`;
  const withProblem = (code, message, scope = "input 0") => {
    const doc = structuredClone(psbtInspectDoc(after));
    doc.problems = [...(doc.problems ?? []), { scope, code, severity: "warning", message }];
    return doc;
  };
  const validOf = (doc) => psbtSignerAuditVerification(beforeDoc, doc).signatures[0].valid;
  assert.equal(validOf(psbtInspectDoc(after)), true, "uncapped, the fixture verifies");
  assert.equal(validOf(withProblem("partial_sig_invalid", mine)), false, "named invalid: invalid");
  assert.equal(validOf(withProblem("partial_sig_unchecked", mine)), null, "named unchecked: never valid");
  assert.equal(validOf(withProblem("partial_sig_invalid", other)), true, "another signer's invalid signature does not blame this one");
  assert.equal(validOf(withProblem("partial_sig_invalid", "unattributed")), null, "a problem naming no key leaves the input uncertain, never invalid");
  assert.equal(validOf(withProblem("partial_sig_invalid", `partial signature (pubkey ${hexOf(PUB).slice(0, 8)}…) short`)), null, "only the decoder's exact 16-digit form names a key");
  // A key name that is not at the start of the decoder's own sentence (text
  // a hostile PSBT might get into a message) names nothing.
  assert.equal(validOf(withProblem("partial_sig_invalid", `could not read field: partial signature (pubkey ${hexOf(PUB).slice(0, 16)}…)`)), null, "an embedded key name is not trusted");
  assert.equal(validOf(withProblem("partial_sig_invalid", `partial signature (pubkey ${"02" + "ab".repeat(7)}…) bad; see partial signature (pubkey ${hexOf(PUB).slice(0, 16)}…)`)), true, "only the leading key is named");
  assert.equal(validOf(withProblem("partial_sig_invalid", mine, "input 1")), true, "another input's problem does not cap this one");
  const budget = psbtSignerAuditVerification(beforeDoc, withProblem("verification_budget", "budget exhausted", "psbt"));
  assert.equal(budget.signatures[0].valid, null);
  assert.equal(budget.complete, false);
});

test("one key in two Taproot leaves: leaf A's bad signature does not make leaf B's valid one invalid", () => {
  // Wicked's recheck: the decoder names a script-path signature by its key
  // only, so a problem about leaf A cannot be pinned to leaf B. Two valid
  // leaves using the same key; the sent PSBT has an invalid leaf-A signature,
  // the returned one keeps it and adds a valid leaf-B signature.
  const leafA = Uint8Array.of(0x20, ...LEAF_XONLY, 0xac); // <key> OP_CHECKSIG
  const leafB = Uint8Array.of(0x20, ...LEAF_XONLY, 0xad, 0x51); // <key> OP_CHECKSIGVERIFY OP_TRUE
  const payment = btc.p2tr(TAP_INTERNAL, [{ script: leafA, leafVersion: 0xc0 }, { script: leafB, leafVersion: 0xc0 }], undefined, true);
  const spk = spkOf(payment);
  const base = () => {
    const tx = new btc.Transaction(SCURE_ANY);
    tx.addInput({ txid: "88".repeat(32), index: 0, witnessUtxo: { script: spk, amount: 50_000n }, tapInternalKey: TAP_INTERNAL, tapLeafScript: payment.tapLeafScript });
    tx.addOutput({ script: DEST, amount: 40_000n });
    return tx;
  };
  const digestFor = (leaf) => base().preimageWitnessV1(0, [spk], btc.SigHash.DEFAULT, [50_000n], undefined, leaf, 0xc0);
  const badA = nobleSchnorr.sign(digestFor(leafA), LEAF_PRIV).slice();
  badA[10] ^= 1;
  const sigB = nobleSchnorr.sign(digestFor(leafB), LEAF_PRIV);
  const keyA = { pubKey: LEAF_XONLY, leafHash: leafHashOf(leafA) }, keyB = { pubKey: LEAF_XONLY, leafHash: leafHashOf(leafB) };
  const withSigs = (sigs) => {
    const tx = base();
    if (sigs.length) tx.updateInput(0, { tapScriptSig: sigs }, true);
    return tx.toPSBT();
  };
  const after = withSigs([[keyA, badA], [keyB, sigB]]);
  const flagged = (psbtInspectDoc(after).problems ?? []).filter((p) => p.code === "tap_sig_invalid" && p.message.startsWith(`script-path signature (xonly ${hexOf(LEAF_XONLY).slice(0, 16)}`));
  assert.ok(flagged.length >= 1, "fixture: the decoder flags the key, not the leaf");
  const { verification, report } = auditOf({ before: withSigs([[keyA, badA]]), after });
  const added = verification.signatures.filter((s) => s.name === "PSBT_IN_TAP_SCRIPT_SIG");
  assert.equal(added.length, 1, "only leaf B's signature is new");
  assert.notEqual(added[0].valid, false, "leaf B's valid signature is not reported invalid");
  assert.ok(!report.findings.some((f) => f.code === "SIGNATURE_INVALID"), "no SIGNATURE_INVALID is raised against leaf B");
  // On its own, the same leaf-B signature verifies.
  const alone = auditOf({ before: withSigs([]), after: withSigs([[keyB, sigB]]) });
  assert.equal(alone.verification.signatures[0].valid, true);
});

test("a 2-of-2 multisig with one signer's invalid signature does not blame the other's valid one", () => {
  // Wicked's reproduction: the sent PSBT carries an invalid key-1 signature,
  // the returned one keeps it and adds a valid key-2 signature. The decoder
  // names key 1; the audit must not report key 2's signature invalid.
  const PRIV2 = hex("05".repeat(32)), PUB2 = nobleSecp256k1.getPublicKey(PRIV2, true);
  const script = concat(Uint8Array.of(0x52, 0x21), PUB, Uint8Array.of(0x21), PUB2, Uint8Array.of(0x52, 0xae)); // 2 <k1> <k2> 2 CHECKMULTISIG
  const tx = new btc.Transaction(SCURE_ANY);
  tx.addInput({ txid: "77".repeat(32), index: 0, witnessUtxo: { script: concat(Uint8Array.of(0x00, 0x20), hodlSha256(script)), amount: 100_000n }, witnessScript: script });
  tx.addOutput({ script: DEST, amount: 90_000n });
  const digest = tx.preimageWitnessV0(0, script, btc.SigHash.ALL, 100_000n);
  const bad1 = derSig(digest);
  bad1[10] ^= 1;
  tx.updateInput(0, { partialSig: [[PUB, bad1]] }, true);
  const before = tx.toPSBT();
  const sig2 = concat(nobleSecp256k1.sign(digest, PRIV2, { prehash: false, format: "der" }), Uint8Array.of(0x01));
  tx.updateInput(0, { partialSig: [[PUB, bad1], [PUB2, sig2]] }, true);
  const after = tx.toPSBT();
  const afterDoc = psbtInspectDoc(after);
  assert.ok((afterDoc.problems ?? []).some((p) => p.code === "partial_sig_invalid" && p.message.includes(hexOf(PUB).slice(0, 16))), "fixture: the decoder names key 1");
  const { verification } = auditOf({ before, after });
  const entry = verification.signatures.find((s) => s.pubkey === hexOf(PUB2));
  assert.ok(entry, "key 2's signature is the new one");
  assert.equal(entry.valid, true, "key 2's valid signature is not blamed for key 1's");
});

// One output whose script is `scriptBytes` long, and one P2TR key-path
// signature per input (64 garbage bytes: verification runs and fails).
const taprootDoc = (inputs, scriptBytes) => {
  // A real x-only key, so the facade verifies (and rejects) the garbage
  // signatures rather than refusing the key.
  const spk = "5120" + hexOf(TAP_INTERNAL);
  const utxo = { key: "01", value: "a086010000000000" + "22" + spk, name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "100000", scriptPubKey: spk } };
  const keySig = { key: "13", value: "44".repeat(64), name: "PSBT_IN_TAP_KEY_SIG", decoded: {} };
  const doc = (withSig) => ({
    psbtVersion: 0,
    tx: {
      version: 2, locktime: 0,
      inputs: Array.from({ length: inputs }, (_, i) => ({ txid: (i + 1).toString(16).padStart(64, "0"), vout: 0, scriptSig: "", sequence: 4294967295 })),
      outputs: [{ value: "1000", scriptPubKey: "6a" + "00".repeat(scriptBytes - 1) }],
    },
    globals: [],
    inputs: Array.from({ length: inputs }, () => (withSig ? [utxo, keySig] : [utxo])),
    outputs: [[]],
  });
  return { beforeDoc: doc(false), afterDoc: doc(true) };
};

test("Taproot hashing counts against the digest budget, and the shared hashes are computed once", () => {
  // Wicked's review: every key-path signature re-hashed the transaction's
  // outputs without charging the budget. One 33 MiB output is now refused
  // before it is hashed...
  const huge = taprootDoc(1, 33 * 1024 * 1024);
  const refused = psbtSignerAuditVerification(huge.beforeDoc, huge.afterDoc);
  assert.equal(refused.complete, false);
  assert.equal(refused.signatures[0].valid, null);
  // ...and a 2 MiB output shared by 64 signatures is hashed once: charged per
  // signature it would be 128 MiB, past the 32 MiB budget.
  const repeated = taprootDoc(64, 2 * 1024 * 1024);
  const shared = psbtSignerAuditVerification(repeated.beforeDoc, repeated.afterDoc);
  assert.equal(shared.signatures.length, 64);
  assert.equal(shared.complete, true, "the shared hashes are charged once, not per signature");
  assert.ok(shared.signatures.every((entry) => entry.valid === false), "garbage signatures were checked and failed");
});

// A hand-built document (as in the budget test above): one P2WSH input with
// the given witness script and `count` garbage-but-well-shaped signatures.
const p2wshDoc = (script, count) => {
  const spk = "0020" + hexOf(hodlSha256(script));
  const utxo = { key: "01", value: "a086010000000000" + "22" + spk, name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "100000", scriptPubKey: spk } };
  const witnessScript = { key: "05", value: hexOf(script), name: "PSBT_IN_WITNESS_SCRIPT", decoded: { hex: hexOf(script) } };
  const der = "3044" + "0220" + "11".repeat(32) + "0220" + "11".repeat(32);
  const sigs = Array.from({ length: count }, (_, n) => {
    const pubkey = "02" + (n + 1).toString(16).padStart(64, "0");
    return { key: "02" + pubkey, value: der + "01", name: "PSBT_IN_PARTIAL_SIG", decoded: { pubkey, signature: der, sighashByte: 1, sighash: "SIGHASH_ALL" } };
  });
  const doc = (pairs) => ({
    psbtVersion: 0,
    tx: { version: 2, locktime: 0, inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: "1000", scriptPubKey: "51" }] },
    globals: [],
    inputs: [pairs],
    outputs: [[]],
  });
  return { beforeDoc: doc([utxo, witnessScript]), afterDoc: doc([utxo, witnessScript, ...sigs]) };
};

test("every signature spends the check budget, even one that exits early on a separator", () => {
  // OP_CODESEPARATOR <key> OP_CHECKSIG: every signature exits early. The old
  // code charged the budget only after that exit, so 257 of them still came
  // back complete.
  const script = concat(Uint8Array.of(0xab, 0x21), PUB, Uint8Array.of(0xac));
  const { beforeDoc, afterDoc } = p2wshDoc(script, SIGNER_AUDIT_MAX_SIGNATURE_CHECKS + 1);
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.complete, false);
  assert.ok(verification.signatures.every((entry) => entry.valid === null));
});

test("bytes hashed are bounded too: a huge witness script stops being checked past the digest budget", () => {
  assert.equal(SIGNER_AUDIT_MAX_DIGEST_BYTES, 32 * 1024 * 1024); // psbt-wasm/src/verify.rs MAX_LEGACY_DIGEST_BYTES
  // 1 MiB of OP_NOP then <key> OP_CHECKSIG: no separator, so each signature
  // hashes the whole script. 40 of them is far under the check count but
  // past 32 MiB of hashing.
  const script = concat(new Uint8Array(1024 * 1024).fill(0x61), Uint8Array.of(0x21), PUB, Uint8Array.of(0xac));
  const { beforeDoc, afterDoc } = p2wshDoc(script, 40);
  const started = Date.now();
  const verification = psbtSignerAuditVerification(beforeDoc, afterDoc);
  assert.equal(verification.complete, false);
  assert.ok(verification.signatures.some((entry) => entry.valid === null), "signatures past the digest budget are unverified");
  assert.ok(verification.signatures.every((entry) => entry.valid !== true));
  assert.ok(Date.now() - started < 20000, "bounded work");
});

test("the shipped verifier does no curve math and imports no @noble code", () => {
  const source = readFileSync(new URL("../src/js/psbt-signer-audit-verify.js", import.meta.url), "utf8");
  assert.ok(!/from\s*["']@noble/.test(source), "psbt-signer-audit-verify.js must not import @noble; BIP-340 runs on the WASM facade");
  assert.ok(!/FIELD_P|bip340Verify|bytesToInt/.test(source), "the hand-rolled BIP-340 path must be gone");
  assert.ok(/schnorr\.verify/.test(source), "BIP-340 verification goes through the facade's schnorr.verify");
});
