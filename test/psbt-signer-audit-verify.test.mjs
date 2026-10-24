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
import { sha256 as hodlSha256 } from "../src/js/hashes.js";
import { hex as hodlHex } from "../src/js/coders.js";
import { secp256k1, secp256k1Ready } from "../src/js/secp256k1.js";
import { psbtInspectDoc, psbtWasmReady } from "../src/js/psbt-wasm.js";
import { auditSigner } from "../src/js/psbt-signer-audit.js";
import { psbtSignerAuditVerification, SIGNER_AUDIT_MAX_SIGNATURE_CHECKS } from "../src/js/psbt-signer-audit-verify.js";

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
test("the shipped verifier does no curve math and imports no @noble code", () => {
  const source = readFileSync(new URL("../src/js/psbt-signer-audit-verify.js", import.meta.url), "utf8");
  assert.ok(!/from\s*["']@noble/.test(source), "psbt-signer-audit-verify.js must not import @noble; BIP-340 runs on the WASM facade");
  assert.ok(!/FIELD_P|bip340Verify|bytesToInt/.test(source), "the hand-rolled BIP-340 path must be gone");
  assert.ok(/schnorr\.verify/.test(source), "BIP-340 verification goes through the facade's schnorr.verify");
});
