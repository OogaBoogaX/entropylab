// The consensus layer over PSBT edits (psbt-wasm verify.rs): every edit is
// checked against Bitcoin's consensus rules and BIP-174's signer checks —
// UTXO claims, redeem/witness script bindings, signatures and final witness
// data — and error-severity problems gate the build unless the editor's
// Insane editing switch passes { insane: true }. These tests pin both the
// detections and the two severities' gate behavior.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { Transaction, p2pk, p2sh, p2wpkh, p2wsh } from "@scure/btc-signer";
import { psbtBuildBytes, psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtEditorBuildDoc, psbtProblemsHtml } from "../src/js/psbt-editor.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const fixtureDoc = (name) => {
  const b64 = readFileSync(join(root, `test/fixtures/psbt/${name}.b64`), "utf8").trim();
  return psbtInspectDoc(Uint8Array.from(atob(b64), (char) => char.charCodeAt(0)));
};
const rebuild = (doc, options) => psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc), options));
const codes = (doc) => doc.problems.map((problem) => `${problem.severity}:${problem.code}`);

test("fixtures carry exactly their honest problems (garbage partial sigs named, real final witness accepted)", () => {
  assert.deepEqual(codes(fixtureDoc("p2wpkh-1in-2out")), ["warning:partial_sig_invalid"]);
  // The finalized P2WPKH input's real signature verifies: no final-witness
  // finding. The fabricated partial/taproot signatures are named as warnings.
  assert.deepEqual(codes(fixtureDoc("mixed-many-inputs")), ["warning:partial_sig_invalid", "warning:tap_sig_invalid", "warning:partial_sig_invalid"]);
  assert.deepEqual(codes(fixtureDoc("p2tr-taproot")), ["warning:tap_sig_invalid"]);
  assert.deepEqual(codes(fixtureDoc("bip174-valid-vector-2")), []);
  assert.deepEqual(codes(fixtureDoc("no-amount-claims")), []);
  assert.deepEqual(codes(fixtureDoc("outputs-exceed-inputs")), ["warning:fee_impossible"]);
  assert.deepEqual(codes(fixtureDoc("no-outputs")), ["error:tx_consensus"]);
});

test("a corrupt final witness is an error and gates the build; insane editing bypasses the gate only", () => {
  const doc = fixtureDoc("mixed-many-inputs");
  const witness = doc.inputs[4].find((pair) => pair.name === "PSBT_IN_FINAL_SCRIPTWITNESS");
  // Flip one byte inside the witness signature: structurally fine, invalid.
  const corrupt = witness.value.slice(0, 10) + (witness.value[10] === "a" ? "b" : "a") + witness.value.slice(11);
  doc.inputs[4] = doc.inputs[4].map((pair) => (pair === witness ? { ...pair, value: corrupt } : pair));
  const inspected = rebuild(doc, { insane: true }); // must build under insane…
  assert.ok(inspected.problems.some((p) => p.severity === "error" && p.code === "final_witness_bad"));
  // …and must refuse under the default policy.
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /final witness/);
});

test("a non-witness UTXO whose txid is not the prevout gates the build (BIP-174 invalid)", () => {
  const doc = fixtureDoc("mixed-many-inputs");
  // Repoint input 0's prevout so the embedded previous transaction no longer
  // matches it (this also orphans input 0's nothing — it carries no sigs).
  doc.tx.inputs[0].txid = "ef".repeat(32);
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /non-witness UTXO's txid does not match/);
  const insane = rebuild(doc, { insane: true });
  assert.ok(insane.problems.some((p) => p.code === "nonwitness_txid_mismatch" && p.severity === "error"));
});

test("a witness UTXO declaring a non-witness output is an error (BIP-174 signer check)", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  // Rewrite the witness UTXO claim to a P2PKH script (76a914…88ac), same
  // amount: a witness UTXO for a non-witness input. The value layout is
  // 8-byte LE amount, compact-size script length, script.
  const claim = doc.inputs[0].find((pair) => pair.name === "PSBT_IN_WITNESS_UTXO");
  claim.value = claim.value.slice(0, 16) + "19" + "76a914" + "00".repeat(20) + "88ac";
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /witness UTXO declared for a non-witness input/);
  const insane = rebuild(doc, { insane: true });
  assert.ok(insane.problems.some((p) => p.code === "witness_utxo_on_legacy" && p.severity === "error"));
});

test("a redeemScript that does not hash to the claimed P2SH output is an error", () => {
  // bip174 vector 2's input 1 spends a P2SH output with a wrapped-segwit
  // redeem script; corrupting one redeem-script byte breaks the hash binding.
  const doc = fixtureDoc("bip174-valid-vector-2");
  const redeem = doc.inputs[1].find((pair) => pair.name === "PSBT_IN_REDEEM_SCRIPT");
  redeem.value = redeem.value.slice(0, -2) + (redeem.value.endsWith("00") ? "01" : "00");
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /redeemScript does not hash/);
  const insane = rebuild(doc, { insane: true });
  assert.ok(insane.problems.some((p) => p.code === "redeem_script_mismatch" && p.severity === "error"));
});

test("warnings never gate: a missing witness UTXO is listed and the build still succeeds", () => {
  // The spend is known to be segwit through a non-witness UTXO claim (an
  // embedded previous transaction paying a P2WPKH output), while the witness
  // UTXO BIP-174 expects for it is absent.
  const p2wpkhScript = "0014" + "11".repeat(20);
  const prevTx =
    "02000000" + "01" + "99".repeat(32) + "00000000" + "00" + "ffffffff" +
    "01" + "204e000000000000" + "16" + p2wpkhScript + "00000000";
  const prevTxid = bytesToHex(Uint8Array.from(hexToBytes(bytesToHex(sha256(sha256(hexToBytes(prevTx)))))).reverse());
  const doc = {
    tx: { version: 2, locktime: 0, inputs: [{ txid: prevTxid, vout: 0, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: 1000, scriptPubKey: "51" }] },
    globals: [],
    inputs: [[{ key: "00", value: prevTx }]],
    outputs: [[]],
  };
  const fresh = psbtInspectDoc(psbtBuildBytes(doc)); // default policy — warnings do not block
  assert.ok(fresh.problems.some((p) => p.code === "missing_witness_utxo" && p.severity === "warning"));
});

test("an input with no UTXO claim at all cannot be classified — no finding, no gate", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const without = psbtEditorBuildDoc(doc);
  without.inputs[0] = without.inputs[0].filter((pair) => pair.key !== "01");
  const fresh = psbtInspectDoc(psbtBuildBytes(without));
  assert.ok(!fresh.problems.some((p) => p.severity === "error"));
});

test("a sighash pair disagreeing with the partial signature's byte is a warning", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const sighash = doc.inputs[0].find((pair) => pair.name === "PSBT_IN_SIGHASH_TYPE");
  sighash.value = "02000000"; // declares SIGHASH_NONE; the signature byte says ALL
  const fresh = rebuild(doc);
  assert.ok(fresh.problems.some((p) => p.code === "sighash_mismatch" && p.severity === "warning"));
});

test("a field that fails its typed decode is listed as an invalid-field warning", () => {
  // Hand-assembled: the fixture's unsigned transaction, one input map whose
  // sighash-type value is truncated to one byte, two empty output maps.
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const unsignedTx = doc.globals.find((pair) => pair.key === "00").value;
  const raw =
    "70736274ff" + "01" + "00" + (unsignedTx.length / 2).toString(16).padStart(2, "0") + unsignedTx + "00" +
    "01" + "03" + "01" + "01" + "00" + "00" + "00";
  const inspected = psbtInspectDoc(hexToBytes(raw));
  assert.ok(inspected.problems.some((p) => p.code === "field_decode" && p.message.includes("PSBT_IN_SIGHASH_TYPE")));
});

test("insane mode changes no bytes when there is nothing to forgive", () => {
  const doc = psbtEditorBuildDoc(fixtureDoc("locktime-rbf"));
  const sane = psbtBuildBytes(doc);
  const insane = psbtBuildBytes(doc, { insane: true });
  assert.deepEqual([...insane], [...sane]);
});

test("the transaction sanity gate keeps its historic message under the unified layer", () => {
  const doc = psbtEditorBuildDoc(fixtureDoc("p2wpkh-1in-2out"));
  doc.tx.outputs = [];
  doc.outputs = [];
  assert.throws(() => psbtBuildBytes(doc), /consensus-invalid: bad-txns-vout-empty/);
  // …and insane mode builds even that (structural validity is kept).
  psbtBuildBytes(doc, { insane: true });
});

test("psbtProblemsHtml lists problems escaped, in the sanitize section's style", () => {
  const doc = fixtureDoc("p2wpkh-1in-2out");
  const html = psbtProblemsHtml(doc, false);
  assert.match(html, /psbted-sanitize/);
  // The inspector's analysis-section paradigm: same classes, real <ul>/<li>.
  assert.match(html, /psbt-analysis-summary/);
  assert.match(html, /<ul><li>/);
  assert.match(html, /warning\(s\), no consensus violations/);
  assert.match(html, /partial signature \(pubkey 0279be667ef9dcbb…\) signature does not verify/);
  // An error-severity problem names the gate and the escape hatch.
  const bad = { problems: [{ severity: "error", scope: "input 0", code: "x", message: "broke <script> it" }] };
  const badHtml = psbtProblemsHtml(bad, false);
  assert.match(badHtml, /Errors block the build and export/);
  assert.ok(!badHtml.includes("<script>"), "problem text must be escaped");
  assert.match(badHtml, /broke &lt;script&gt; it/);
  // Under insane editing the same list says it did not gate.
  assert.match(psbtProblemsHtml(bad, true), /did not block the build/);
});

test("psbtProblemsHtml reads the untruncated severity totals (audit C3-4)", () => {
  // The display list caps at 64 entries; the heading must come from the
  // doc's pre-truncation counts, or 64 early warnings would read as "no
  // consensus violations" while errors were dropped from view.
  const warnings = Array.from({ length: 64 }, (_, i) => ({ severity: "warning", scope: "input 0", code: "w", message: `warning ${i}` }));
  const doc = { problems: warnings, problemsTruncated: true, problemCount: 66, errorCount: 2 };
  const html = psbtProblemsHtml(doc, false);
  assert.match(html, /2 consensus\/signing problem\(s\) and 64 warning\(s\)/);
  assert.match(html, /Errors block the build/);
  assert.doesNotMatch(html, /no consensus violations/);
  // A legacy doc without the totals must never claim cleanliness from a
  // truncated list either: it says the totals are unknown and points at the
  // build gate instead.
  const legacy = psbtProblemsHtml({ problems: warnings, problemsTruncated: true }, false);
  assert.doesNotMatch(legacy, /no consensus violations/);
  assert.match(legacy, /truncated/);
  // Untruncated legacy docs keep the old headings.
  assert.match(psbtProblemsHtml({ problems: warnings.slice(0, 3), problemsTruncated: false }, false), /3 warning\(s\), no consensus violations/);
});

// #866: BIP-174's Input Finalizer clears PSBT_IN_REDEEM_SCRIPT (0x04), so a
// finalized P2SH-wrapped segwit input carries only its final scriptSig, a
// single push of the redeem script that BIP-16 binds to the P2SH output, and
// its final witness. Contract: that input is checked against the redeem
// script its scriptSig pushes, as when 0x04 is present. An honest spend stays
// clean; a final witness that does not bind to the redeem script's program,
// or whose signature does not verify, is a final_witness_bad error; and a
// scriptSig push that does not hash to the P2SH output is a
// redeem_script_mismatch error. Each PSBT is built, signed and finalized by
// @scure/btc-signer (the independent finalizer), then one byte is changed.
const wrappedSigner = new Uint8Array(32).fill(7);
const wrappedKey = secp256k1.getPublicKey(wrappedSigner, true);
const finalizedSpend = (payment) => {
  const tx = new Transaction();
  tx.addInput({ txid: "11".repeat(32), index: 0, witnessUtxo: { script: payment.script, amount: 50_000n }, redeemScript: payment.redeemScript, witnessScript: payment.witnessScript });
  tx.addOutputAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40_000n);
  tx.signIdx(wrappedSigner, 0);
  tx.finalize();
  return tx.toPSBT();
};
const lastAt = (bytes, needle) => {
  const at = Buffer.from(bytes).lastIndexOf(Buffer.from(needle));
  assert.ok(at >= 0, "the bytes to change are in the PSBT");
  return at;
};
const flipped = (bytes, at) => {
  const copy = Uint8Array.from(bytes);
  copy[at] ^= 0x01;
  return copy;
};
const wrappedP2wpkh = p2sh(p2wpkh(wrappedKey));
const wrappedP2wsh = p2sh(p2wsh(p2pk(wrappedKey)));
const nativeP2wsh = p2wsh(p2pk(wrappedKey));

test("a finalized wrapped-segwit input without its redeemScript stays clean when honest (#866)", () => {
  for (const [label, payment] of [["P2SH-P2WPKH", wrappedP2wpkh], ["P2SH-P2WSH", wrappedP2wsh]]) {
    const doc = psbtInspectDoc(finalizedSpend(payment));
    assert.deepEqual(doc.inputs[0].map((pair) => pair.name), ["PSBT_IN_WITNESS_UTXO", "PSBT_IN_FINAL_SCRIPTSIG", "PSBT_IN_FINAL_SCRIPTWITNESS"], `${label}: the finalizer cleared 0x04`);
    assert.deepEqual(codes(doc), [], label);
  }
});

test("a finalized wrapped-segwit input's final witness is checked without 0x04 (#866)", () => {
  // P2SH-P2WSH: one byte of the witness script in the final witness.
  const wsh = finalizedSpend(wrappedP2wsh);
  assert.deepEqual(codes(psbtInspectDoc(flipped(wsh, lastAt(wsh, wrappedP2wsh.witnessScript) + 5))), ["error:final_witness_bad"], "P2SH-P2WSH witness script altered");
  // P2SH-P2WPKH: the witness public key swapped for another valid key.
  const wpkh = finalizedSpend(wrappedP2wpkh);
  const swapped = Uint8Array.from(wpkh);
  swapped.set(secp256k1.getPublicKey(new Uint8Array(32).fill(9), true), lastAt(wpkh, wrappedKey));
  assert.deepEqual(codes(psbtInspectDoc(swapped)), ["error:final_witness_bad"], "P2SH-P2WPKH witness key swapped");
  // P2SH-P2WPKH: one byte of the DER signature's s value (key and program
  // still bind, so only the signature check can catch it).
  const witness = psbtInspectDoc(wpkh).inputs[0].find((pair) => pair.name === "PSBT_IN_FINAL_SCRIPTWITNESS").value;
  const signature = hexToBytes(witness.slice(4, 4 + parseInt(witness.slice(2, 4), 16) * 2));
  assert.deepEqual(codes(psbtInspectDoc(flipped(wpkh, lastAt(wpkh, signature) + signature.length - 4))), ["error:final_witness_bad"], "P2SH-P2WPKH signature altered");
  // Control: the same witness-script change on a native P2WSH input was
  // already caught.
  const native = finalizedSpend(nativeP2wsh);
  assert.deepEqual(codes(psbtInspectDoc(flipped(native, lastAt(native, nativeP2wsh.witnessScript) + 5))), ["error:final_witness_bad"], "native P2WSH control");
});

test("a finalized P2SH input whose scriptSig redeem push does not hash to the output is an error (#866)", () => {
  for (const [label, payment] of [["P2SH-P2WPKH", wrappedP2wpkh], ["P2SH-P2WSH", wrappedP2wsh]]) {
    const bytes = finalizedSpend(payment);
    assert.deepEqual(codes(psbtInspectDoc(flipped(bytes, lastAt(bytes, payment.redeemScript) + 5))), ["error:redeem_script_mismatch"], label);
  }
});

// The 0x04-less path reads a present final scriptSig as consensus does
// (#890 review). BIP-16 requires a push-only scriptSig whose last push is
// the serialized redeem script, so a non-push, unparseable or empty one is
// final_scriptsig_bad. For a wrapped-segwit redeem, BIP-141 further requires
// the exact single push (Core: SCRIPT_ERR_WITNESS_MALLEATED_P2SH), so a
// non-minimal push is final_scriptsig_bad even with a good witness, and the
// witness is still checked. For a legacy redeem, a non-minimal push is
// policy, not consensus, and is not flagged.
const withFinalPairs = (doc, scriptSig, witness) => rebuild({
  ...doc,
  inputs: [doc.inputs[0].map((pair) => (
    pair.name === "PSBT_IN_FINAL_SCRIPTSIG" ? { ...pair, value: scriptSig }
      : pair.name === "PSBT_IN_FINAL_SCRIPTWITNESS" && witness !== undefined ? { ...pair, value: witness }
        : pair
  ))],
}, { insane: true });

test("a malformed final scriptSig on a 0x04-less wrapped-segwit input fails closed (#866)", () => {
  const doc = psbtInspectDoc(finalizedSpend(wrappedP2wpkh));
  const value = (name) => doc.inputs[0].find((pair) => pair.name === name).value;
  const redeem = bytesToHex(wrappedP2wpkh.redeemScript);
  assert.equal(value("PSBT_IN_FINAL_SCRIPTSIG"), "16" + redeem, "the finalizer wrote one minimal push");
  const otherKey = bytesToHex(secp256k1.getPublicKey(new Uint8Array(32).fill(9), true));
  const badWitness = value("PSBT_IN_FINAL_SCRIPTWITNESS").replace(bytesToHex(wrappedKey), otherKey);
  assert.notEqual(badWitness, value("PSBT_IN_FINAL_SCRIPTWITNESS"));
  const cases = [
    ["a non-push opcode (OP_NOP) ahead of the redeem push", "61" + "16" + redeem, undefined, ["error:final_scriptsig_bad"]],
    ["the redeem push truncated by one byte", "16" + redeem.slice(0, -2), undefined, ["error:final_scriptsig_bad"]],
    ["an empty scriptSig", "", undefined, ["error:final_scriptsig_bad"]],
    ["a non-minimal OP_PUSHDATA1 redeem push, good witness", "4c16" + redeem, undefined, ["error:final_scriptsig_bad"]],
    ["a non-minimal OP_PUSHDATA1 redeem push, witness key that does not bind", "4c16" + redeem, badWitness, ["error:final_scriptsig_bad", "error:final_witness_bad"]],
  ];
  for (const [label, scriptSig, witness, expected] of cases) {
    assert.deepEqual(codes(withFinalPairs(doc, scriptSig, witness)).sort(), expected, label);
  }
  assert.deepEqual(codes(withFinalPairs(doc, "16" + redeem)), [], "control: the finalizer's own bytes stay clean");
});

test("a 0x04-less legacy P2SH input keeps a valid non-minimal push, and an absent final scriptSig is not a finding (#866)", () => {
  // A finalized legacy P2SH(P2PK) spend, its previous transaction carried as
  // the non-witness UTXO.
  const legacy = p2sh(p2pk(wrappedKey));
  const previous = new Transaction();
  previous.addInput({ txid: "22".repeat(32), index: 0 });
  previous.addOutput({ script: legacy.script, amount: 50_000n });
  const tx = new Transaction();
  tx.addInput({ txid: previous.id, index: 0, nonWitnessUtxo: previous.toBytes(true, false), redeemScript: legacy.redeemScript });
  tx.addOutputAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40_000n);
  tx.signIdx(wrappedSigner, 0);
  tx.finalize();
  const doc = psbtInspectDoc(tx.toPSBT());
  assert.ok(!doc.inputs[0].some((pair) => pair.name === "PSBT_IN_REDEEM_SCRIPT"), "the finalizer cleared 0x04");
  assert.deepEqual(codes(doc), [], "honest legacy spend");
  // Re-encode its last push, the redeem script, with OP_PUSHDATA1: still a
  // consensus-valid legacy spend (MINIMALDATA is policy).
  const scriptSig = doc.inputs[0].find((pair) => pair.name === "PSBT_IN_FINAL_SCRIPTSIG").value;
  const redeem = bytesToHex(legacy.redeemScript);
  assert.ok(scriptSig.endsWith(bytesToHex([legacy.redeemScript.length]) + redeem), "the redeem script is the last, minimal push");
  const nonMinimal = scriptSig.slice(0, -(redeem.length + 2)) + "4c" + bytesToHex([legacy.redeemScript.length]) + redeem;
  assert.deepEqual(codes(withFinalPairs(doc, nonMinimal)), [], "a non-minimal legacy push is not flagged");
  // An unfinalized P2SH input with neither 0x04 nor 0x07 has nothing to
  // check: no finding.
  const unfinalized = new Transaction();
  unfinalized.addInput({ txid: "33".repeat(32), index: 0, witnessUtxo: { script: wrappedP2wpkh.script, amount: 50_000n } });
  unfinalized.addOutputAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40_000n);
  assert.deepEqual(codes(psbtInspectDoc(unfinalized.toPSBT())), [], "absent final scriptSig");
});
