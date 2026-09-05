// Transaction edits must not leave signing material behind. A BIP-174
// signature commits to the exact unsigned transaction it was made over, so a
// PSBT that keeps its partial signatures or final scripts after the editor
// moved an amount, a prevout or a sequence would look signed for outputs
// nobody authorized. These tests drive the same document mutations the field
// handlers perform and prove the rebuilt file carries no signing material —
// and that an untouched transaction keeps every pair.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtEditorBuildDoc, psbtDropStaleSigningMaterial, psbtTxSectionKey } from "../src/js/psbt-editor.js";
import { psbtBuildBytes, psbtInspectDoc } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const fixtureDoc = () => {
  const b64 = read("test/fixtures/psbt/p2wpkh-1in-2out.b64").trim();
  return psbtInspectDoc(Uint8Array.from(Buffer.from(b64, "base64")));
};

// BIP-174 valid vector 2: a finalized P2PKH input (PSBT_IN_FINAL_SCRIPTSIG).
const FINALIZED_B64 = Buffer.from(
  unhex(
    "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
      "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a91476" +
      "8a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac" +
      "000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d88" +
      "91ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d7" +
      "3fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34" +
      "dbafa9e3dda01fb82308000000",
  ),
).toString("base64");

function unhex(hex) {
  return hex.match(/.{2}/g).map((byte) => parseInt(byte, 16));
}

const rebuild = (doc) => psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc)));

// Mirrors the editor's rebuild(): drop when the transaction moved from what
// the maps were decoded against, then build.
const editTransaction = (doc, mutateFields) => {
  const signedAgainst = psbtTxSectionKey(doc.tx);
  mutateFields(doc);
  const draft = psbtTxSectionKey(doc.tx) === signedAgainst ? { doc, dropped: [] } : psbtDropStaleSigningMaterial(doc);
  return { fresh: rebuild(draft.doc), dropped: draft.dropped };
};

const signingPairs = (doc) =>
  doc.inputs
    .flatMap((map, input) => map.filter((pair) => pair.name === "PSBT_IN_PARTIAL_SIG" || pair.name?.startsWith("PSBT_IN_FINAL_") || pair.name?.startsWith("PSBT_IN_TAP_KEY_SIG") || pair.name?.startsWith("PSBT_IN_TAP_SCRIPT_SIG")).map((pair) => `input ${input} ${pair.name}`))
    .concat(doc.globals.filter((pair) => pair.name === "PSBT_GLOBAL_UNSIGNED_TX").map(() => "unsigned tx pair"));

const hasFixtureSignature = () => {
  const doc = fixtureDoc();
  assert.ok(doc.inputs[0].some((pair) => pair.name === "PSBT_IN_PARTIAL_SIG"), "fixture must carry a partial signature");
  return doc;
};

test("the fixture's own transaction key matches its decoded self", () => {
  const doc = hasFixtureSignature();
  assert.equal(psbtTxSectionKey(doc.tx), psbtTxSectionKey(structuredClone(doc).tx));
  // A field read back as a string mid-keystroke is the same field.
  const typed = structuredClone(doc);
  typed.tx.outputs[0].value = String(typed.tx.outputs[0].value);
  typed.tx.inputs[0].txid = typed.tx.inputs[0].txid.toUpperCase();
  assert.equal(psbtTxSectionKey(typed.tx), psbtTxSectionKey(doc.tx));
});

test("editing an output value drops the partial signature it committed to", () => {
  const doc = hasFixtureSignature();
  const { fresh, dropped } = editTransaction(doc, (d) => {
    d.tx.outputs[0].value = 1;
  });
  assert.deepEqual(signingPairs(fresh).filter((name) => name.includes("PARTIAL")), []);
  assert.equal(dropped.length, 1);
  assert.equal(dropped[0].name, "PSBT_IN_PARTIAL_SIG");
  // The transaction really did change, and the file still builds.
  assert.equal(fresh.tx.outputs[0].value, 1);
});

test("re-pointing an input drops signatures over the old transaction", () => {
  const doc = hasFixtureSignature();
  const { fresh, dropped } = editTransaction(doc, (d) => {
    d.tx.inputs[0].txid = "11".repeat(32);
    d.tx.inputs[0].vout = 7;
  });
  assert.equal(fresh.tx.inputs[0].vout, 7);
  assert.equal(dropped.length, 1);
});

test("deleting an output drops signatures that no longer commit to it", () => {
  const doc = hasFixtureSignature();
  const { fresh, dropped } = editTransaction(doc, (d) => {
    d.tx.outputs.splice(1, 1);
    d.outputs.splice(1, 1);
  });
  assert.equal(fresh.tx.outputs.length, 1);
  assert.equal(dropped.length, 1);
});

test("sequence and locktime edits drop signing material too", () => {
  for (const mutateFields of [(d) => (d.tx.inputs[0].sequence = 0), (d) => (d.tx.locktime = 500_000), (d) => (d.tx.version = 1)]) {
    const doc = hasFixtureSignature();
    const { fresh, dropped } = editTransaction(doc, mutateFields);
    assert.equal(dropped.length, 1, "every committed field orphans the signature");
    assert.deepEqual(signingPairs(fresh).filter((name) => name.includes("PARTIAL")), []);
  }
});

test("a finalized input's final scriptsig does not survive a transaction edit", () => {
  const doc = psbtInspectDoc(Uint8Array.from(Buffer.from(FINALIZED_B64, "base64")));
  assert.ok(doc.inputs[0].some((pair) => pair.name === "PSBT_IN_FINAL_SCRIPTSIG"), "vector 2 must carry a finalized input");
  const { fresh } = editTransaction(doc, (d) => {
    d.tx.outputs[0].value = 1;
  });
  assert.ok(!fresh.inputs.some((map) => map.some((pair) => pair.name === "PSBT_IN_FINAL_SCRIPTSIG")));
});

test("an unedited transaction keeps every signature and pair", () => {
  const doc = hasFixtureSignature();
  const before = JSON.stringify(doc.inputs);
  const signedAgainst = psbtTxSectionKey(doc.tx);
  // Only the maps change (a hand-edited pair value), so signing material stays.
  doc.inputs[0][0].value = doc.inputs[0][0].value;
  assert.equal(psbtTxSectionKey(doc.tx), signedAgainst);
  const fresh = rebuild(doc);
  assert.equal(JSON.stringify(fresh.inputs), before, "an edit that did not move the transaction must not drop pairs");
});

// The issue asks for ECDSA and Taproot coverage: a key-path signature is a
// different pair type with a different key encoding, so the drop set has to
// name both. `p2tr-taproot.b64` carries a real PSBT_IN_TAP_KEY_SIG.
test("a Taproot key-path signature does not survive a transaction edit", () => {
  const b64 = read("test/fixtures/psbt/p2tr-taproot.b64").trim();
  const doc = psbtInspectDoc(Uint8Array.from(Buffer.from(b64, "base64")));
  assert.equal(doc.rustBitcoinError, null, "the taproot fixture must parse");
  assert.ok(
    doc.inputs[0].some((pair) => pair.name === "PSBT_IN_TAP_KEY_SIG"),
    "the taproot fixture must carry a key-path signature",
  );
  const { fresh, dropped } = editTransaction(doc, (d) => {
    d.tx.outputs[0].value = 1;
  });
  assert.ok(dropped.some((pair) => pair.name === "PSBT_IN_TAP_KEY_SIG"), "the key-path signature should have been dropped");
  assert.ok(!fresh.inputs.some((map) => map.some((pair) => pair.name === "PSBT_IN_TAP_KEY_SIG")));
  // A Taproot input's own key material is not signing material: internal keys
  // and derivations describe who may sign, so they survive for re-signing.
  assert.ok(
    fresh.inputs[1].some((pair) => pair.name === "PSBT_IN_TAP_INTERNAL_KEY"),
    "PSBT_IN_TAP_INTERNAL_KEY is not signing material and must survive",
  );
});

test("the sighash-type declaration survives: it is a policy, not a signature", () => {
  const doc = hasFixtureSignature();
  const { fresh } = editTransaction(doc, (d) => {
    d.tx.outputs[0].value = 1;
  });
  assert.ok(fresh.inputs[0].some((pair) => pair.name === "PSBT_IN_SIGHASH_TYPE"));
});

test("psbtDropStaleSigningMaterial names what it removed and leaves the input alone", () => {
  const doc = hasFixtureSignature();
  const snapshot = JSON.stringify(doc);
  const { doc: stripped, dropped } = psbtDropStaleSigningMaterial(doc);
  assert.equal(JSON.stringify(doc), snapshot, "the document passed in is not mutated");
  assert.equal(dropped.length, 1);
  assert.match(dropped[0].note, /^pubkey /);
  assert.ok(stripped.inputs[0].length < doc.inputs[0].length);
  // Nothing left to drop: the same document comes back.
  const again = psbtDropStaleSigningMaterial(stripped);
  assert.equal(again.doc, stripped);
  assert.deepEqual(again.dropped, []);
});

test("the editor wires the drop into every rebuild and reports it", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /const staleTx = signedAgainst !== null && psbtTxSectionKey\(doc\.tx\) !== signedAgainst;/);
  assert.match(editor, /const draft = staleTx \? psbtDropStaleSigningMaterial\(doc\) : \{ doc, dropped: \[\] \};/);
  assert.match(editor, /psbtBuildBytes\(psbtEditorBuildDoc\(draft\.doc\)\)/);
  assert.match(editor, /\$\{signingDropped\.length \? signingDroppedNotice\(signingDropped\) : ""\}/);
});
