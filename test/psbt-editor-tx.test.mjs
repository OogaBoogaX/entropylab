// Structural transaction editing in the PSBT editor: the Add input /
// Add output controls and the per-row delete buttons splice the unsigned
// transaction and its key-value maps together, so the document the WASM
// rebuilds always has exactly one map per tx element. These tests drive the
// same document mutations the buttons perform and prove rust-bitcoin accepts
// (or, for the last input, deliberately rejects) the result.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtEditorBuildDoc, dropSigningPairs, signingAnchor } from "../src/js/psbt-editor.js";
import { psbtBuildBytes, psbtInspectDoc } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const fixtureDoc = () => {
  const b64 = read("test/fixtures/psbt/p2wpkh-1in-2out.b64").trim();
  return psbtInspectDoc(Uint8Array.from(atob(b64), (char) => char.charCodeAt(0)));
};

// Mirrors the [data-tx-add] click handler in psbt-editor.js.
const addElement = (doc, kind) => {
  if (kind === "input") {
    doc.tx.inputs.push({ txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 });
    doc.inputs.push([]);
  } else {
    doc.tx.outputs.push({ value: "0", scriptPubKey: "" });
    doc.outputs.push([]);
  }
};

// Mirrors the [data-txin-del] / [data-txout-del] click handlers.
const removeElement = (doc, kind, index) => {
  doc.tx[kind === "input" ? "inputs" : "outputs"].splice(index, 1);
  doc[kind === "input" ? "inputs" : "outputs"].splice(index, 1);
};

const rebuild = (doc) => psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc)));

test("adding an input appends a spending slot and its empty key-value map", () => {
  const doc = fixtureDoc();
  const before = doc.tx.inputs.length;
  addElement(doc, "input");
  const fresh = rebuild(doc);
  assert.equal(fresh.tx.inputs.length, before + 1);
  assert.equal(fresh.inputs.length, before + 1);
  const added = fresh.tx.inputs[before];
  assert.equal(added.txid, "0".repeat(64));
  assert.equal(added.vout, 0);
  assert.equal(added.sequence, 4294967295);
  assert.deepEqual(fresh.inputs[before], []);
});

test("adding an output appends a zero-value empty-script slot and its map", () => {
  const doc = fixtureDoc();
  const before = doc.tx.outputs.length;
  addElement(doc, "output");
  const fresh = rebuild(doc);
  assert.equal(fresh.tx.outputs.length, before + 1);
  assert.equal(fresh.outputs.length, before + 1);
  assert.equal(fresh.tx.outputs[before].value, "0");
  assert.equal(fresh.tx.outputs[before].scriptPubKey, "");
  assert.deepEqual(fresh.outputs[before], []);
});

test("deleting an input removes its key-value map with it", () => {
  const doc = fixtureDoc();
  addElement(doc, "input");
  let fresh = rebuild(doc);
  assert.equal(fresh.tx.inputs.length, 2);
  removeElement(fresh, "input", 0);
  fresh = rebuild(fresh);
  assert.equal(fresh.tx.inputs.length, 1);
  assert.equal(fresh.inputs.length, 1);
  // The surviving input is the added one: its prevout is the zero outpoint.
  assert.equal(fresh.tx.inputs[0].txid, "0".repeat(64));
});

test("deleting an output removes its key-value map with it", () => {
  const doc = fixtureDoc();
  const before = doc.tx.outputs.length;
  removeElement(doc, "output", 0);
  const fresh = rebuild(doc);
  assert.equal(fresh.tx.outputs.length, before - 1);
  assert.equal(fresh.outputs.length, before - 1);
});

test("a map/element count mismatch is the build error the UI guards against", () => {
  const doc = fixtureDoc();
  doc.tx.inputs.push({ txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 });
  // No matching key-value map: the WASM must refuse, not misalign maps.
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /input maps but the transaction has/);
});

test("the last input cannot be deleted: a zero-input unsigned tx does not round-trip", () => {
  const doc = fixtureDoc();
  removeElement(doc, "input", 0);
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)));
  // …which is why the delete control is withheld when one input remains.
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /tx\.inputs\.length > 1 \? `<button [^>]*data-txin-del=/);
});

test("the editor renders the structural controls for inputs and outputs", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /data-tx-add="input"/);
  assert.match(editor, /data-tx-add="output"/);
  assert.match(editor, /data-txin-del="\$\{index\}"/);
  assert.match(editor, /data-txout-del="\$\{index\}"/);
  // Both arrays change together in every handler, keeping maps aligned.
  assert.match(editor, /draft\.tx\.inputs\.push\([\s\S]*?draft\.inputs\.push/);
  assert.match(editor, /draft\.tx\.outputs\.push\([\s\S]*?draft\.outputs\.push/);
  assert.match(editor, /draft\.tx\.inputs\.splice\(index, 1\);\s*\n\s*draft\.inputs\.splice\(index, 1\)/);
  assert.match(editor, /draft\.tx\.outputs\.splice\(index, 1\);\s*\n\s*draft\.outputs\.splice\(index, 1\)/);
});

test("the pair-delete handler binds pair buttons only, not the element deletes", () => {
  // Regression: the row deletes (data-txin-del/data-txout-del) and the
  // diagram close button share the psbted-del styling class with the pair
  // deletes. Binding the pair-delete handler to the bare class double-fired
  // it with an undefined data-kind — its TypeError surfaced as a spurious
  // error banner and the freshly built result was falsely marked stale.
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /querySelectorAll\("\.psbted-del\[data-kind\]"\)/);
  assert.doesNotMatch(editor, /querySelectorAll\("\.psbted-del"\)/);
});

test("a rejected structural edit rolls back the signing anchor and stale flag with the document", () => {
  // Regression (issues #325, #360): rebuild() clears the signing anchor
  // before its build can fail, so a rollback that restores only the document
  // left a signed document anchored to nothing — the next accepted
  // transaction edit kept signing pairs committing to the pre-edit
  // transaction — and the restored, building document was marked stale.
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /const backup = doc, backupAnchor = pristineTx, wasStale = stale;/);
  assert.match(editor, /doc = backup;\s*\n\s*pristineTx = backupAnchor;\s*\n\s*stale = wasStale;/);
});

test("dropSigningPairs removes exactly the transaction-committing fields (issues #325, #360)", () => {
  const doc = fixtureDoc();
  doc.inputs[0].push(
    { key: "02" + "02".repeat(33), value: "3007" }, // partial sig
    { key: "07", value: "47" + "30".repeat(35) }, // final scriptSig
    { key: "08", value: "02" }, // final scriptWitness
    { key: "13", value: "5a".repeat(64) }, // taproot key sig
    { key: "14" + "cc".repeat(32) + "dd".repeat(32), value: "6b".repeat(64) }, // taproot script sig
  );
  const utxoPairs = doc.inputs[0].filter((pair) => pair.key === "01").length;
  const dropped = dropSigningPairs(doc);
  assert.equal(dropped, 6); // the five above plus the fixture's own partial sig
  // The witness UTXO, the sighash-type hint, and the derivation path stay:
  // none of them are signatures.
  assert.deepEqual(doc.inputs[0].map((pair) => pair.key.slice(0, 2)).sort(), ["01", "03", "06"]);
  assert.equal(doc.inputs[0].filter((pair) => pair.key === "01").length, utxoPairs);
  // The surviving document still builds: claims and sighash hints remain.
  assert.ok(psbtBuildBytes(psbtEditorBuildDoc(doc)).length > 0);
});

test("dropSigningPairs removes MuSig2 session material but keeps participant pubkeys (BIP-373, issue #325)", () => {
  const doc = fixtureDoc();
  doc.inputs[0].push(
    { key: "1a" + "02".repeat(33), value: "02" + "03".repeat(33) }, // participant pubkeys: message-independent, stay
    { key: "1b" + "02".repeat(33), value: "aa".repeat(66) }, // pub nonce: bound to the message, drops
    { key: "1c" + "02".repeat(33), value: "bb".repeat(32) }, // partial signature: drops
  );
  const dropped = dropSigningPairs(doc);
  assert.equal(dropped, 3); // 0x1b, 0x1c, and the fixture's own partial sig
  assert.ok(doc.inputs[0].some((pair) => pair.key.slice(0, 2) === "1a"), "participant pubkeys stay");
  assert.ok(!doc.inputs[0].some((pair) => ["1b", "1c"].includes(pair.key.slice(0, 2))), "nonces and partial sigs dropped");
});

test("the signing anchor covers UTXO declarations, not just the transaction (issue #325)", () => {
  const doc = fixtureDoc();
  const anchor = signingAnchor(doc);
  // Re-reading the same document yields the same anchor.
  assert.equal(signingAnchor(fixtureDoc()), anchor);
  // A witness-UTXO value edit (amount or scriptPubKey) changes what every
  // BIP-143/BIP-341 signature commits to, so the anchor moves…
  const claim = doc.inputs[0].find((pair) => pair.key === "01");
  claim.value = claim.value.slice(0, -1) + (claim.value.endsWith("0") ? "1" : "0");
  assert.notEqual(signingAnchor(doc), anchor);
  // …and a transaction edit moves it too.
  const doc2 = fixtureDoc();
  doc2.tx.outputs[0].value = String(Number(doc2.tx.outputs[0].value) + 1);
  assert.notEqual(signingAnchor(doc2), anchor);
  // A pair that commits to nothing (the sighash-type hint) leaves it alone.
  const doc3 = fixtureDoc();
  const hint = doc3.inputs[0].find((pair) => pair.key.slice(0, 2) === "03");
  if (hint) {
    hint.value = hint.value === "01000000" ? "02000000" : "01000000";
    assert.equal(signingAnchor(doc3), anchor);
  }
});

test("the signing anchor ignores decorative transaction fields (issue #325)", () => {
  const doc = fixtureDoc();
  const anchor = signingAnchor(doc);
  // `asm` is derived from scriptPubKey at inspection and the builder never
  // reads it, so editing only asm must not move the anchor — the same rule
  // the pair maps already apply to their name/decoded fields.
  doc.tx.outputs[0].asm = "OP_TRUE";
  assert.equal(signingAnchor(doc), anchor);
  // What the builder does read (value, scriptPubKey) still moves it.
  doc.tx.outputs[0].scriptPubKey = "51";
  assert.notEqual(signingAnchor(doc), anchor);
});

test("a rejected structural edit rolls the signing anchor back with the document (issue #325)", () => {
  // Mirrors the editor's rebuild()/mutate() closures. rebuild() drops the
  // draft's signing pairs and clears the anchor before the fallible build;
  // when the build rejects, mutate() must restore the anchor together with
  // the document, or a later UTXO edit would keep signatures it no longer
  // commits to while export re-enables.
  let doc = fixtureDoc();
  let pristineTx = null, stale = false;
  const rebuildDoc = () => {
    if (pristineTx !== null && signingAnchor(doc) !== pristineTx) {
      dropSigningPairs(doc);
      pristineTx = null;
    }
    doc = psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc)));
    stale = false;
    pristineTx = signingAnchor(doc);
  };
  const mutateDoc = (fn) => {
    const backup = doc, backupAnchor = pristineTx, wasStale = stale;
    const draft = structuredClone(doc);
    try {
      fn(draft);
      doc = draft;
      rebuildDoc();
    } catch {
      doc = backup;
      pristineTx = backupAnchor;
      stale = wasStale;
    }
  };
  rebuildDoc(); // the load flow anchors the fresh document
  const anchor = pristineTx;
  // A duplicate UTXO declaration is rejected by rust-bitcoin; the failed
  // rebuild had already cleared the anchor before the build threw.
  const claim = doc.inputs[0].find((pair) => pair.key === "01").value;
  mutateDoc((draft) => draft.inputs[0].push({ key: "01", value: claim }));
  assert.equal(pristineTx, anchor, "rollback restores the anchor");
  assert.ok(doc.inputs[0].some((pair) => pair.key.slice(0, 2) === "02"), "rollback restores the signature");
  // The follow-up UTXO-claim edit must still drop the signature.
  const pair = doc.inputs[0].find((p) => p.key === "01");
  pair.value = pair.value.slice(0, -1) + (pair.value.endsWith("0") ? "1" : "0");
  rebuildDoc();
  assert.ok(!doc.inputs[0].some((p) => p.key.slice(0, 2) === "02"), "the post-rollback edit drops the signature");
});

test("the editor drops signing material when the anchor changes (issues #325, #360)", () => {
  const editor = read("src/js/psbt-editor.js");
  // The rebuild compares against the transaction and UTXO declarations the
  // pairs were inspected with, and re-anchors only after a successful build.
  assert.match(editor, /pristineTx !== null && signingAnchor\(doc\) !== pristineTx/);
  assert.match(editor, /dropSigningPairs\(doc\)/);
  assert.match(editor, /pristineTx = signingAnchor\(doc\)/);
  // Loads and wipes re-anchor so a fresh document's pairs are never stripped.
  assert.ok((editor.match(/pristineTx = null/g) || []).length >= 3, "load, load-failure, and wipe all reset the anchor");
});
