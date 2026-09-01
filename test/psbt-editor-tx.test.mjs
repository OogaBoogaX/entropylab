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
import { psbtEditorBuildDoc } from "../src/js/psbt-editor.js";
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
    doc.tx.outputs.push({ value: 0, scriptPubKey: "" });
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
  assert.equal(fresh.tx.outputs[before].value, 0);
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
  assert.match(editor, /tx\.inputs\.length > 1 \? `<button type="button" class="psbted-del" data-txin-del=/);
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
