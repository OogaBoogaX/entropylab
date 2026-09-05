// Semantic PSBT comparison (src/js/psbt-diff.js) and its editor report
// (psbtDiffHtml in src/js/psbt-editor.js). The engine is exercised against
// real rust-bitcoin inspection documents wherever possible — the mock
// documents mirror their shape (numeric satoshi values, hex pair values) so
// the tests cannot pass against a shape the decoder never produces.
// Run with `npm test` (part of the default suite).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc, psbtBuildBytes } from "../src/js/psbt-wasm.js";
import { psbtEditorBuildDoc, psbtDiffHtml } from "../src/js/psbt-editor.js";
import { comparePsbtDocs } from "../src/js/psbt-diff.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// The real decoder output for the committed 1-in/2-out P2WPKH fixture.
const fixtureDoc = () => {
  const b64 = readFileSync(join(root, "test", "fixtures", "psbt", "p2wpkh-1in-2out.b64"), "utf8").trim();
  return psbtInspectDoc(new Uint8Array(Buffer.from(b64, "base64")));
};

// Edits applied the way the editor applies them, then put through the same
// build + inspect round-trip the comparison UI uses on both sides.
const rebuild = (doc) => psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc)));

// A hand-written document in the exact shape psbtInspectDoc produces: numeric
// satoshi values, hex pair keys/values, the unsigned transaction riding in
// the global map as key 00.
const doc = (overrides = {}) => ({
  tx: {
    version: 2,
    locktime: 0,
    inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }],
    outputs: [{ value: 1000, scriptPubKey: "0014" + "22".repeat(20) }],
  },
  globals: [
    { key: "00", value: "aa", name: "PSBT_GLOBAL_UNSIGNED_TX" },
    { key: "01", value: "bb", name: "PSBT_GLOBAL_XPUB" },
  ],
  inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }]],
  outputs: [[]],
  ...overrides,
});

test("identical documents compare equal", () => {
  const result = comparePsbtDocs(doc(), doc());
  assert.equal(result.equal, true);
  assert.equal(result.changes.length, 0);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.signingChanged, false);
  assert.equal(result.metadataChanged, false);
});

test("PSBT map ordering does not create a difference", () => {
  const before = doc();
  const after = doc({ globals: [before.globals[1], before.globals[0]], inputs: [[before.inputs[0][0]]] });
  assert.equal(comparePsbtDocs(before, after).equal, true);
});

test("transaction changes are reported separately", () => {
  const after = doc({ tx: { ...doc().tx, outputs: [{ value: 900, scriptPubKey: "0014" + "22".repeat(20) }] } });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.transactionChanged, true);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.signingChanged, false);
  assert.deepEqual(result.changes, [{ scope: "output", index: 0, field: "output[0].value", kind: "changed", before: 1000, after: 900, category: "transaction" }]);
});

test("the unsigned-transaction global pair is not double-reported as metadata", () => {
  // Key 00 in the global map carries the unsigned transaction's bytes; its
  // hex changes with every transaction edit. The tx section already covers
  // the transaction, so a lone key-00 difference must report no change at
  // all — otherwise every transaction change would also flag "metadata".
  const before = doc();
  const after = doc({ globals: [{ key: "00", value: "ff", name: "PSBT_GLOBAL_UNSIGNED_TX" }, before.globals[1]] });
  assert.equal(comparePsbtDocs(before, after).equal, true);
});

test("a real transaction change flags the transaction and not the metadata", () => {
  // Regression for the double-report above, this time end to end: after a
  // real output edit, the rebuilt PSBT's global unsigned-tx pair genuinely
  // differs, and the metadata flag must still stay clear.
  const before = fixtureDoc();
  const draft = structuredClone(before);
  draft.tx.outputs[0].value = draft.tx.outputs[0].value - 1000;
  const after = rebuild(draft);
  assert.notEqual(before.globals.find((pair) => pair.key === "00").value, after.globals.find((pair) => pair.key === "00").value);
  const result = comparePsbtDocs(before, after);
  assert.equal(result.equal, false);
  assert.equal(result.transactionChanged, true);
  assert.equal(result.signingChanged, false);
  assert.equal(result.metadataChanged, false);
  assert.deepEqual(
    result.changes.map(({ scope, index, field, kind }) => ({ scope, index, field, kind })),
    [{ scope: "output", index: 0, field: "output[0].value", kind: "changed" }],
  );
});

test("a real reordered build compares equal to the original", () => {
  // The two serializations differ byte for byte in the input map, but the
  // decoded contents are the same PSBT.
  const before = fixtureDoc();
  assert.ok(before.inputs[0].length > 1, "fixture input map must hold several pairs");
  const draft = structuredClone(before);
  draft.inputs[0] = [...draft.inputs[0]].reverse();
  const after = rebuild(draft);
  const result = comparePsbtDocs(before, after);
  assert.equal(result.equal, true);
  assert.deepEqual(result.changes, []);
});

test("removing a real partial signature is a signing-only change", () => {
  const before = fixtureDoc();
  assert.ok(before.inputs[0].some((pair) => pair.name === "PSBT_IN_PARTIAL_SIG"), "fixture must carry a partial signature");
  const draft = structuredClone(before);
  draft.inputs[0] = draft.inputs[0].filter((pair) => pair.name !== "PSBT_IN_PARTIAL_SIG");
  const after = rebuild(draft);
  const result = comparePsbtDocs(before, after);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.signingChanged, true);
  assert.equal(result.changes.length, 1);
  assert.equal(result.changes[0].kind, "removed");
  assert.equal(result.changes[0].category, "signing");
  assert.equal(result.changes[0].name, "PSBT_IN_PARTIAL_SIG");
  assert.equal(result.changes[0].scope, "input-map");
  assert.equal(result.changes[0].index, 0);
});

test("partial signatures are classified as signing changes", () => {
  const after = doc({ inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }, { key: "02aabb", value: "dd", name: "PSBT_IN_PARTIAL_SIG" }]] });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.signingChanged, true);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.changes[0].kind, "added");
  assert.equal(result.changes[0].category, "signing");
});

test("sighash type is classified as a signing change", () => {
  const after = doc({ inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }, { key: "08", value: "01", name: "PSBT_IN_SIGHASH_TYPE" }]] });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.signingChanged, true);
  assert.equal(result.metadataChanged, false);
  assert.equal(result.changes[0].category, "signing");
  assert.equal(result.changes[0].name, "PSBT_IN_SIGHASH_TYPE");
});

test("metadata changes are distinguished from signing changes", () => {
  const after = doc({ globals: [doc().globals[0], { key: "01", value: "changed", name: "PSBT_GLOBAL_XPUB" }] });
  const result = comparePsbtDocs(doc(), after);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.signingChanged, false);
  assert.equal(result.metadataChanged, true);
  assert.equal(result.changes.length, 1);
  assert.equal(result.changes[0].kind, "changed");
  assert.equal(result.changes[0].category, "metadata");
});

test("added and removed transaction elements are reported without hiding map changes", () => {
  const before = doc();
  const after = doc({ tx: { ...before.tx, inputs: [], outputs: [before.tx.outputs[0], { value: 500, scriptPubKey: "0014" + "33".repeat(20) }] }, inputs: [], outputs: [[], []] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.transactionChanged, true);
  assert.ok(result.changes.some((change) => change.scope === "input" && change.kind === "removed"));
  assert.ok(result.changes.some((change) => change.scope === "output" && change.kind === "added"));
  assert.ok(result.changes.some((change) => change.scope === "input-map" && change.kind === "removed"));
});

test("map fields can be changed, added, and removed", () => {
  const before = doc();
  const after = doc({ globals: [{ key: "00", value: "aa", name: "PSBT_GLOBAL_UNSIGNED_TX" }, { key: "01", value: "changed" }, { key: "02", value: "new" }] });
  const result = comparePsbtDocs(before, after);
  assert.deepEqual(result.changes.map(({ scope, kind, key }) => ({ scope, kind, key })), [
    { scope: "global", kind: "changed", key: "01" },
    { scope: "global", kind: "added", key: "02" },
  ]);
});

test("reordered inputs are reported as changes (index matching is intentional in v1)", () => {
  const before = doc({ tx: { version: 2, locktime: 0, inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }, { txid: "22".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: 1000, scriptPubKey: "0014" + "22".repeat(20) }] }, inputs: [[], []] });
  const after = doc({ tx: { version: 2, locktime: 0, inputs: [{ txid: "22".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }, { txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }], outputs: [{ value: 1000, scriptPubKey: "0014" + "22".repeat(20) }] }, inputs: [[], []] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.transactionChanged, true);
  assert.ok(result.changes.some((c) => c.field === "input[0].txid"));
});

test("invalid comparison inputs fail explicitly", () => {
  assert.throws(() => comparePsbtDocs(null, {}), /Both PSBT inspection documents are required/);
});

// --- The editor's comparison report (psbtDiffHtml) ------------------------

test("the report announces semantically identical PSBTs", () => {
  const before = fixtureDoc();
  const html = psbtDiffHtml(comparePsbtDocs(before, fixtureDoc()), before, fixtureDoc(), "mainnet");
  assert.match(html, /Semantically identical/);
  assert.doesNotMatch(html, /<table/);
});

test("the report separates the transaction change, states the fee, and escapes nothing twice", () => {
  const before = fixtureDoc();
  const draft = structuredClone(before);
  draft.tx.outputs[0].value = draft.tx.outputs[0].value - 1000;
  const after = rebuild(draft);
  const html = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
  assert.match(html, /✕ The underlying transaction changed/);
  assert.match(html, /Signing state unchanged/);
  assert.match(html, /PSBT metadata unchanged/);
  assert.match(html, /Output 0 · value/);
  assert.match(html, new RegExp(`${before.tx.outputs[0].value} sats`));
  assert.match(html, new RegExp(`${after.tx.outputs[0].value} sats`));
  // The fee is PSBT-claimed inputs minus outputs; an output edit moves it.
  assert.match(html, /Fee \(from PSBT-claimed input amounts\)/);
  assert.match(html, /before = the PSBT in the editor/);
});

test("the report lists a removed signature under its input map", () => {
  const before = fixtureDoc();
  const draft = structuredClone(before);
  draft.inputs[0] = draft.inputs[0].filter((pair) => pair.name !== "PSBT_IN_PARTIAL_SIG");
  const after = rebuild(draft);
  const html = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
  assert.match(html, /✓ The underlying transaction is unchanged/);
  assert.match(html, /⚠ Signing state changed/);
  assert.match(html, /Input 0 key-value map/);
  assert.match(html, /PSBT_IN_PARTIAL_SIG/);
});

test("the report escapes pair names and values from an untrusted PSBT", () => {
  const evil = '<img src=x onerror=alert(1)>';
  const before = doc({ inputs: [[{ key: "fc01", value: "<script>alert(1)</script>", name: evil, decoded: null }]] });
  const html = psbtDiffHtml(comparePsbtDocs(before, doc()), before, doc(), "mainnet");
  assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.ok(html.includes("&lt;img src=x"), "escaped name missing");
  assert.ok(html.includes("&lt;script&gt;"), "escaped value missing");
});
