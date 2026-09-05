// Pure semantic comparison of two rust-bitcoin PSBT inspection documents
// (the output of psbtInspectDoc in psbt-wasm.js).
//
// The comparison deliberately works on decoded structure rather than raw PSBT
// bytes. PSBT map ordering is not a semantic difference, while transaction
// fields, PSBT key/value pairs, and signing material are reported separately.
// Both documents should come from the same decoder so field types line up
// (the editor compares rust-bitcoin's fresh decode of each side).
//
// v1 limitations (intentional):
// - Inputs/outputs are matched by index, not by prevout.
// - Map values from psbtInspectDoc are compared as raw hex primitives (===).
// - This engine only reports differences; it does not decide safety.

const SIGNING_FIELDS = new Set([
  "PSBT_IN_PARTIAL_SIG",
  "PSBT_IN_FINAL_SCRIPTSIG",
  "PSBT_IN_FINAL_SCRIPTWITNESS",
  "PSBT_IN_TAP_KEY_SIG",
  "PSBT_IN_TAP_SCRIPT_SIG",
  "PSBT_IN_SIGHASH_TYPE",
]);

// The unsigned transaction rides in the global map as key 00
// (PSBT_GLOBAL_UNSIGNED_TX). Its bytes are exactly the transaction the tx
// section already compares field by field, so the pair is excluded from the
// map comparison: counting it would report every transaction change a second
// time and flag a "metadata" change that is not one.
const UNSIGNED_TX_GLOBAL_KEY = "00";

const categoryFor = (name) => (SIGNING_FIELDS.has(name) ? "signing" : "metadata");

const mapByKey = (pairs = []) => {
  const out = new Map();
  for (const pair of pairs) {
    // Duplicate keys within one map are invalid PSBT (rust-bitcoin rejects
    // them), so the first occurrence is the only one that can exist.
    if (!out.has(pair.key)) out.set(pair.key, pair);
  }
  return out;
};

const compareMap = (before, after, scope, index = null) => {
  const left = mapByKey(before);
  const right = mapByKey(after);
  const changes = [];
  for (const [key, pair] of left) {
    const other = right.get(key);
    const path = { scope, index, key, name: pair.name || null };
    if (!other) changes.push({ ...path, kind: "removed", before: pair.value, after: null, category: categoryFor(pair.name) });
    else if (pair.value !== other.value) changes.push({ ...path, kind: "changed", before: pair.value, after: other.value, category: categoryFor(pair.name) });
  }
  for (const [key, pair] of right) {
    if (!left.has(key)) changes.push({ scope, index, key, name: pair.name || null, kind: "added", before: null, after: pair.value, category: categoryFor(pair.name) });
  }
  return changes;
};

const compareTransactionField = (changes, scope, index, field, before, after) => {
  if (before !== after) changes.push({ scope, index, field, kind: "changed", before, after, category: "transaction" });
};

const compareIndexed = (changes, before = [], after = [], scope, fields) => {
  const length = Math.max(before.length, after.length);
  for (let index = 0; index < length; index++) {
    const left = before[index];
    const right = after[index];
    if (left === undefined) { changes.push({ scope, index, kind: "added", before: null, after: right, category: "transaction" }); continue; }
    if (right === undefined) { changes.push({ scope, index, kind: "removed", before: left, after: null, category: "transaction" }); continue; }
    for (const field of fields) compareTransactionField(changes, scope, index, `${scope}[${index}].${field}`, left[field], right[field]);
  }
};

export const comparePsbtDocs = (before, after) => {
  if (!before || !after || typeof before !== "object" || typeof after !== "object") throw new Error("Both PSBT inspection documents are required.");
  const changes = [];
  const leftTx = before.tx || {};
  const rightTx = after.tx || {};
  for (const field of ["version", "locktime"]) compareTransactionField(changes, "transaction", null, field, leftTx[field], rightTx[field]);
  compareIndexed(changes, leftTx.inputs, rightTx.inputs, "input", ["txid", "vout", "scriptSig", "sequence"]);
  compareIndexed(changes, leftTx.outputs, rightTx.outputs, "output", ["value", "scriptPubKey"]);
  const globalPairs = (doc) => (doc.globals || []).filter((pair) => pair.key !== UNSIGNED_TX_GLOBAL_KEY);
  changes.push(...compareMap(globalPairs(before), globalPairs(after), "global"));
  const inputCount = Math.max((before.inputs || []).length, (after.inputs || []).length);
  for (let index = 0; index < inputCount; index++) changes.push(...compareMap(before.inputs?.[index], after.inputs?.[index], "input-map", index));
  const outputCount = Math.max((before.outputs || []).length, (after.outputs || []).length);
  for (let index = 0; index < outputCount; index++) changes.push(...compareMap(before.outputs?.[index], after.outputs?.[index], "output-map", index));
  const transactionChanges = changes.filter((change) => change.category === "transaction");
  const signingChanges = changes.filter((change) => change.category === "signing");
  const metadataChanges = changes.filter((change) => change.category === "metadata");
  return { equal: changes.length === 0, transactionChanged: transactionChanges.length > 0, signingChanged: signingChanges.length > 0, metadataChanged: metadataChanges.length > 0, changes };
};
