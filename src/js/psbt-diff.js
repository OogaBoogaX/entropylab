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
  // BIP-373 MuSig2 signing-session material (audit B3): nonce substitution
  // is the key-extraction class, a swapped participant key re-targets the
  // aggregate key, and a partial signature is a signature share.
  "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS",
  "PSBT_IN_MUSIG2_PUB_NONCE",
  "PSBT_IN_MUSIG2_PARTIAL_SIG",
]);

// The unsigned transaction rides in the global map as key 00
// (PSBT_GLOBAL_UNSIGNED_TX). Its bytes are exactly the transaction the tx
// section already compares field by field, so the pair is excluded from the
// map comparison: counting it would report every transaction change a second
// time and flag a "metadata" change that is not one.
const UNSIGNED_TX_GLOBAL_KEY = "00";

const categoryFor = (name) => (SIGNING_FIELDS.has(name) ? "signing" : "metadata");

// Duplicate keys within one map are invalid PSBT, but the inspect decoder
// does not reject them (psbt-wasm read_map caps the pair count yet keeps
// every pair), so one key can genuinely map to several pairs here. The
// comparison therefore groups pairs by key and compares the groups as
// multisets: equal values pair off regardless of map order, and whatever is
// left over on either side — including an extra occurrence of a key the
// other side also lists — is a real difference (audit B2: a duplicate
// PSBT_IN_SIGHASH_TYPE hidden behind a matching first record must surface).
const groupByKey = (pairs = []) => {
  const out = new Map();
  for (const pair of pairs) {
    const group = out.get(pair.key);
    if (group) group.push(pair);
    else out.set(pair.key, [pair]);
  }
  return out;
};

const compareMap = (before, after, scope, index = null) => {
  const left = groupByKey(before);
  const right = groupByKey(after);
  const changes = [];
  for (const [key, leftPairs] of left) {
    const rightPairs = right.get(key) || [];
    const name = leftPairs[0].name || rightPairs[0]?.name || null;
    const path = { scope, index, key, name };
    const category = categoryFor(name);
    // Multiset pairing by value: a value found on both sides cancels out,
    // whichever map position it sat at. Leftovers are reported; each entry
    // carries the ordinal of its occurrence within the key's group so the
    // report can show the exact pair that differs.
    const unmatchedRight = rightPairs.map((pair, ordinal) => ({ pair, ordinal }));
    const unmatchedLeft = [];
    leftPairs.forEach((pair, ordinal) => {
      const at = unmatchedRight.findIndex((entry) => entry.pair.value === pair.value);
      if (at === -1) unmatchedLeft.push({ pair, ordinal });
      else unmatchedRight.splice(at, 1);
    });
    const count = Math.max(unmatchedLeft.length, unmatchedRight.length);
    for (let i = 0; i < count; i++) {
      const l = unmatchedLeft[i];
      const r = unmatchedRight[i];
      if (l && r) changes.push({ ...path, kind: "changed", before: l.pair.value, after: r.pair.value, beforeOrdinal: l.ordinal, afterOrdinal: r.ordinal, category });
      else if (l) changes.push({ ...path, kind: "removed", before: l.pair.value, after: null, beforeOrdinal: l.ordinal, category });
      else changes.push({ ...path, kind: "added", before: null, after: r.pair.value, afterOrdinal: r.ordinal, category });
    }
  }
  for (const [key, rightPairs] of right) {
    if (left.has(key)) continue;
    rightPairs.forEach((pair, ordinal) => {
      changes.push({ scope, index, key, name: pair.name || null, kind: "added", before: null, after: pair.value, afterOrdinal: ordinal, category: categoryFor(pair.name) });
    });
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
