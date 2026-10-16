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
import { SigHash, Transaction, p2wpkh } from "@scure/btc-signer";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { psbtInspectDoc, psbtBuildBytes } from "../src/js/psbt-wasm.js";
import { psbtEditorBuildDoc, psbtDiffHtml } from "../src/js/psbt-editor.js";
import { comparePsbtDocs } from "../src/js/psbt-diff.js";
import { MiniDocument } from "./mini-dom.mjs";

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

test("decoded public keys and origins are separate exact copy targets, while raw private-capable fields stay private", () => {
  const pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
  const fingerprint = "3442193e";
  const before = doc({ globals: [], inputs: [[]] });
  const after = doc({ globals: [
    { key: "01aa", value: "bb", name: "PSBT_GLOBAL_XPUB", decoded: { xpub, fingerprint, path: "m/0'" } },
    { key: "fcaa", value: "private-opaque-value", name: "PSBT_GLOBAL_PROPRIETARY", decoded: { prefixText: "private-prefix", subtype: 0, keydata: "00" } },
  ], inputs: [[
    { key: `06${pubkey}`, value: "cc", name: "PSBT_IN_BIP32_DERIVATION", decoded: { pubkey, fingerprint, path: "m/0'" } },
    { key: "17", value: pubkey.slice(2), name: "PSBT_IN_TAP_INTERNAL_KEY", decoded: { xonly: pubkey.slice(2) } },
  ]] });
  const document = new MiniDocument();
  document.body.innerHTML = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet", { copyIcon: () => '<svg data-test-copy-icon></svg>' });
  const values = document.querySelectorAll("[data-public-value]");
  for (const expected of [pubkey, xpub, fingerprint, pubkey.slice(2)]) {
    const value = values.find((node) => (node.dataset.copyValue ?? node.textContent) === expected);
    assert.ok(value, `missing exact public copy payload ${expected}`);
    assert.ok(value.closest("[data-copy-group]").querySelector("[data-public-copy]"));
  }
  assert.equal(values.some((value) => value.textContent.includes("private-")), false);
  assert.ok(document.querySelector("[data-private-value]"));
});

test("comparison output addresses use the public copy contract", () => {
  const before = doc();
  const after = doc({ tx: { ...doc().tx, outputs: [{ value: 1000, scriptPubKey: "76a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac" }] } });
  const document = new MiniDocument();
  document.body.innerHTML = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
  assert.ok(document.querySelectorAll("[data-public-value]").some((value) => value.textContent === "1BonMcawnmL4XMxEcofTWqTXxtk9K7hEWe"));
});

test("a proprietary prefix's bidi and invisible characters are neutralized in the diff report (audit S36-2)", () => {
  // describePair prints a proprietary key's decoded prefix text; raw, a
  // bidi override in it reorders the report line it lands in.
  const pair = {
    key: "fcaa",
    name: "PSBT_GLOBAL_PROPRIETARY",
    value: "deadbeef",
    decoded: { prefixText: "abc\u202Edef", prefix: "616263e280ae646566", subtype: 0 },
  };
  const before = doc({ globals: [...doc().globals, pair] });
  const after = doc();
  const diff = comparePsbtDocs(before, after);
  const html = psbtDiffHtml(diff, before, after, "mainnet");
  assert.ok(!html.includes("\u202E"), "the diff renders a live bidi override");
  assert.ok(html.includes("abc\uFFFDdef"), "the override is not visibly neutralized");
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

test("MuSig2 (BIP-373) input pairs are named and classified as signing changes (audit B3)", () => {
  // Real round-trips through the decoder on both sides, so the pair names
  // come from psbtInspectDoc. Shapes follow BIP-373: keydata is the
  // participant pubkey (33 bytes) plus the aggregate pubkey (33 bytes); the
  // value is a participant-pubkey list, a 66-byte public nonce, or a
  // 32-byte partial signature. A swapped nonce is the key-extraction class.
  const participant = "02" + "11".repeat(32);
  const aggregate = "03" + "22".repeat(32);
  const otherParticipant = "02" + "44".repeat(32);
  const cases = [
    { name: "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS", key: "1a" + aggregate, before: "01" + participant, after: "02" + participant + otherParticipant },
    { name: "PSBT_IN_MUSIG2_PUB_NONCE", key: "1b" + participant + aggregate, before: "02" + "55".repeat(32) + "02" + "66".repeat(32), after: "02" + "77".repeat(32) + "02" + "88".repeat(32) },
    { name: "PSBT_IN_MUSIG2_PARTIAL_SIG", key: "1c" + participant + aggregate, before: "99".repeat(32), after: "aa".repeat(32) },
  ];
  for (const { name, key, before: valueBefore, after: valueAfter } of cases) {
    const withPair = (value) => {
      const draft = fixtureDoc();
      draft.inputs[0].push({ key, value });
      return rebuild(draft);
    };
    const before = withPair(valueBefore);
    const after = withPair(valueAfter);
    const inspected = after.inputs[0].find((pair) => pair.key === key);
    assert.equal(inspected.name, name, `${name} must not surface as PSBT_IN_UNKNOWN`);
    const result = comparePsbtDocs(before, after);
    assert.equal(result.equal, false);
    assert.equal(result.transactionChanged, false);
    assert.equal(result.metadataChanged, false, `${name} change must not read as metadata`);
    assert.equal(result.signingChanged, true, `${name} change must read as signing`);
    assert.deepEqual(
      result.changes.map(({ kind, category, name: changedName }) => ({ kind, category, name: changedName })),
      [{ kind: "changed", category: "signing", name }],
    );
    const html = psbtDiffHtml(result, before, after, "mainnet");
    assert.match(html, /Signing state changed/);
    assert.doesNotMatch(html, /Signing state unchanged/);
  }
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

// --- Duplicate keys (audit B2) ---------------------------------------------
// The inspect decoder accepts duplicate keys in a map (psbt-wasm read_map
// caps the count but keeps every pair), so a pasted PSBT can carry a second
// PSBT_IN_SIGHASH_TYPE behind a matching first record. The comparison must
// treat each key's pairs as a multiset: every occurrence counts.

test("a hidden duplicate signing key is reported, not collapsed onto the first occurrence (audit B2)", () => {
  // Real sighash values are 4-byte little-endian: 01000000 = ALL,
  // 02000000 = NONE. The first records match; only the hidden one differs.
  const witnessUtxo = { key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" };
  const sighash = (value) => ({ key: "03", value, name: "PSBT_IN_SIGHASH_TYPE" });
  const before = doc({ inputs: [[witnessUtxo, sighash("01000000")]] });
  const after = doc({ inputs: [[witnessUtxo, sighash("01000000"), sighash("02000000")]] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.equal, false, "a document carrying a hidden extra record must not compare equal");
  assert.equal(result.signingChanged, true);
  const hidden = result.changes.find((change) => change.key === "03");
  assert.equal(hidden.kind, "added");
  assert.equal(hidden.category, "signing");
  assert.equal(hidden.name, "PSBT_IN_SIGHASH_TYPE");
  assert.equal(hidden.after, "02000000");
  // And mirrored: an extra record only on the editor's side is a removal.
  const reverse = comparePsbtDocs(after, before);
  assert.equal(reverse.equal, false);
  assert.equal(reverse.signingChanged, true);
  const removed = reverse.changes.find((change) => change.key === "03");
  assert.equal(removed.kind, "removed");
  assert.equal(removed.category, "signing");
  assert.equal(removed.before, "02000000");
});

test("duplicate-key order within a map is still a non-difference (multiset, not sequence)", () => {
  // The same multiset of values under one key, listed in a different order,
  // is the same PSBT content — map ordering is not a semantic difference.
  const pair = (value) => ({ key: "fc01", value, name: null });
  const before = doc({ globals: [...doc().globals, pair("aa"), pair("bb")] });
  const after = doc({ globals: [...doc().globals, pair("bb"), pair("aa")] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.equal, true);
  assert.deepEqual(result.changes, []);
});

test("a value change inside a duplicated key is reported instead of disappearing", () => {
  const pair = (value) => ({ key: "fc01", value, name: null });
  const before = doc({ globals: [...doc().globals, pair("aa"), pair("bb")] });
  const after = doc({ globals: [...doc().globals, pair("aa"), pair("cc")] });
  const result = comparePsbtDocs(before, after);
  assert.equal(result.equal, false);
  assert.equal(result.metadataChanged, true);
  const changed = result.changes.find((change) => change.key === "fc01");
  assert.equal(changed.kind, "changed");
  assert.equal(changed.before, "bb");
  assert.equal(changed.after, "cc");
});

// The verdict gate: neither the identity headline nor the signing-unchanged
// line may print while a compared document is one equality cannot be claimed
// for — rust-bitcoin rejected it, its unsigned transaction is
// consensus-invalid, or its duplicate-key sanitize family is in problem
// state. The mocks below attach those fields exactly as psbtInspectDoc sets
// them (rustBitcoinError / txSanityError strings, sanitize family states).

// A joint sighash pair shared by the gated-document tests.
const sighashPair = { key: "03", value: "01000000", name: "PSBT_IN_SIGHASH_TYPE" };
const dupProblemSanitize = {
  duplicateKeys: { state: "problem", findings: [{ code: "duplicate_key", scope: "input", index: 0, name: "PSBT_IN_SIGHASH_TYPE" }], truncated: false },
  xpubDerivesChild: { state: "complete", findings: [], truncated: false },
};

test("the report never claims identity for a document with a problem-state duplicate-key finding (audit B2)", () => {
  // The decoder produces exactly this for a PSBT carrying duplicate keys:
  // both sides decode to the same multiset, the sanitize family is in
  // problem state, and equality still cannot be claimed.
  const base = doc({ inputs: [[sighashPair, { ...sighashPair, value: "02000000" }]] });
  const before = { ...base, sanitize: dupProblemSanitize };
  const after = { ...doc({ inputs: [[sighashPair, { ...sighashPair, value: "02000000" }]] }), sanitize: dupProblemSanitize };
  const diff = comparePsbtDocs(before, after);
  assert.equal(diff.equal, true, "identical multisets compare equal; the report layer must still withhold the verdict");
  const html = psbtDiffHtml(diff, before, after, "mainnet");
  assert.doesNotMatch(html, /Semantically identical/);
  assert.doesNotMatch(html, /Signing state unchanged\./);
  assert.match(html, /equality cannot be claimed for an invalid document/);
});

test("the gate triggers on either compared document, and on rustBitcoinError or txSanityError", () => {
  const clean = doc();
  for (const flagged of [
    { ...doc(), sanitize: dupProblemSanitize },
    { ...doc(), rustBitcoinError: "duplicate key" },
    { ...doc(), txSanityError: "bad-txns-inputs-duplicate" },
  ]) {
    for (const [before, after] of [[clean, flagged], [flagged, clean]]) {
      const html = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
      assert.doesNotMatch(html, /Semantically identical/);
      assert.doesNotMatch(html, /Signing state unchanged\./);
      assert.match(html, /equality cannot be claimed for an invalid document/);
    }
  }
});

test("a pasted PSBT hiding a duplicate sighash behind a matching first record reports the hidden pair (audit B2, end to end)", () => {
  // as rust-bitcoin's serialize-layer decode of a v0 duplicate-key PSBT plus
  // this crate's sanitize analysis would report it.
  const before = doc({ inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }, sighashPair]] });
  const after = {
    ...doc({ inputs: [[{ key: "01", value: "cc", name: "PSBT_IN_WITNESS_UTXO" }, sighashPair, { ...sighashPair, value: "02000000" }]] }),
    rustBitcoinError: "duplicate key",
    sanitize: dupProblemSanitize,
  };
  const html = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
  assert.doesNotMatch(html, /Semantically identical/);
  assert.doesNotMatch(html, /Signing state unchanged\./);
  assert.match(html, /Signing state changed/);
  assert.match(html, /PSBT_IN_SIGHASH_TYPE/);
  assert.match(html, /02000000/, "the hidden record's value must appear in the report");
  assert.match(html, /equality cannot be claimed for an invalid document/);
});

test("the committed fixture with a raw duplicate sighash record is gated and reports the hidden pair (audit B2, real bytes)", () => {
  // The same attack as above, built from bytes rather than a hand-written
  // document: a second PSBT_IN_SIGHASH_TYPE (SIGHASH_NONE) is appended to
  // input 0 of the committed fixture, so the decoder itself must set the
  // fields the gate reads (#867).
  const raw = Buffer.from(readFileSync(join(root, "test", "fixtures", "psbt", "p2wpkh-1in-2out.b64"), "utf8").trim(), "base64");
  const compact = (n) => (n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8]);
  const readCompact = (at) => (raw[at] < 0xfd ? [raw[at], 1] : [raw.readUInt16LE(at + 1), 3]);
  // BIP-174 maps after the 5-byte magic: [global, input 0, outputs...].
  const maps = [];
  for (let at = 5; at < raw.length; ) {
    const pairs = [];
    for (;;) {
      const [keyLength, keySize] = readCompact(at);
      at += keySize;
      if (!keyLength) break;
      const key = raw.subarray(at, (at += keyLength));
      const [valueLength, valueSize] = readCompact(at);
      at += valueSize;
      pairs.push([key, raw.subarray(at, (at += valueLength))]);
    }
    maps.push(pairs);
  }
  const firstSighash = maps[1].find(([key]) => key.length === 1 && key[0] === 0x03);
  assert.ok(firstSighash, "the fixture's input 0 carries a sighash record");
  assert.equal(Buffer.from(firstSighash[1]).toString("hex"), "01000000", "the fixture signs SIGHASH_ALL");
  maps[1].push([Buffer.from([0x03]), Buffer.from([0x02, 0x00, 0x00, 0x00])]);
  const tampered = Uint8Array.from([...raw.subarray(0, 5), ...maps.flatMap((pairs) => [...pairs.flatMap(([key, value]) => [...compact(key.length), ...key, ...compact(value.length), ...value]), 0x00])]);
  const before = fixtureDoc();
  const after = psbtInspectDoc(tampered);
  assert.match(after.rustBitcoinError, /duplicate key/);
  assert.equal(after.sanitize.duplicateKeys.state, "problem");
  const html = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
  assert.doesNotMatch(html, /Semantically identical/);
  assert.doesNotMatch(html, /Signing state unchanged\./);
  assert.match(html, /Signing state changed/);
  assert.match(html, /PSBT_IN_SIGHASH_TYPE[\s\S]*SIGHASH_NONE \(0x2\)/, "the hidden record must appear in the report, decoded");
  assert.match(html, /equality cannot be claimed for an invalid document/);
});

test("a clean pair of documents still earns the identity headline", () => {
  const before = doc();
  const html = psbtDiffHtml(comparePsbtDocs(before, doc()), before, doc(), "mainnet");
  assert.match(html, /Semantically identical/);
  assert.doesNotMatch(html, /equality cannot be claimed for an invalid document/);
});

// --- Every compared field reaches the verdict --------------------------------
// The report's headline lines are the verdict a user acts on, so each field
// the engine compares must move them on its own. A mutation run on rock
// 02e402e found these unguarded: dropping any one of them from psbt-diff.js
// (or the per-index row filter from psbtDiffHtml) left the suite green while
// the report would read "Semantically identical", "Signing state unchanged" or
// "The underlying transaction is unchanged" for a PSBT that differs.

// The report's section for one map, found by its heading.
const reportSection = (html, title) => {
  const document = new MiniDocument();
  document.body.innerHTML = html;
  const section = document.querySelectorAll("section").find((node) => node.querySelector("h3")?.textContent === title);
  assert.ok(section, `the report has no "${title}" section`);
  return section;
};

test("each unsigned-transaction field, changed alone, is a transaction change", () => {
  const base = doc().tx;
  const input = (patch) => ({ ...base, inputs: [{ ...base.inputs[0], ...patch }] });
  const output = (patch) => ({ ...base, outputs: [{ ...base.outputs[0], ...patch }] });
  const cases = [
    ["transaction", null, "version", 2, 1, { ...base, version: 1 }],
    ["transaction", null, "locktime", 0, 800000, { ...base, locktime: 800000 }],
    ["input", 0, "input[0].txid", "11".repeat(32), "33".repeat(32), input({ txid: "33".repeat(32) })],
    ["input", 0, "input[0].vout", 0, 1, input({ vout: 1 })],
    ["input", 0, "input[0].scriptSig", "", "00", input({ scriptSig: "00" })],
    ["input", 0, "input[0].sequence", 4294967295, 4294967293, input({ sequence: 4294967293 })],
    ["output", 0, "output[0].value", 1000, 999, output({ value: 999 })],
    ["output", 0, "output[0].scriptPubKey", "0014" + "22".repeat(20), "0014" + "33".repeat(20), output({ scriptPubKey: "0014" + "33".repeat(20) })],
  ];
  for (const [scope, index, field, before, after, tx] of cases) {
    const result = comparePsbtDocs(doc(), doc({ tx }));
    assert.equal(result.equal, false, `a ${field} change compared equal`);
    assert.equal(result.transactionChanged, true, `a ${field} change is not a transaction change`);
    assert.equal(result.signingChanged, false);
    assert.equal(result.metadataChanged, false);
    assert.deepEqual(result.changes, [{ scope, index, field, kind: "changed", before, after, category: "transaction" }]);
  }
});

test("a version, locktime, prevout-index or sequence edit made by an independent PSBT library is a transaction change", () => {
  // Real PSBTs built by @scure/btc-signer (an independent implementation) and
  // decoded by the inspector the Compare tool runs on both sides, so the field
  // names compared are the decoder's own, not the mock's.
  const script = p2wpkh(secp256k1.getPublicKey(new Uint8Array(32).fill(1), true)).script;
  const signerPsbt = ({ version = 2, lockTime = 0, index = 0, sequence = 0xffffffff } = {}) => {
    const tx = new Transaction({ version, lockTime });
    tx.addInput({ txid: "11".repeat(32), index, sequence, witnessUtxo: { script, amount: 150000n } });
    tx.addOutput({ script, amount: 100000n });
    return psbtInspectDoc(tx.toPSBT(0));
  };
  const before = signerPsbt();
  for (const [field, edit, from, to] of [
    ["version", { version: 1 }, 2, 1],
    ["locktime", { lockTime: 800000 }, 0, 800000],
    ["input[0].vout", { index: 1 }, 0, 1],
    ["input[0].sequence", { sequence: 0xfffffffd }, 0xffffffff, 0xfffffffd],
  ]) {
    const after = signerPsbt(edit);
    const result = comparePsbtDocs(before, after);
    assert.equal(result.equal, false, `a real ${field} edit compared equal`);
    assert.equal(result.transactionChanged, true);
    assert.equal(result.signingChanged, false);
    assert.equal(result.metadataChanged, false);
    assert.deepEqual(result.changes.map(({ field: changed, before: was, after: now }) => ({ field: changed, before: was, after: now })), [{ field, before: from, after: to }]);
    const html = psbtDiffHtml(result, before, after, "mainnet");
    assert.match(html, /✕ The underlying transaction changed/);
    assert.doesNotMatch(html, /Semantically identical/);
  }
});

test("an input or output added or removed on its own is a transaction change", () => {
  // The older test above adds an output and removes an input together, so
  // either classification alone kept transactionChanged true.
  const base = doc();
  const twoInputs = doc({ tx: { ...base.tx, inputs: [...base.tx.inputs, { txid: "33".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }] }, inputs: [...base.inputs, []] });
  const twoOutputs = doc({ tx: { ...base.tx, outputs: [...base.tx.outputs, { value: 500, scriptPubKey: "0014" + "33".repeat(20) }] }, outputs: [[], []] });
  for (const [label, before, after, scope, kind] of [
    ["input added", base, twoInputs, "input", "added"],
    ["input removed", twoInputs, base, "input", "removed"],
    ["output added", base, twoOutputs, "output", "added"],
    ["output removed", twoOutputs, base, "output", "removed"],
  ]) {
    const result = comparePsbtDocs(before, after);
    assert.equal(result.transactionChanged, true, `${label}: not a transaction change`);
    assert.equal(result.signingChanged, false);
    assert.equal(result.metadataChanged, false);
    assert.deepEqual(result.changes.map(({ scope: changed, index, kind: how, category }) => ({ scope: changed, index, kind: how, category })), [{ scope, index: 1, kind, category: "transaction" }]);
    const html = psbtDiffHtml(result, before, after, "mainnet");
    assert.match(html, /✕ The underlying transaction changed/, label);
    assert.doesNotMatch(html, /✓ The underlying transaction is unchanged/, label);
  }
});

// A real round trip with one changed pair on input 0 must read as signing:
// the transaction and the metadata unchanged, and the report must say so.
const assertSigningChange = (before, after, name) => {
  assert.equal(after.inputs[0].find((pair) => pair.name === name)?.name, name, `${name} must not surface as PSBT_IN_UNKNOWN`);
  const result = comparePsbtDocs(before, after);
  assert.equal(result.equal, false);
  assert.equal(result.transactionChanged, false);
  assert.equal(result.metadataChanged, false, `${name} change must not read as metadata`);
  assert.equal(result.signingChanged, true, `${name} change must read as signing`);
  assert.deepEqual(
    result.changes.map(({ kind, category, name: changedName }) => ({ kind, category, name: changedName })),
    [{ kind: "changed", category: "signing", name }],
  );
  const html = psbtDiffHtml(result, before, after, "mainnet");
  assert.match(html, /⚠ Signing state changed/);
  assert.doesNotMatch(html, /Signing state unchanged/);
};

test("a final scriptSig and both taproot signature fields are signing changes (BIP-174 0x07, BIP-371 0x13/0x14)", () => {
  // Same real round trip as the MuSig2 test. Value shapes: 0x07 is script
  // bytes; 0x13 a 64-byte Schnorr signature; 0x14 is keyed by an x-only
  // pubkey (secp256k1's generator x here) and a 32-byte leaf hash.
  const generatorX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const cases = [
    { name: "PSBT_IN_FINAL_SCRIPTSIG", key: "07", before: "160014" + "11".repeat(20), after: "160014" + "33".repeat(20) },
    { name: "PSBT_IN_TAP_KEY_SIG", key: "13", before: "11".repeat(64), after: "22".repeat(64) },
    { name: "PSBT_IN_TAP_SCRIPT_SIG", key: "14" + generatorX + "55".repeat(32), before: "11".repeat(64), after: "22".repeat(64) },
  ];
  for (const { name, key, before, after } of cases) {
    const withPair = (value) => {
      const draft = fixtureDoc();
      draft.inputs[0].push({ key, value });
      return rebuild(draft);
    };
    assertSigningChange(withPair(before), withPair(after), name);
  }
});

test("a swapped final witness is a signing change, not metadata (BIP-174 0x08, finalized by an independent signer)", () => {
  // The editor's builder verifies a final witness against its previous
  // output, so both sides come from @scure/btc-signer: the same P2WPKH spend
  // signed and finalized once with SIGHASH_ALL and once with
  // ALL|ANYONECANPAY. Finalizing drops everything but the UTXO and the final
  // witness, so the witness is the only pair that differs.
  const key = new Uint8Array(32).fill(1);
  const script = p2wpkh(secp256k1.getPublicKey(key, true)).script;
  const finalized = (sighashType) => {
    const tx = new Transaction();
    tx.addInput({ txid: "11".repeat(32), index: 0, witnessUtxo: { script, amount: 150000n }, ...(sighashType ? { sighashType } : {}) });
    tx.addOutput({ script, amount: 100000n });
    tx.sign(key, sighashType ? [sighashType] : undefined);
    tx.finalize();
    return psbtInspectDoc(tx.toPSBT(0));
  };
  assertSigningChange(finalized(), finalized(SigHash.ALL_ANYONECANPAY), "PSBT_IN_FINAL_SCRIPTWITNESS");
});

test("output key-value maps are compared: a re-pointed or stripped change-output derivation is reported under that output", () => {
  // The fixture's output 1 carries PSBT_OUT_BIP32_DERIVATION, the record a
  // wallet reads to recognise its own change. Re-pointing it to another
  // master fingerprint, or stripping it, must not compare equal.
  const before = fixtureDoc();
  const derivation = before.outputs[1].find((pair) => pair.name === "PSBT_OUT_BIP32_DERIVATION");
  assert.ok(derivation && derivation.value.startsWith("12345678"), "fixture output 1 must carry a derivation from fingerprint 12345678");
  const isDerivation = (pair) => pair.name === "PSBT_OUT_BIP32_DERIVATION";
  for (const [kind, edit, shown] of [
    ["changed", (pairs) => pairs.map((pair) => (isDerivation(pair) ? { key: pair.key, value: "87654321" + pair.value.slice(8) } : pair)), ["12345678", "87654321"]],
    ["removed", (pairs) => pairs.filter((pair) => !isDerivation(pair)), ["12345678"]],
  ]) {
    const draft = structuredClone(before);
    draft.outputs[1] = edit(draft.outputs[1]);
    const after = rebuild(draft);
    const result = comparePsbtDocs(before, after);
    assert.equal(result.equal, false, `a ${kind} output derivation compared equal`);
    assert.equal(result.metadataChanged, true);
    assert.equal(result.transactionChanged, false);
    assert.equal(result.signingChanged, false);
    assert.deepEqual(
      result.changes.map(({ scope, index, kind: how, name }) => ({ scope, index, kind: how, name })),
      [{ scope: "output-map", index: 1, kind, name: "PSBT_OUT_BIP32_DERIVATION" }],
    );
    const html = psbtDiffHtml(result, before, after, "mainnet");
    assert.match(html, /⚠ PSBT metadata changed/);
    assert.doesNotMatch(html, /Semantically identical/);
    const section = reportSection(html, "Output 1 key-value map").textContent;
    for (const fingerprint of shown) assert.ok(section.includes(fingerprint), `the output 1 row does not show fingerprint ${fingerprint}`);
  }
});

test("each map change is listed only under its own input", () => {
  // A row looks its values up in its section's own map, so a misfiled row
  // shows a dash rather than the other input's value; counting the rows is
  // what catches it.
  const pair = (key, value) => ({ key, value, name: null });
  const tx = { ...doc().tx, inputs: [doc().tx.inputs[0], { txid: "33".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }] };
  const before = doc({ tx, inputs: [[pair("fc01", "a0a0")], [pair("fc02", "b0b0")]] });
  const after = doc({ tx, inputs: [[pair("fc01", "a1a1")], [pair("fc02", "b1b1")]] });
  const html = psbtDiffHtml(comparePsbtDocs(before, after), before, after, "mainnet");
  for (const [index, was, now] of [[0, "a0a0", "a1a1"], [1, "b0b0", "b1b1"]]) {
    const rows = reportSection(html, `Input ${index} key-value map`).querySelector("tbody").querySelectorAll("tr");
    assert.equal(rows.length, 1, `input ${index}'s section lists another input's change`);
    assert.ok(rows[0].textContent.includes(was) && rows[0].textContent.includes(now), `input ${index}'s row does not show ${was} → ${now}`);
  }
});
