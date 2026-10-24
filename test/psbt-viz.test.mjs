// Tests for the pure half of the PSBT flow visualizer (src/js/psbt-viz.js) —
// the mempool.space-style inputs → transaction → outputs diagram rendered at
// the top of the PSBT editor. Selection state, DOM binding, the connector
// path drawing and the detail panel live in psbt-editor.js and are covered
// by the Firefox browser suite (test/browser-suite.html).
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtVizHtml } from "../src/js/psbt-viz.js";
import * as vizModule from "../src/js/psbt-viz.js";
import { comparePsbtDocs } from "../src/js/psbt-diff.js";
import { psbtDiffHtml, satsToBtc } from "../src/js/psbt-editor.js";
import { addressFromScript } from "../src/js/addresses.js";
import { MiniDocument } from "./mini-dom.mjs";

// BIP-174 valid vector 2 (same file as in test/psbt-wasm.test.mjs): two
// inputs — a finalized P2PKH scriptSig with no amount claim and a nested
// P2WPKH carrying a 100000000-sat witness UTXO — and two P2PKH outputs.
const VALID_HEX =
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
  "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40" +
  "bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000" +
  "0001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf133" +
  "6f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1" +
  "f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";
const VALID = new Uint8Array(VALID_HEX.match(/.{2}/g).map((b) => parseInt(b, 16)));

const inspectValid = () => psbtInspectDoc(VALID);

test("diagram addresses supply full public copy payloads without replacing navigation", () => {
  const document = new MiniDocument();
  document.body.innerHTML = psbtVizHtml(inspectValid(), "mainnet", { copyIcon: () => '<svg data-test-copy-icon></svg>' });
  const values = document.querySelectorAll("[data-public-value]");
  assert.equal(values.length, 3);
  assert.deepEqual(values.slice(1).map((value) => value.dataset.copyValue), [
    "1BonMcawnmL4XMxEcofTWqTXxtk9K7hEWe", "1B9N1re3RYdB7RPhsNS92vbYQegYWZW3og",
  ]);
  for (const value of values) {
    assert.equal(value.closest("[data-viz]"), null, "copy must not also navigate");
    assert.ok(value.closest("[data-copy-group]").querySelector("[data-public-copy]"));
  }
  assert.equal(document.querySelectorAll("[data-viz]").length, 5);
  assert.equal(document.querySelectorAll("button button").length, 0);
});

// The diagram groups read-only sats with narrow no-break spaces; keep the
// escape visible instead of hiding invisible characters in assertions.
const sats = (digits) => digits.replace(/\B(?=(\d{3})+(?!\d))/g, ",");

// A minimal synthetic document for shapes the vector does not exercise.
const syntheticDoc = (overrides = {}) => ({
  psbtVersion: 0,
  tx: {
    version: 2,
    locktime: 0,
    inputs: [{ txid: "00".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 }],
    outputs: [{ value: 5000, scriptPubKey: "6a046f726469", asm: "OP_RETURN OP_PUSHBYTES_4 6f726469" }],
  },
  globals: [],
  inputs: [[]],
  outputs: [[]],
  totalIn: null,
  totalOut: 5000,
  fee: { known: false },
  rustBitcoinError: null,
  ...overrides,
});

test("the diagram shows one box per input and output with decoded claims", () => {
  const html = psbtVizHtml(inspectValid(), "mainnet");
  // The count rides in its own element, so match the pair, not the spacing.
  assert.match(html, /Inputs[\s\S]{0,40}\(2\)/);
  assert.match(html, /Outputs[\s\S]{0,40}\(2\)/);
  for (const target of ["input:0", "input:1", "output:0", "output:1"]) {
    assert.ok(html.includes(`data-viz="${target}"`), `missing box ${target}`);
  }
  // Input 0 carries only a finalized scriptSig: no claim, but a status.
  assert.ok(html.includes("no amount claim"), "input without utxo pairs must say so");
  assert.ok(html.includes("finalized"), "finalized input status missing");
  // Input 1's witness UTXO claim renders as grouped sats plus the address.
  assert.ok(html.includes(`${sats("100000000")} sats`), "witness UTXO claim missing");
  assert.ok(html.includes("36YhUacEtc"), "P2SH claim address missing");
  // Outputs render their addresses, script tags, and editable sats fields.
  // Box labels truncate mid-string (mempool.space-style); the full address
  // survives in the tooltip and the button's aria-label.
  assert.ok(html.includes("1BonMcawnm…k9K7hEWe"), "output 0 address missing");
  assert.ok(html.includes('title="1BonMcawnmL4XMxEcofTWqTXxtk9K7hEWe"'), "output 0 full address tooltip missing");
  assert.ok(html.includes('aria-label="Output 1, 1B9N1re3RYdB7RPhsNS92vbYQegYWZW3og:'), "output 1 full address label missing");
  assert.ok(html.includes('data-txout-val="0" value="199900000"'), "output 0 amount field missing");
  assert.ok(html.includes('data-txout-val="1" value="9358"'), "output 1 amount field missing");
  // The middle summarizes the unsigned transaction; the fee is unknown here
  // because input 0 claims no amount.
  assert.ok(html.includes("PSBT v0"), "PSBT version missing");
  assert.ok(html.includes("version 2 · locktime 0"), "version/locktime missing");
  assert.ok(html.includes("unknown"), "unknown fee state missing");
  // Input amounts keep the unverified-claim disclaimer on the diagram itself.
  assert.ok(html.includes("not verified"), "claim disclaimer missing");
});

test("P2PKH outputs are tagged with their script template", () => {
  const html = psbtVizHtml(inspectValid(), "mainnet");
  assert.ok(html.includes("P2PKH"), "script template tag missing");
});

test("a malformed scriptPubKey falls back to the script display, never a zero-filled address", () => {
  // The old lenient hex parser turned invalid digits into zero bytes, so
  // "0014" + 20 garbage pairs decoded to the all-zero P2WPKH program and the
  // box posed as a real (fabricated) address. Strict decoding throws, the
  // address lookup returns null, and the box shows the raw script instead.
  const doc = syntheticDoc();
  doc.tx.outputs = [{ value: "1", scriptPubKey: "0014" + "zz".repeat(20), asm: "" }];
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(!html.includes("bc1q"), "malformed hex must not decode into an address");
  assert.ok(html.includes("0014zzzz"), "the raw script hex is shown instead");
});

test("OP_RETURN outputs get the data-carrier tag instead of an address", () => {
  const html = psbtVizHtml(syntheticDoc(), "mainnet");
  assert.ok(html.includes("OP_RETURN"), "OP_RETURN tag missing");
  assert.ok(!html.includes("psbted-viz-out"), "an OP_RETURN box must not pose as an address");
});

test("signing progress counts successfully decoded partial and taproot signatures (issue #328)", () => {
  // A pair name alone no longer counts: the typed decode must have succeeded,
  // and the key must have the shape that field requires (AR-09).
  const keyFor = (name) => ({
    PSBT_IN_PARTIAL_SIG: "02" + "02" + "11".repeat(32),
    PSBT_IN_TAP_KEY_SIG: "13",
    PSBT_IN_FINAL_SCRIPTWITNESS: "08",
    PSBT_IN_FINAL_SCRIPTSIG: "07",
  })[name] ?? "02";
  const pairs = (names) => names.map((name) => ({ key: keyFor(name), value: "", name, decoded: { signature: "ab" } }));
  const doc = syntheticDoc({
    inputs: [[], pairs(["PSBT_IN_PARTIAL_SIG", "PSBT_IN_PARTIAL_SIG"]), pairs(["PSBT_IN_TAP_KEY_SIG"]), pairs(["PSBT_IN_FINAL_SCRIPTWITNESS"])],
  });
  doc.tx.inputs = [0, 1, 2, 3].map((vout) => ({ txid: "11".repeat(32), vout, scriptSig: "", sequence: 0 }));
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(html.includes("unsigned"), "empty map must read unsigned");
  assert.ok(html.includes("2 signatures"), "partial signatures not counted");
  assert.ok(html.includes("1 signature"), "taproot key signature not counted");
  assert.ok(html.includes("finalized"), "final witness not reported");
});

test("malformed signing fields read as malformed, never as signed or finalized (issue #328)", () => {
  // Names survive failed decodes; the status must not. A field that fails its
  // typed decode is presence without validity. The keys here are well formed,
  // so only the decode failure can be responsible.
  const keyFor = (name) => (name === "PSBT_IN_PARTIAL_SIG" ? "02" + "02" + "11".repeat(32)
    : name === "PSBT_IN_TAP_SCRIPT_SIG" ? "14" + "22".repeat(32) + "33".repeat(32)
    : name === "PSBT_IN_FINAL_SCRIPTSIG" ? "07" : "02");
  const bad = (name) => ({ key: keyFor(name), value: "", name, decoded: null, decodeError: "truncated" });
  const doc = syntheticDoc({
    inputs: [
      [bad("PSBT_IN_PARTIAL_SIG")],
      [bad("PSBT_IN_FINAL_SCRIPTSIG")],
      // A good signature alongside a malformed one still counts the good one.
      [{ key: keyFor("PSBT_IN_PARTIAL_SIG"), value: "", name: "PSBT_IN_PARTIAL_SIG", decoded: { signature: "ab" } }, bad("PSBT_IN_TAP_SCRIPT_SIG")],
    ],
  });
  doc.tx.inputs = [0, 1, 2].map((vout) => ({ txid: "11".repeat(32), vout, scriptSig: "", sequence: 0 }));
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(!html.includes("finalized"), "malformed final scriptSig was labeled finalized");
  assert.ok(!html.includes("2 signatures"), "malformed signatures were counted");
  assert.equal(html.match(/malformed signing field/g).length, 2, "malformed fields not flagged");
  assert.ok(html.includes("1 signature"), "the one decodable signature should still count");
});

test("a keyed signing field with the wrong key shape is malformed, not progress (AR-09)", () => {
  // BIP-174 puts the signer's public key in a partial signature's keydata; a
  // keyless `02 01` record decodes to a signature but cannot identify a
  // signer, and a tap-script signature needs x-only key plus leaf hash.
  const decoded = { signature: "ab" };
  const pair = (name, key) => ({ key, value: "", name, decoded });
  const statusOf = (...pairs) => {
    const doc = syntheticDoc({ inputs: [pairs] });
    doc.tx.inputs = [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 0 }];
    const html = psbtVizHtml(doc, "mainnet");
    if (html.includes("malformed signing field")) return "malformed";
    if (html.includes("1 signature")) return "signed";
    return "unsigned";
  };
  assert.equal(statusOf(pair("PSBT_IN_PARTIAL_SIG", "02")), "malformed", "a keyless partial signature is malformed");
  assert.equal(statusOf(pair("PSBT_IN_PARTIAL_SIG", "02" + "02" + "11".repeat(32))), "signed", "a compressed-key partial signature counts");
  assert.equal(statusOf(pair("PSBT_IN_PARTIAL_SIG", "02" + "04" + "11".repeat(64))), "signed", "an uncompressed-key partial signature counts");
  assert.equal(statusOf(pair("PSBT_IN_TAP_SCRIPT_SIG", "14" + "22".repeat(32))), "malformed", "a tap-script signature without a leaf hash is malformed");
  assert.equal(statusOf(pair("PSBT_IN_TAP_SCRIPT_SIG", "14" + "22".repeat(32) + "33".repeat(32))), "signed", "a full tap-script key counts");
});

test("a taproot signature with an undefined sighash suffix does not read as signed (issue #333, diagram-side)", () => {
  // The unit-level fix is in test/psbt-wasm.test.mjs (tap_sig_json now
  // rejects a 65-byte Taproot signature whose trailing byte is not a defined
  // Taproot sighash type). This is the end-to-end case the diagram actually
  // cares about: the real WASM decode feeding real "decoded" pairs into
  // signingStatus(), the same path issue #328 hardened for a failed decode
  // in general. Before that decoder-level fix, an undefined sighash byte
  // still produced a `decoded` value with no `decodeError`, so this read as
  // "1 signature" here even though psbt-schnorr.js's own hodlLooksSchnorr
  // would have refused the exact same bytes.
  const unhex = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  const tx =
    "02000000" + "01" + "00".repeat(32) + "00000000" + "00" + "ffffffff" +
    "01" + "0000000000000000" + "00" + "00000000";
  const psbtBadSuffix =
    "70736274ff" + "0100" + (tx.length / 2).toString(16).padStart(2, "0") + tx + "00" +
    "01" + "13" + "41" + "5a".repeat(64) + "04" + // PSBT_IN_TAP_KEY_SIG, undefined 0x04 suffix
    "00" + "00";
  const doc = psbtInspectDoc(unhex(psbtBadSuffix));
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(!html.includes("1 signature"), "an undefined sighash suffix must not count as a signature");
  assert.ok(html.includes("malformed signing field"), "it should read as malformed instead");
});

test("every box is a link to its own section, and the diagram holds no selection", () => {
  const doc = inspectValid();
  const html = psbtVizHtml(doc, "mainnet");
  const box = (target) => html.match(new RegExp(`<button[^>]*data-viz="${target}"[^>]*>`))[0];
  // Each box names the section it jumps to; psbt-editor.js scrolls to the
  // element carrying the matching data-psbted-section.
  for (const target of ["input:0", "input:1", "output:0", "tx"]) {
    assert.ok(box(target).includes(`data-viz="${target}"`), `${target} box is not a link`);
  }
  // Nothing opens in place any more, so no box carries an expanded state.
  assert.ok(!html.includes("aria-expanded"), "a link must not claim to expand anything");
  assert.ok(!html.includes("is-open"), "no box keeps a selected state");
});

test("the connector layer ships empty: the browser draws the lines with layout", () => {
  const html = psbtVizHtml(inspectValid(), "mainnet");
  assert.ok(html.includes('<svg class="psbted-viz-svg"'), "connector layer missing");
  assert.ok(html.includes("aria-hidden"), "decorative layer must be hidden from assistive tech");
  assert.ok(!html.includes("<path"), "paths need layout; they must not be in the pure markup");
});

test("the transaction box is a button that links to the transaction fields", () => {
  const html = psbtVizHtml(inspectValid(), "mainnet");
  const txButton = html.match(/<button[^>]*data-viz="tx"[^>]*>/);
  assert.ok(txButton, "transaction box is not a button");
  assert.ok(/aria-label="Unsigned transaction: go to/.test(txButton[0]), "the tx box does not say where it goes");
});

test("fee states: known fee, negative fee, unknown fee", () => {
  const known = psbtVizHtml(syntheticDoc({ fee: { known: true, sats: 1412 } }), "mainnet");
  assert.ok(known.includes(`${sats("1412")} sats`), "known fee missing");
  const negative = psbtVizHtml(syntheticDoc({ fee: { known: true, sats: null } }), "mainnet");
  assert.ok(negative.includes("outputs exceed claimed inputs"), "negative fee missing");
  const unknown = psbtVizHtml(syntheticDoc({ fee: { known: false } }), "mainnet");
  assert.ok(unknown.includes("unknown"), "unknown fee missing");
  // The unknown state stays compact; the reason moves to the tooltip.
  assert.ok(!unknown.includes("unknown — an input carries no amount claim"), "long fee text still inline");
  assert.ok(unknown.includes('title="an input carries no amount claim"'), "fee reason not on hover");
});

test("invalid fee reasons and an unknown outputs total render from the document", () => {
  // The inspector marks fees invalid with a reason (issue #367): u64 overflow
  // or amounts past Bitcoin's MAX_MONEY. The diagram shows the reason.
  const overflow = psbtVizHtml(syntheticDoc({ fee: { known: true, sats: null, error: "amounts overflow u64" } }), "mainnet");
  assert.ok(overflow.includes("amounts overflow u64"), "overflow fee reason missing");
  const capped = psbtVizHtml(syntheticDoc({ fee: { known: true, sats: null, error: "amounts exceed Bitcoin's MAX_MONEY" } }), "mainnet");
  assert.ok(capped.includes("MAX_MONEY"), "MAX_MONEY fee reason missing");
  // An overflowing output total comes back null; the column hint must say so
  // instead of grouping "null".
  const noTotal = psbtVizHtml(syntheticDoc({ totalOut: null }), "mainnet");
  assert.ok(noTotal.includes("outputs total unknown"), "unknown outputs total missing");
  assert.ok(!noTotal.includes("null sats"), "null total must not render as an amount");
});

test("conflicting witness and non-witness claims render as a conflict, independent of map order (issue #324)", () => {
  const witness = { key: "01", value: "", name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "5000", scriptPubKey: "51" } };
  const nonWitness = { key: "00", value: "", name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "00".repeat(32), outputCount: 1, prevout: { vout: 1, value: "1000", scriptPubKey: "51" } } };
  for (const pairs of [[witness, nonWitness], [nonWitness, witness]]) {
    const html = psbtVizHtml(syntheticDoc({ inputs: [pairs] }), "mainnet");
    assert.ok(html.includes(`conflicting claims: ${sats("5000")} vs ${sats("1000")} sats`), "conflict warning missing");
  }
  // The fee line shows the document's conflict reason instead of "unknown".
  const conflicted = psbtVizHtml(syntheticDoc({
    inputs: [[witness, nonWitness]],
    fee: { known: false, error: "input(s) 0 declare conflicting witness and non-witness UTXO amounts" },
  }), "mainnet");
  assert.ok(conflicted.includes("conflicting witness and non-witness UTXO amounts"), "fee conflict reason missing");
  // Agreeing claims resolve normally to the (verified) non-witness claim.
  const agreed = psbtVizHtml(syntheticDoc({
    inputs: [[{ ...witness, decoded: { value: "1000", scriptPubKey: "51" } }, nonWitness]],
  }), "mainnet");
  assert.ok(agreed.includes(`${sats("1000")} sats`), "agreed claim amount missing");
  assert.ok(!agreed.includes("conflicting claims"), "agreement must not warn");
});

test("same-amount claims with different scripts still render as a conflict, in both map orders", () => {
  // The consensus layer (psbt-wasm verify.rs, utxo_claim_conflict) treats a
  // witness and non-witness claim as conflicting when the scriptPubKey
  // differs, even at the same amount, and the inspector's own input table
  // (app.js, audit C3-7) resolves agreement on amount AND script. The
  // diagram must not silently pick one claim's address when the scripts
  // disagree — that address is what a segwit signer's sighash basis would
  // contradict.
  const witness = { key: "01", value: "", name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "0014" + "aa".repeat(20) } };
  const nonWitness = { key: "00", value: "", name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "00".repeat(32), outputCount: 1, prevout: { vout: 1, value: "1000", scriptPubKey: "0014" + "bb".repeat(20) } } };
  const witnessAddress = addressFromScript(new Uint8Array(witness.decoded.scriptPubKey.match(/../g).map((b) => parseInt(b, 16))), "mainnet");
  assert.ok(witnessAddress, "expected an address for the witness claim's script");
  for (const pairs of [[witness, nonWitness], [nonWitness, witness]]) {
    const html = psbtVizHtml(syntheticDoc({ inputs: [pairs] }), "mainnet");
    assert.ok(html.includes("conflicting claims"), "conflict warning missing for equal-amount/different-script claims");
    assert.ok(!html.includes(`conflicting claims: ${sats("1000")} vs ${sats("1000")} sats`), "equal amounts must not render as an amount-vs-amount conflict");
    assert.ok(!html.includes(witnessAddress), "the witness claim's address must not be picked silently");
  }
});

test("exotic witness programs render as bech32m addresses, matching the inspector (issue #354)", () => {
  // The diagram and the inspector share one renderer (rust-bitcoin via
  // addressFromScript), so scripts that used to fall back to hex here —
  // v1 programs ≠ 32 bytes, v2–v16 programs — show their address instead.
  const programs = [
    "51024e73", // BIP-433 P2A: the one exotic case that always worked
    "5120" + "02".padStart(64, "0"), // v1, off-curve x-only key (x=2 has no curve point)
    "5110" + "22".repeat(16), // v1, 16-byte program
    "5202" + "3333", // v2, 2-byte program
    "5220" + "44".repeat(32), // v2, 32-byte program
  ];
  const doc = syntheticDoc();
  doc.tx.outputs = programs.map((scriptPubKey) => ({ value: "1", scriptPubKey, asm: "" }));
  doc.outputs = programs.map(() => []);
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(html.includes("bc1pfeessrawgf"), "P2A address missing");
  for (const program of programs) {
    const address = addressFromScript(new Uint8Array(program.match(/../g).map((b) => parseInt(b, 16))), "mainnet");
    assert.ok(address, `expected an address for ${program}`);
    assert.ok(html.includes(address), `${address} not rendered for ${program}`);
  }
});

test("column hint lines carry the totals, unless a claim is missing", () => {
  const html = psbtVizHtml(syntheticDoc({ totalIn: 250000 }), "mainnet");
  assert.ok(html.includes(`${sats("250000")} sats claimed, not verified`), "inputs total missing");
  assert.ok(html.includes(`${sats("5000")} sats in total`), "outputs total missing");
  // The vector's first input claims nothing, so the inputs side cannot total.
  const partial = psbtVizHtml(inspectValid(), "mainnet");
  assert.ok(!partial.includes("sats claimed"), "a partial claim set must not total");
  assert.ok(partial.includes("not verified"), "claim disclaimer missing");
});

test("an input's prevout is stated once per box, in full on hover", () => {
  const html = psbtVizHtml(inspectValid(), "mainnet");
  // Input 0 has no claim: the truncated txid:vout is the label; the sub-line
  // must not repeat it. Input 1 has an address label: its prevout is hover-only.
  // (The inspection document reports txids in display order.)
  const txid = "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab";
  const firstBox = html.match(/<div class="psbted-viz-box">[\s\S]*?<\/div>/)[0];
  const subLine = firstBox.match(/<p class="psbted-viz-sub"[\s\S]*?<\/p>/)[0];
  assert.ok(!subLine.includes("e47b5b7a…4909ab"), "prevout repeated in the sub-line");
  assert.ok(subLine.includes(`title="spends ${txid}:0"`), "full prevout not on hover");
  assert.ok(!html.includes("e47b5b7a…4909ab:1"), "claimed input's prevout leaked off its label");
});

test("non-witness UTXO claims show the spent prevout's amount and address", () => {
  const doc = syntheticDoc({
    inputs: [[{
      key: "00",
      value: "",
      name: "PSBT_IN_NON_WITNESS_UTXO",
      decoded: { txid: "22".repeat(32), outputCount: 1, prevout: { vout: 1, value: 42000, scriptPubKey: "0014" + "11".repeat(20) } },
    }]],
  });
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(html.includes(`${sats("42000")} sats`), "non-witness claim amount missing");
  assert.ok(html.includes("bc1q"), "non-witness claim address missing");
  assert.ok(html.includes("P2WPKH"), "witness script template not tagged");
});

test("markup from hostile document strings stays inert", () => {
  const hostile = '"><img src=x onerror=alert(1)>';
  const doc = syntheticDoc({
    tx: {
      version: 2,
      locktime: 0,
      inputs: [{ txid: hostile, vout: 0, scriptSig: "", sequence: 0 }],
      outputs: [{ value: 1, scriptPubKey: hostile, asm: hostile }],
    },
  });
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(!html.includes("<img"), "unescaped markup in the diagram");
  assert.ok(html.includes("&lt;img"), "hostile text was not escaped");
});

test("an empty transaction renders explicit empty states", () => {
  const doc = syntheticDoc({ tx: { version: 2, locktime: 0, inputs: [], outputs: [] }, inputs: [], outputs: [] });
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(html.includes("No inputs."), "empty inputs state missing");
  assert.ok(html.includes("No outputs."), "empty outputs state missing");
});

test("the testnet network renders testnet addresses", () => {
  const mainnet = psbtVizHtml(inspectValid(), "mainnet");
  const testnet = psbtVizHtml(inspectValid(), "testnet");
  assert.ok(mainnet.includes("1BonMcawnm"), "mainnet address missing");
  assert.ok(!testnet.includes("1BonMcawnm"), "testnet render kept the mainnet address");
});

// Witness programs the consensus rules leave undefined (BIP141, BIP341,
// BIP350; P2A from BIP-433). Contract: an output the rules define (v0 with a
// 20- or 32-byte program, v1 with a 32-byte one) or that is not a witness
// program at all gets no note. v2-v16, and v1 at any other length, warn that
// anyone can spend the output until a soft fork defines it (drafts such as
// BIP460 propose v2). v1 <4e73> is pay-to-anchor, anyone-can-spend by design.
// v0 at any other length can never be spent, and neither can a v1-v16 program
// whose bytes are zero-valued (all zeros, or negative zero): Bitcoin Core's
// VerifyScript fails a false top stack item (CastToBool) before it looks at
// the witness program. Notes never block export: BIP350 says wallets must be
// able to pay future versions.
const program = (version, bytes) => `${version === 0 ? "00" : (0x50 + version).toString(16)}${bytes.toString(16).padStart(2, "0")}${"ab".repeat(bytes)}`;

test("witness programs the consensus rules leave undefined are classified, and defined ones are not", () => {
  const { witnessProgramNote } = vizModule;
  assert.equal(typeof witnessProgramNote, "function");
  const notWitnessOrDefined = [
    program(0, 20), program(0, 32), program(1, 32), // P2WPKH, P2WSH, P2TR
    `76a914${"11".repeat(20)}88ac`, `a914${"11".repeat(20)}87`, "6a046f726469", // P2PKH, P2SH, OP_RETURN
    "", "00", "0001ff", // empty, OP_0 alone, a 1-byte push (programs are 2-40 bytes)
    program(2, 41), // a 41-byte push is not a witness program
    `5220${"ab".repeat(31)}`, // the push length disagrees with the bytes
  ];
  for (const script of notWitnessOrDefined) assert.equal(witnessProgramNote(script), null, script);

  const v2 = witnessProgramNote(program(2, 32));
  assert.equal(v2.label, "SegWit v2 (not active)");
  assert.equal(v2.tone, "warn");
  assert.equal(v2.note(1), "Output #1 pays to SegWit v2, which no active soft fork defines. Until one does, anyone can spend it.");
  assert.equal(witnessProgramNote(program(16, 2)).label, "SegWit v16 (not active)");
  assert.equal(witnessProgramNote(program(2, 40)).label, "SegWit v2 (not active)");
  assert.equal(witnessProgramNote(program(2, 32).toUpperCase())?.label, "SegWit v2 (not active)", "hex case does not matter");

  const odd = witnessProgramNote(program(1, 20));
  assert.equal(odd.label, "SegWit v1, 20-byte (undefined)");
  assert.equal(odd.tone, "warn");
  assert.equal(odd.note(2), "Output #2 pays to a 20-byte SegWit v1 program, which Taproot does not define. Until a soft fork does, anyone can spend it.");
  assert.equal(witnessProgramNote("51024e74").label, "SegWit v1, 2-byte (undefined)", "only 4e73 is P2A");

  const anchor = witnessProgramNote("51024e73");
  assert.equal(anchor.label, "P2A (anchor)");
  assert.equal(anchor.tone, "info");
  assert.equal(anchor.note(3), "Output #3 is a pay-to-anchor (P2A): anyone can spend it, by design, to bump the fee.");

  const burned = witnessProgramNote(program(0, 25));
  assert.equal(burned.label, "SegWit v0, 25-byte (unspendable)");
  assert.equal(burned.tone, "bad");
  assert.equal(burned.note(4), "Output #4 is a 25-byte SegWit v0 program: no one can ever spend it.");
});

test("a zero-valued v1-v16 witness program is unspendable, not anyone-can-spend", () => {
  // Bitcoin Core (interpreter.cpp): VerifyScript returns SCRIPT_ERR_EVAL_FALSE
  // when CastToBool(stack.back()) is false, before the witness-program branch.
  // CastToBool is false for all-zero bytes and for zeros ending in 0x80
  // (negative zero), so these outputs burn their coins (BIP141 footnote 2).
  const { witnessProgramNote } = vizModule;
  for (const [script, version, bytes] of [
    ["51020000", 1, 2], ["51020080", 1, 2], ["52020000", 2, 2], ["60020080", 16, 2],
    [`5228${"00".repeat(40)}`, 2, 40], [`5314${"00".repeat(19)}80`, 3, 20], [`5114${"00".repeat(20)}`, 1, 20],
  ]) {
    const found = witnessProgramNote(script);
    assert.equal(found?.label, `SegWit v${version}, ${bytes}-byte (unspendable)`, script);
    assert.equal(found.tone, "bad", script);
    assert.equal(found.note(5), `Output #5 pays to a zero-valued SegWit v${version} program, which the script check reads as false: no one can ever spend it.`, script);
  }
  // One nonzero byte anywhere but a trailing 0x80 makes the program true: still undefined.
  for (const script of ["52020001", "52028000", "52020100", "51020001", "52020180"]) {
    assert.equal(witnessProgramNote(script)?.tone, "warn", script);
  }
});

test("the diagram labels undefined witness programs instead of a bare 'script'", () => {
  const scripts = [program(2, 32), program(1, 20), "51024e73", program(0, 25)];
  const doc = syntheticDoc();
  doc.tx.outputs = scripts.map((scriptPubKey) => ({ value: "1", scriptPubKey, asm: "" }));
  doc.outputs = scripts.map(() => []);
  const html = psbtVizHtml(doc, "mainnet");
  for (const label of ["SegWit v2 (not active)", "SegWit v1, 20-byte (undefined)", "P2A (anchor)", "SegWit v0, 25-byte (unspendable)"]) {
    assert.ok(html.includes(label), `${label} missing from the diagram`);
  }
});

test("the editor summary carries one note per undefined witness output, and none otherwise", () => {
  const { psbtOutputNotesHtml } = vizModule;
  assert.equal(typeof psbtOutputNotesHtml, "function");
  assert.equal(psbtOutputNotesHtml(inspectValid()), "", "P2PKH outputs get no note");
  const doc = syntheticDoc();
  doc.tx.outputs = [program(0, 20), program(2, 32), "51024e73", program(0, 25)].map((scriptPubKey) => ({ value: "1", scriptPubKey, asm: "" }));
  const html = psbtOutputNotesHtml(doc);
  assert.doesNotMatch(html, /Output #0/, "a defined P2WPKH output got a note");
  assert.match(html, /<span class="psbted-note-warn">⚠ Output #1 pays to SegWit v2, which no active soft fork defines\./);
  assert.match(html, /<span class="muted">Output #2 is a pay-to-anchor \(P2A\)/);
  assert.match(html, /<span class="psbted-note-bad">✕ Output #3 is a 25-byte SegWit v0 program: no one can ever spend it\.<\/span>/);
});

// Red-team F7: a crafted PSBT passes the 5 MB / 100k-element load gates with
// more inputs and outputs than the DOM survives. The diagram (and every PSBT
// view through the shared PSBT_RENDER_LIMIT) renders at most 500 boxes per
// side and notes the elided count, while totals, the fee and every warning
// still cover the full document. The PSBTs are hand-assembled here: inputs
// claiming a 2,000-sat P2WPKH witness UTXO each, outputs of 1,000 sats — so
// for 1,200 in / 700 out the inspector computes totalIn 2,400,000, totalOut
// 700,000 and fee 1,700,000 sats over every element, cap or no cap.
const craftedPsbt = (inputCount, outputCount) => {
  const le32 = (n) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
  const le64 = (n) => [...le32(n), 0, 0, 0, 0];
  const varint = (n) => (n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 0xff, (n >> 8) & 0xff] : [0xfe, ...le32(n)]);
  const script = [0x00, 0x14, ...new Array(20).fill(0x22)]; // P2WPKH
  const tx = [
    ...le32(2),
    ...varint(inputCount),
    ...Array.from({ length: inputCount }, (_, i) => [...new Array(32).fill(0x11), ...le32(i), 0x00, 0xff, 0xff, 0xff, 0xff]).flat(),
    ...varint(outputCount),
    ...Array.from({ length: outputCount }, () => [...le64(1000), script.length, ...script]).flat(),
    ...le32(0),
  ];
  const witnessUtxo = [...le64(2000), script.length, ...script];
  return new Uint8Array([
    0x70, 0x73, 0x62, 0x74, 0xff, // "psbt\xff"
    0x01, 0x00, ...varint(tx.length), ...tx, 0x00, // the global unsigned-transaction pair
    ...Array.from({ length: inputCount }, () => [0x01, 0x01, witnessUtxo.length, ...witnessUtxo, 0x00]).flat(), // one witness-UTXO pair per input map
    ...new Array(outputCount).fill(0x00), // one empty map per output
  ]);
};

test("an oversize PSBT renders only 500 boxes per side, notes the elided counts, and keeps full-document totals (F7)", () => {
  const doc = psbtInspectDoc(craftedPsbt(1200, 700));
  assert.equal(doc.tx.inputs.length, 1200);
  assert.equal(doc.tx.outputs.length, 700);
  const html = psbtVizHtml(doc, "mainnet");
  assert.equal(html.match(/data-viz="input:/g).length, 500, "input boxes capped at 500");
  assert.equal(html.match(/data-viz="output:/g).length, 500, "output boxes capped at 500");
  assert.ok(html.includes('data-viz="input:499"'), "input #499 is rendered");
  assert.ok(!html.includes('data-viz="input:500"'), "input #500 is not rendered");
  assert.ok(html.includes('data-viz="output:499"'), "output #499 is rendered");
  assert.ok(!html.includes('data-viz="output:500"'), "output #500 is not rendered");
  // One elision line per column, in the same element and class the editor
  // uses for its truncated-problems note.
  assert.ok(html.includes('<p class="psbted-note-warn">700 more inputs not shown, still included in this transaction.</p>'), "inputs elision line");
  assert.ok(html.includes('<p class="psbted-note-warn">200 more outputs not shown, still included in this transaction.</p>'), "outputs elision line");
  // Headings, totals and the fee still cover all 1,200 inputs and 700 outputs.
  assert.match(html, /Inputs[\s\S]{0,40}\(1200\)/);
  assert.match(html, /Outputs[\s\S]{0,40}\(700\)/);
  assert.ok(html.includes(`${sats("2400000")} sats claimed, not verified`), "inputs total covers every input");
  assert.ok(html.includes(`${sats("700000")} sats in total`), "outputs total covers every output");
  assert.ok(html.includes(`${sats("1700000")} sats</span>`), "fee covers the full document");
});

test("a PSBT under the render cap renders every box and no elision line", () => {
  const doc = psbtInspectDoc(craftedPsbt(3, 2));
  const html = psbtVizHtml(doc, "mainnet");
  assert.equal(html.match(/data-viz="input:/g).length, 3, "every input rendered");
  assert.equal(html.match(/data-viz="output:/g).length, 2, "every output rendered");
  assert.ok(!html.includes("(not rendered)"), "no elision line under the cap");
  assert.ok(html.includes(`${sats("4000")} sats</span>`), "fee 6,000 in − 2,000 out");
});

// --- F7 round 2: the PSBT inspector (hodlRenderPsbt in app.js) ------------
// app.js is the browser monolith: it exports nothing, so hodlRenderPsbt is
// extracted from its source and evaluated with stubs for the helpers it
// closes over. The extractor skips strings and comments, so the braces in
// literals like "…and {n} more." do not fool the brace matcher.
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const extractAppFunction = (name) => {
  const source = readFileSync(join(repoRoot, "src/js/app.js"), "utf8");
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} not found in app.js`);
  let depth = 0, state = "code", quote = "";
  for (let i = start; i < source.length; i++) {
    const char = source[i], next = source[i + 1];
    if (state === "line") { if (char === "\n") state = "code"; continue; }
    if (state === "block") { if (char === "*" && next === "/") { state = "code"; i++; } continue; }
    if (state === "string") { if (char === "\\") i++; else if (char === quote) state = "code"; continue; }
    if (char === "/" && next === "/") { state = "line"; i++; continue; }
    if (char === "/" && next === "*") { state = "block"; i++; continue; }
    if (char === "'" || char === '"' || char === "`") { state = "string"; quote = char; continue; }
    if (char === "{") depth++;
    else if (char === "}" && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
};

// The stubs are the inspector's own contracts: hodlWitUtxo reads an input's
// witness-UTXO claim, hodlSighashPolicy its declared sighash type,
// hodlRenderOutputHtml builds one output block. The crafted document gives
// every input a 2,000-sat claim and every output 1,000 sats, so the fee over
// ALL elements is arithmetic the test owns: 1,200 in / 700 out → 1,700,000
// sats (0.017 BTC); 3 in / 2 out → 4,000 sats.
const hodlRenderPsbtForTest = (overrides = {}) => {
  const captured = {};
  const stubs = {
    PSBT_RENDER_LIMIT: vizModule.PSBT_RENDER_LIMIT,
    // The real helper once it exists; the passthrough keeps the harness
    // runnable on the pre-fix source, so the count assertions below fail on
    // the claimed reason (uncapped rendering), not on a missing export.
    cappedHtml: vizModule.cappedHtml ?? ((items, renderOne) => items.map(renderOne).join("")),
    // Same passthrough pattern for the view render budget: an infinite
    // budget before the fix, the real one after.
    renderBudget: vizModule.renderBudget ?? (() => ({ take: (count = 1) => count, get left() { return Infinity; }, get spent() { return false; } })),
    hodlInspectorNetwork: () => "mainnet",
    inspectPsbtInscriptions: (psbt) => psbt.stubInscriptions || { inputs: [], envelopes: [] },
    describeEnvelope: (envelope) => [`envelope ${envelope.envelopeIndex}`],
    hodlPsbtReferenceVerdict: () => ({ state: "complete", problems: [], unlisted: 0 }),
    hodlT: (text, vars) => String(text).replace(/\{(\w+)\}/g, (match, key) => (vars && key in vars ? vars[key] : match)),
    hodlTText: (text) => text,
    hodlEscapeHtml: (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"),
    hodlSessionOwnership: () => new Map(),
    hodlRenderOutputHtml: (output, index) => `<p class='psbt-kv'><strong>Output ${index}</strong></p>`,
    hodlOwnershipWarning: () => "",
    hodlWitUtxo: (entries) => {
      const claim = entries.find((entry) => entry.type === 0x01);
      return claim ? { amount: claim.amount, script: claim.script } : null;
    },
    hodlNonWitUtxo: () => null,
    hodlEq: () => false,
    hodlSighashPolicy: (entries) => {
      const declared = entries.find((entry) => entry.type === 0x03);
      return declared ? declared.sighash : null;
    },
    hodlSighashLabel: (sighash) => ({ 1: "SIGHASH_ALL", 2: "SIGHASH_NONE", 3: "SIGHASH_SINGLE" }[sighash] ?? `SIGHASH_${sighash}`),
    hodlPartialSigs: (entries) => entries.filter((entry) => entry.type === 0x02).map((entry) => ({ der: entry.der, pubkey: entry.pubkey, sighash: 1, raw: entry.der })),
    hodlSigParts: () => null,
    hodlDerRLoose: () => new Uint8Array(32).fill(7),
    hodlInputScriptCode: () => null,
    hodlSighashProblems: () => [],
    hodlPrivForPub: () => null,
    hodlPrivFromPath: () => null,
    hodlHex: { encode: (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("") },
    hodlCompressedPubkey: (pubkey) => pubkey,
    hodlPsbtMasterFingerprint: () => null,
    hodlPsbtDerivationFingerprints: () => null,
    hodlPsbtHd: null,
    hodlParseAntiExfil: () => null,
    hodlPsbtRecordNonceInspection: () => {},
    hodlTapSigsParsed: () => [],
    hodlFinalized: () => false,
    hodlAddr: () => "bc1qstub",
    hodlPublicInlineHtml: (value) => value,
    hodlHexRev: (txid) => txid,
    hodlSats: (sats) => (Number(sats) / 100000000).toFixed(8),
    // The Taproot nonce check (#1051) is covered by its own suites; these
    // render-cap tests only need it inert.
    hodlFind: (entries, type) => entries.filter((entry) => entry.type === type),
    hodlEq: (a, b) => a.length === b.length && a.every((byte, at) => byte === b[at]),
    hodlCompareSchnorrNonces: () => ({ reused: [], incomplete: 0 }),
    hodlSchnorrReuseHtml: () => "",
    hodlFinalTapKeySig: () => null,
    hodlFinalTapScriptSigs: () => null,
    hodlFinalIsTaproot: () => false,
    isP2tr: () => false,
    hodlCompareNonces: () => ({ reused: [], possible: [], crossKey: [] }),
    hodlPsbtNonceCheck: () => ({ label: "ECDSA nonce reuse", state: "complete", detail: "" }),
    hodlPsbtAnalysisSummary: (checks) => {
      captured.checks = checks;
      return "";
    },
  };
  Object.assign(stubs, overrides);
  const names = Object.keys(stubs);
  const render = new Function(...names, `${extractAppFunction("hodlRenderPsbt")}; return hodlRenderPsbt;`)(...names.map((name) => stubs[name]));
  return { render, captured };
};

const inspectorDoc = (inputCount, outputCount, sighashAt = -1) => {
  const script = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x22)]); // P2WPKH
  return {
    tx: {
      version: 2,
      locktime: 0,
      inputs: Array.from({ length: inputCount }, (_, vout) => ({ txid: "11".repeat(32), vout, script: new Uint8Array(), sequence: 0xffffffff })),
      outputs: Array.from({ length: outputCount }, () => ({ amount: 1000n, script })),
    },
    inputs: Array.from({ length: inputCount }, (_, index) => [
      { type: 0x01, amount: 2000n, script },
      ...(index === sighashAt ? [{ type: 0x03, sighash: 3 }] : []),
    ]),
    outputs: Array.from({ length: outputCount }, () => []),
  };
};

test("a 1,200-input PSBT renders 500 input sections in the inspector, notes the elided counts, and still warns from input 900 (F7)", () => {
  const { render, captured } = hodlRenderPsbtForTest();
  const html = render(inspectorDoc(1200, 700, 900), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  assert.equal(html.match(/<strong>Input \d+<\/strong>/g)?.length ?? 0, 500, "input sections capped at 500");
  assert.equal(html.match(/<strong>Output \d+<\/strong>/g)?.length ?? 0, 500, "output blocks capped at 500");
  assert.ok(html.includes("<strong>Input 499</strong>"), "input #499 is rendered");
  assert.ok(!html.includes("<strong>Input 500</strong>"), "input #500 is not rendered");
  assert.ok(html.includes("<strong>Output 499</strong>"), "output #499 is rendered");
  assert.ok(!html.includes("<strong>Output 500</strong>"), "output #500 is not rendered");
  // One elision line per list, in the same element and class hodlRenderRawTx
  // uses, with the count as a plain integer.
  assert.ok(html.includes("<p class='psbt-warn'>700 more inputs not shown, still included in this transaction.</p>"), "inputs elision line");
  assert.ok(html.includes("<p class='psbt-warn'>200 more outputs not shown, still included in this transaction.</p>"), "outputs elision line");
  // The analysis still covers every element: input 900's declared
  // SIGHASH_SINGLE is a policy problem even though its section is elided…
  assert.ok(html.includes("input 900 requests SIGHASH_SINGLE"), "warning from elided input 900 still appears");
  assert.equal(captured.checks.find((check) => check.label === "SIGHASH policy").state, "problem", "the summary's policy check saw input 900");
  // …and the fee is computed over all 1,200 claims and 700 outputs:
  // 1,200 × 2,000 − 700 × 1,000 = 1,700,000 sats.
  assert.ok(html.includes("0.01700000 BTC"), "fee covers every input and output");
});

test("the inspector under the render cap renders every section and no elision line", () => {
  const { render } = hodlRenderPsbtForTest();
  const html = render(inspectorDoc(3, 2), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  assert.equal(html.match(/<strong>Input \d+<\/strong>/g)?.length ?? 0, 3, "every input rendered");
  assert.equal(html.match(/<strong>Output \d+<\/strong>/g)?.length ?? 0, 2, "every output rendered");
  assert.ok(!html.includes("(not rendered)"), "no elision line under the cap");
  assert.ok(html.includes("0.00004000 BTC"), "fee 3 × 2,000 − 2 × 1,000 = 4,000 sats");
});

test("app.js shares the one PSBT_RENDER_LIMIT and cappedHtml with the PSBT views (no local duplicate)", () => {
  const source = readFileSync(join(repoRoot, "src/js/app.js"), "utf8");
  assert.match(source, /import \{ PSBT_INSPECTOR_LIMIT, PSBT_RENDER_LIMIT, cappedHtml, renderBudget \} from "\.\/psbt-viz\.js";/, "imported from psbt-viz.js");
  assert.doesNotMatch(source, /const PSBT_RENDER_LIMIT =/, "no duplicated local constant");
});

// --- F7 round 3: the per-element findings that bypassed the render cap -----
// Round 2 capped the per-element sections, but the per-element findings in
// the same loops — one warning paragraph per input, one nonce row and one
// r-value line per signature, one editor note per output, one compare row or
// section per change, one editor table row per pair — still rendered
// unboundedly, so a crafted PSBT that passes the 5 MB / 100k-element load
// gates still hung the tab. Each path below now renders at most
// PSBT_RENDER_LIMIT elements plus one elision line, while every analysis,
// count and verdict still covers all elements. The elided counts are
// arithmetic the test owns: 1,200 − 500 = 700 and 700 − 500 = 200.

test("cappedHtml renders every item under the cap, and caps with one elision line over it", () => {
  const { cappedHtml, PSBT_RENDER_LIMIT } = vizModule;
  assert.equal(typeof cappedHtml, "function");
  const renderOne = (item) => `<i>${item}</i>`;
  assert.equal(cappedHtml([0, 1, 2], renderOne, "rows"), "<i>0</i><i>1</i><i>2</i>", "under the cap every item renders and no elision line is added");
  const items = Array.from({ length: PSBT_RENDER_LIMIT + 700 }, (_, index) => index);
  const capped = cappedHtml(items, renderOne, "rows");
  assert.equal((capped.match(/<i>/g) || []).length, PSBT_RENDER_LIMIT, "rendered items capped");
  assert.ok(capped.includes(`<i>${PSBT_RENDER_LIMIT - 1}</i>`), "the last item under the cap renders");
  assert.ok(!capped.includes(`<i>${PSBT_RENDER_LIMIT}</i>`), "the first item past the cap does not render");
  assert.ok(capped.includes("700 more rows"), "the elided count appears");
  // app.js passes the elision line through hodlT; the helper takes it as a callback.
  assert.ok(cappedHtml(items, renderOne, "rows", (n) => `translated ${n}`).includes("translated 700"), "the caller-supplied line is used");
});

test("per-input policy warnings render inline within the cap and are collected and capped past it, with the analysis covering every input (F7)", () => {
  const { render, captured } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(1200, 1);
  // Every input declares SIGHASH_SINGLE: one policy warning per input.
  doc.inputs.forEach((map) => map.push({ type: 0x03, sighash: 3 }));
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  // The first 500 inputs render their warning directly under their own
  // section (rock's placement); the 700 over-cap inputs' warnings are
  // collected and rendered capped at 500 after the loop: 500 + 500 in all.
  assert.equal((html.match(/<p class='psbt-bad'>/g) || []).length, 1000, "500 inline + 500 collected warning paragraphs");
  assert.ok(html.includes("200 more warnings"), "the collected list notes its elided count");
  const input0 = html.indexOf("<strong>Input 0</strong>");
  const warning0 = html.indexOf("input 0 requests SIGHASH_SINGLE");
  const input1 = html.indexOf("<strong>Input 1</strong>");
  assert.ok(input0 !== -1 && warning0 !== -1 && input1 !== -1, "the section and its warning both render");
  assert.ok(input0 < warning0 && warning0 < input1, "an in-cap input's warning sits under its own section");
  assert.equal(captured.checks.find((check) => check.label === "SIGHASH policy").state, "problem", "the policy check still covers all 1,200 inputs");
  assert.ok(html.includes("0.02399000 BTC"), "fee covers every input: 1,200 × 2,000 − 1,000 sats");
});

test("nonce analysis rows and r-value lines are capped at 500 with the elided counts (F7)", () => {
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(1200, 1);
  const pubkey = new Uint8Array(33).fill(2);
  doc.inputs.forEach((map) => map.push({ type: 0x02, pubkey, der: new Uint8Array(72).fill(0x30) }));
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "nonce", { network: "mainnet", transcript: "", record: false });
  assert.equal((html.match(/<strong>Input \d+<\/strong>/g) || []).length, 500, "nonce rows capped at 500");
  assert.equal((html.match(/\(input \d+\)/g) || []).length, 500, "r-value lines capped at 500");
  assert.equal((html.match(/700 more rows/g) || []).length, 2, "the r-value list and the nonce rows each note the elided count");
});

test("the editor summary's per-output notes are capped at 500 with the elided count (F7)", () => {
  const doc = syntheticDoc();
  doc.tx.outputs = Array.from({ length: 700 }, () => ({ value: "1", scriptPubKey: program(2, 32), asm: "" }));
  const html = vizModule.psbtOutputNotesHtml(doc);
  assert.equal((html.match(/Output #\d+/g) || []).length, 500, "notes capped at 500");
  assert.ok(html.includes("200 more notes"), "the elided count appears");
});

// hodlRenderRawTx is extracted like hodlRenderPsbt above; the stubs are the
// raw-transaction inspector's own contracts (one extracted signature and one
// inscription hint per flagged input).
const hodlRenderRawTxForTest = () => {
  const stubs = {
    PSBT_RENDER_LIMIT: vizModule.PSBT_RENDER_LIMIT,
    cappedHtml: vizModule.cappedHtml ?? ((items, renderOne) => items.map(renderOne).join("")),
    hodlInspectorNetwork: () => "mainnet",
    hodlT: (text, vars) => String(text).replace(/\{(\w+)\}/g, (match, key) => (vars && key in vars ? vars[key] : match)),
    hodlEscapeHtml: (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"),
    hodlSessionOwnership: () => new Map(),
    hodlRenderOutputHtml: (output, index) => `<p class='psbt-kv'><strong>Output ${index}</strong></p>`,
    hodlOwnershipWarning: () => "",
    hodlHexRev: (txid) => txid,
    extractEcdsaSignatures: (tx) => tx.inputs.flatMap((input, index) => (input.signature ? [{ input: index, der: input.signature, pubkey: input.pubkey }] : [])),
    inscriptionHints: (tx) => tx.inputs.flatMap((input, index) => (input.envelope ? [{ input: index, scriptBytes: input.envelope }] : [])),
    hodlSigParts: () => null,
    hodlDerRLoose: () => new Uint8Array(32).fill(7),
    hodlHex: { encode: (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("") },
    hodlCompressedPubkey: (pubkey) => pubkey,
    // The Taproot nonce check (#1051) is covered by its own suites; these
    // render-cap tests only need it inert.
    hodlFind: (entries, type) => entries.filter((entry) => entry.type === type),
    hodlEq: (a, b) => a.length === b.length && a.every((byte, at) => byte === b[at]),
    hodlCompareSchnorrNonces: () => ({ reused: [], incomplete: 0 }),
    hodlSchnorrReuseHtml: () => "",
    hodlTapScriptPathSigs: () => null,
    hodlTapWitnessShape: () => null,
    hodlCompareNonces: () => ({ reused: [], possible: [], crossKey: [] }),
    hodlPsbtRecordNonceInspection: () => {},
  };
  const names = Object.keys(stubs);
  const render = new Function(...names, `${extractAppFunction("hodlRenderRawTx")}; return hodlRenderRawTx;`)(...names.map((name) => stubs[name]));
  return { render };
};

const rawTxDoc = (inputCount, { signed = false, envelopes = false } = {}) => ({
  version: 2,
  locktime: 0,
  segwit: false,
  inputs: Array.from({ length: inputCount }, (_, vout) => ({
    txid: "11".repeat(32),
    vout,
    sequence: 0xffffffff,
    ...(signed ? { signature: new Uint8Array(72).fill(0x30), pubkey: new Uint8Array(33).fill(2) } : {}),
    ...(envelopes ? { envelope: 12 } : {}),
  })),
  outputs: [{ amount: 1000n, script: new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x22)]) }],
});

test("the raw-transaction inspector caps inscription hints and r-value lines at 500 with the elided counts (F7)", () => {
  const { render } = hodlRenderRawTxForTest();
  const html = render(rawTxDoc(1200, { signed: true, envelopes: true }), new Uint8Array(), "2024-01-01T00:00:00Z", "all", { network: "mainnet", record: false });
  assert.equal((html.match(/<strong>Input \d+<\/strong>/g) || []).length, 500, "input sections capped at 500");
  assert.equal((html.match(/Inscription envelope/g) || []).length, 500, "inscription hints capped at 500");
  assert.ok(html.includes("700 more warnings"), "the hints' elided count appears");
  assert.equal((html.match(/\(input \d+\)/g) || []).length, 500, "r-value lines capped at 500");
  assert.ok(html.includes("700 more rows"), "the r-values' elided count appears");
});

test("a small raw transaction renders every hint and r-value line with no elision line", () => {
  const { render } = hodlRenderRawTxForTest();
  const html = render(rawTxDoc(2, { signed: true, envelopes: true }), new Uint8Array(), "2024-01-01T00:00:00Z", "all", { network: "mainnet", record: false });
  assert.equal((html.match(/Inscription envelope/g) || []).length, 2, "every hint rendered");
  assert.equal((html.match(/\(input \d+\)/g) || []).length, 2, "every r-value line rendered");
  assert.ok(!html.includes("(not rendered)"), "no elision line under the cap");
});

test("the compare view caps transaction-diff rows and notes the elided count, with the analysis covering every change (F7)", () => {
  const doc = (txid) => ({
    tx: {
      version: 2,
      locktime: 0,
      inputs: Array.from({ length: 1200 }, (_, vout) => ({ txid, vout, scriptSig: "", sequence: 0xffffffff })),
      outputs: [],
    },
    globals: [],
    inputs: Array.from({ length: 1200 }, () => []),
    outputs: [],
    fee: { known: false },
  });
  const before = doc("11".repeat(32)), after = doc("22".repeat(32));
  const diff = comparePsbtDocs(before, after);
  assert.equal(diff.changes.length, 1200, "every input's changed txid is analysed");
  const html = psbtDiffHtml(diff, before, after, "mainnet");
  assert.equal((html.match(/<tr><td/g) || []).length, 500, "diff rows capped at 500");
  assert.ok(html.includes("700 more changes"), "the elided count appears");
});

test("the compare view caps per-map sections and notes the elided count (F7)", () => {
  const doc = (value) => ({
    tx: {
      version: 2,
      locktime: 0,
      inputs: Array.from({ length: 1200 }, (_, vout) => ({ txid: "11".repeat(32), vout, scriptSig: "", sequence: 0xffffffff })),
      outputs: [],
    },
    globals: [],
    inputs: Array.from({ length: 1200 }, () => [{ key: "fc00", value, name: "PSBT_IN_PROPRIETARY", decoded: null }]),
    outputs: [],
    fee: { known: false },
  });
  const before = doc("aa"), after = doc("bb");
  const diff = comparePsbtDocs(before, after);
  assert.equal(diff.changes.length, 1200, "every input map's changed pair is analysed");
  const html = psbtDiffHtml(diff, before, after, "mainnet");
  assert.equal((html.match(/key-value map<\/h3>/g) || []).length, 500, "map sections capped at 500");
  assert.ok(html.includes("700 more changes"), "the elided count appears");
});

// pairRows is a closure inside initPsbtEditor, so it is extracted from
// psbt-editor.js source and evaluated with stubs — the same harness pattern
// as hodlRenderPsbt above. The extractor tracks template literals (including
// nested ${ … } expressions) so braces inside them are not counted.
const extractEditorConst = (name) => {
  const source = readFileSync(join(repoRoot, "src/js/psbt-editor.js"), "utf8");
  const start = source.indexOf(`const ${name} = `);
  assert.ok(start >= 0, `${name} not found in psbt-editor.js`);
  let depth = 0, state = "code", quote = "";
  const templateDepths = [];
  for (let i = start; i < source.length; i++) {
    const char = source[i], next = source[i + 1];
    if (state === "line") { if (char === "\n") state = "code"; continue; }
    if (state === "block") { if (char === "*" && next === "/") { state = "code"; i++; } continue; }
    if (state === "string") {
      if (char === "\\") { i++; continue; }
      if (char === quote) { state = "code"; continue; }
      if (quote === "`" && char === "$" && next === "{") { templateDepths.push(depth); depth++; state = "code"; i++; }
      continue;
    }
    if (char === "/" && next === "/") { state = "line"; i++; continue; }
    if (char === "/" && next === "*") { state = "block"; i++; continue; }
    if (char === "'" || char === '"' || char === "`") { state = "string"; quote = char; continue; }
    if (char === "{") { depth++; continue; }
    if (char === "}") {
      depth--;
      if (templateDepths.length && depth === templateDepths[templateDepths.length - 1]) {
        templateDepths.pop();
        state = "string";
        quote = "`";
      } else if (depth === 0) {
        let end = i + 1;
        while (source[end] === " " || source[end] === "\n") end++;
        if (source[end] === ";") end++;
        return source.slice(start, end);
      }
    }
  }
  throw new Error(`unbalanced braces in ${name}`);
};

// extractEditorConst with a passthrough for a const the fix adds: null when
// the source has no such const, so the harness can substitute a no-op and
// the behaviour assertions fail on the claimed reason, not on the extractor
// (the cappedHtml/renderBudget passthrough pattern above).
const tryExtractEditorConst = (name) => {
  const source = readFileSync(join(repoRoot, "src/js/psbt-editor.js"), "utf8");
  return source.includes(`const ${name} = `) ? extractEditorConst(name) : null;
};

const pairRowsForTest = () => {
  const stubs = {
    PSBT_RENDER_LIMIT: vizModule.PSBT_RENDER_LIMIT,
    EXPAND_LIMIT: 80,
    PAIR_TYPES: { global: [["fc", "PSBT_GLOBAL_PROPRIETARY", "prefix len + prefix + subtype + keydata"]], input: [], output: [] },
    KV_COLUMNS: { field: "Field", key: "Key (hex)", value: "Value (hex)", decoded: "Decoded" },
    escapeHtml: (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"),
    cellLabel: () => "",
    describePair: () => ({ text: "", tone: "" }),
    pairNoteHtml: () => "",
    expandableHtml: (text) => String(text),
    network: () => "mainnet",
    copyIcon: () => "",
  };
  const names = Object.keys(stubs);
  return new Function(...names, `${extractEditorConst("pairRows")}; return pairRows;`)(...names.map((name) => stubs[name]));
};

test("the editor's pair tables cap rendered rows per map and note the elided count (F7)", () => {
  const pairRows = pairRowsForTest();
  const map = Array.from({ length: 1200 }, (_, index) => ({ key: "fc00", value: index.toString(16), name: "PSBT_GLOBAL_PROPRIETARY", decoded: null }));
  const html = pairRows("global", map, 0);
  assert.equal((html.match(/<tr role="row">\s*<td /g) || []).length, 500, "pair rows capped at 500");
  assert.ok(html.includes("700 more pairs"), "the elided count appears");
  const small = pairRows("global", map.slice(0, 2), 0);
  assert.equal((small.match(/<tr role="row">\s*<td /g) || []).length, 2, "every pair renders under the cap");
  assert.ok(!small.includes("(not rendered)"), "no elision line under the cap");
});

// --- F7 round 4: one render budget per view -------------------------------
// The per-list cap bounds one list, but nested lists multiply: 500 capped
// map sections of 200 pairs still render 100,000 rows. Every PSBT view now
// also shares one total render budget (PSBT_RENDER_BUDGET rows/sections/
// boxes, spent in document order); past it the view renders one muted line
// with the counted leftovers. Within the caps every view renders exactly as
// before — the inspector's per-input warnings included.

test("the view render budget is exported from psbt-viz.js and grants only what is left", () => {
  assert.equal(vizModule.PSBT_RENDER_BUDGET, 2000);
  const renderBudget = vizModule.renderBudget ?? (() => ({ take: (count = 1) => count, get left() { return Infinity; }, get spent() { return false; } }));
  const budget = renderBudget(3);
  assert.equal(budget.take(2), 2);
  assert.equal(budget.take(2), 1, "only what is left is granted");
  assert.ok(budget.spent, "the budget is spent");
  assert.equal(budget.take(1), 0, "a spent budget grants nothing");
});

test("cappedHtml spends from the view's render budget when one is passed", () => {
  const renderBudget = vizModule.renderBudget ?? (() => ({ take: (count = 1) => count, get left() { return Infinity; }, get spent() { return false; } }));
  const budget = renderBudget(5);
  const renderOne = (item) => `<i>${item}</i>`;
  const first = vizModule.cappedHtml([1, 2, 3], renderOne, "rows", undefined, budget);
  assert.equal(first, "<i>1</i><i>2</i><i>3</i>", "the budget grants what the cap would show");
  const second = vizModule.cappedHtml([4, 5, 6, 7], renderOne, "rows", undefined, budget);
  assert.equal((second.match(/<i>/g) || []).length, 2, "only the remaining budget renders");
  assert.ok(second.includes("2 more rows"), "the elision line counts what the budget cut");
});

test("an in-cap PSBT renders each per-input warning directly under its own input section, exactly like rock", () => {
  const { render } = hodlRenderPsbtForTest();
  // Three inputs, the middle one declaring SIGHASH_SINGLE: rock renders the
  // policy warning between Input 1's section and Input 2's section.
  const html = render(inspectorDoc(3, 1, 1), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  const input1 = html.indexOf("<strong>Input 1</strong>");
  const warning = html.indexOf("input 1 requests SIGHASH_SINGLE");
  const input2 = html.indexOf("<strong>Input 2</strong>");
  assert.ok(input1 !== -1 && warning !== -1 && input2 !== -1, "the section and its warning both render");
  assert.ok(input1 < warning && warning < input2, "the warning immediately follows its own input section");
  assert.ok(!html.includes("(not rendered)"), "no elision line for a small PSBT");
});

test("the inspector's whole view stays within the render budget when every input warns (F7)", () => {
  const { render, captured } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(1200, 1);
  // Every input declares SIGHASH_SINGLE and carries one inscription
  // envelope: two warning paragraphs per input, 2,400 in all.
  doc.inputs.forEach((map) => map.push({ type: 0x03, sighash: 3 }));
  doc.stubInscriptions = {
    inputs: Array.from({ length: 1200 }, () => ({ envelopes: [{ envelopeIndex: 0, source: "stub", bodyBytes: 10 }] })),
    envelopes: [],
  };
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  const sections = (html.match(/<strong>Input \d+<\/strong>/g) || []).length;
  const outputs = (html.match(/<strong>Output \d+<\/strong>/g) || []).length;
  // The capped-list note is warning-styled too (TC's review), but it is not a rendered warning row.
  const warnings = (html.match(/<p class='psbt-(?:bad|warn)'>(?!\d+ more (?:input|output)s? not shown)/g) || []).length;
  assert.equal(sections, 500, "input sections capped at 500");
  assert.equal(outputs, 1, "the one output renders");
  // 1 output block + 500 inputs × (1 section + 2 warnings) = 1,501 units
  // before the collected warnings; the budget then grants 499 of the 500
  // capped collected warnings: exactly PSBT_RENDER_BUDGET units in all.
  assert.equal(sections + outputs + warnings, vizModule.PSBT_RENDER_BUDGET ?? 2000, "the view renders exactly up to the budget");
  assert.equal(warnings, 1499, "1,000 inline + 499 collected warnings");
  assert.ok(html.includes("901 more warnings"), "the collected list notes what the budget cut");
  assert.ok(html.includes("700 more inputs"), "the inputs elision line");
  assert.equal(captured.checks.find((check) => check.label === "SIGHASH policy").state, "problem", "the policy check still covers all 1,200 inputs");
  assert.ok(html.includes("0.02399000 BTC"), "fee covers every input: 1,200 × 2,000 − 1,000 sats");
});

// render() and pairRows() are closures inside initPsbtEditor, so they are
// extracted from psbt-editor.js source and evaluated with stubs — the same
// harness pattern as hodlRenderPsbt above, reusing extractEditorConst.
// pairRows is evaluated alongside render so the view's render budget flows
// through the real row renderer; `out` captures the rendered HTML and
// `addedPairs` plays the Add Pair handler's record-keeping. The stubs are
// the editor's own contracts (every free variable of both closures).
const editorRenderForTest = (doc) => {
  const out = { innerHTML: "" };
  const stubs = {
    PSBT_RENDER_LIMIT: vizModule.PSBT_RENDER_LIMIT,
    renderBudget: vizModule.renderBudget ?? (() => ({ take: (count = 1) => count, get left() { return Infinity; }, get spent() { return false; } })),
    addedPairs: new Map(),
    doc,
    out,
    stale: false,
    insane: false,
    network: () => "mainnet",
    syncActions: () => {},
    bind: () => {},
    satsToBtc,
    escapeHtml: (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"),
    addressFor: () => null,
    opReturnSummary: () => null,
    publicValueHtml: (value) => String(value),
    copyIcon: () => "",
    cellLabel: () => "",
    KV_COLUMNS: { field: "Field", key: "Key (hex)", value: "Value (hex)", decoded: "Decoded" },
    TXIN_COLUMNS: { txid: "Previous txid", vout: "vout", seq: "sequence" },
    TXOUT_COLUMNS: { value: "Value (sats)", script: "scriptPubKey" },
    PAIR_TYPES: { global: [], input: [], output: [] },
    EXPAND_LIMIT: 80,
    describePair: () => ({ text: "", tone: "" }),
    pairNoteHtml: () => "",
    expandableHtml: (text) => String(text),
    // The real notes renderer, so the render-level budget test below
    // exercises the actual psbtOutputNotesHtml path (the head ignores the
    // budget argument, which is the defect).
    psbtOutputNotesHtml: (doc, budget) => vizModule.psbtOutputNotesHtml(doc, budget),
    psbtVizHtml: () => "",
    psbtProblemsHtml: () => "",
    psbtSanitizeHtml: () => "",
  };
  const names = Object.keys(stubs);
  const render = new Function(...names, `${extractEditorConst("pairRows")}\n${extractEditorConst("render")}\nreturn render;`)(...names.map((name) => stubs[name]));
  // The delete handlers' added-pairs re-key, with a no-op passthrough on the
  // pre-fix source so the round-5 tests fail on the stale keys (the claimed
  // reason), not on a missing const.
  const shiftAddedPairs = new Function("addedPairs", `${tryExtractEditorConst("shiftAddedPairs") ?? "const shiftAddedPairs = () => {};"}\nreturn shiftAddedPairs;`)(stubs.addedPairs);
  return { render, out, addedPairs: stubs.addedPairs, shiftAddedPairs };
};

// A synthetic editor document: inputCount inputs whose maps carry
// pairsPerInput proprietary pairs each, outputCount outputs with empty maps.
const editorDoc = (inputCount, pairsPerInput, outputCount = 1) => ({
  psbtVersion: 0,
  tx: {
    version: 2,
    locktime: 0,
    inputs: Array.from({ length: inputCount }, (_, vout) => ({ txid: "11".repeat(32), vout, scriptSig: "", sequence: 0xffffffff })),
    outputs: Array.from({ length: outputCount }, () => ({ value: "1000", scriptPubKey: "0014" + "22".repeat(20), asm: "" })),
  },
  globals: [],
  inputs: Array.from({ length: inputCount }, (_, map) =>
    Array.from({ length: pairsPerInput }, (_, pair) => ({ key: "fc00", value: (map * pairsPerInput + pair).toString(16), name: "PSBT_IN_PROPRIETARY", decoded: null }))),
  outputs: Array.from({ length: outputCount }, () => []),
  fee: { known: false },
});

// Data rows only: the header rows are <tr role="row"><th…, the data rows
// <tr role="row"><td… (the same distinction the pairRows test above makes).
const dataRows = (html) => (html.match(/<tr role="row">\s*<td /g) || []).length;

test("the editor bounds the whole view to the render budget: 500 maps × 200 pairs cannot multiply past it (F7)", () => {
  const { render, out } = editorRenderForTest(editorDoc(500, 200));
  render();
  const html = out.innerHTML;
  // Document order: 500 input rows + 1 output row + the global section (its
  // empty map renders its no-pairs row), then whole input-map sections of
  // 1 + 200 units until the budget is spent — 7 full sections and one of
  // 1 + 90: 500 + 1 + 1 + 7 × 200 + 90 = 1,992 rows, never over the budget.
  assert.equal(dataRows(html), 1992, "rows render in document order up to the budget");
  assert.ok(dataRows(html) <= (vizModule.PSBT_RENDER_BUDGET ?? 2000), "never over the budget");
  assert.ok(html.includes('data-psbted-section="input:7"'), "the section the budget cuts mid-table still renders");
  assert.ok(!html.includes('data-psbted-section="input:8"'), "no section renders past the budget");
  // The single budget line counts every unit not rendered from the stop
  // point: 500 input rows + 1 output row + 1 global section + 500 × (1
  // section + 200 pairs) + 1 output-map section = 101,003 units of demand;
  // 2,000 rendered, 99,003 elided.
  assert.ok(html.includes("99003"), "the budget line counts every elided section and pair");
  assert.ok(html.includes("(not rendered)"), "the budget line appears");
});

test("when both the inputs table and the input map sections are capped, the second note names the maps (F7)", () => {
  const { render, out } = editorRenderForTest(editorDoc(1200, 0));
  render();
  const html = out.innerHTML;
  assert.equal((html.match(/700 more inputs not shown, still included in this transaction\./g) || []).length, 1, "the transaction table's note appears once");
  assert.equal((html.match(/700 more input maps \(not rendered\)/g) || []).length, 1, "the map sections' note names the maps");
});

test("a pair added to an over-cap map renders after the capped rows, so the user sees it (F7)", () => {
  const doc = editorDoc(1, 0);
  doc.globals = Array.from({ length: 501 }, (_, pair) => ({ key: "fc00", value: pair.toString(16), name: "PSBT_GLOBAL_PROPRIETARY", decoded: null }));
  const { render, out, addedPairs } = editorRenderForTest(doc);
  addedPairs.set("global:0", 1); // what the Add Pair handler records per accepted add
  render();
  const html = out.innerHTML;
  assert.ok(html.includes('data-pair="500"'), "the added pair (index 500) renders past the cap");
  assert.ok(!html.includes("more pairs"), "all 501 pairs render: 500 capped rows plus the added one");
});

test("a pair added to an over-cap input map stays visible after an earlier input is deleted (F7 round 5)", () => {
  const doc = editorDoc(3, 0);
  // Input 1's map is over the cap; input 2's small map is the neighbour that
  // lands on the stale "input:1" key after the delete.
  doc.inputs[1] = Array.from({ length: 501 }, (_, pair) => ({ key: "fc00", value: pair.toString(16), name: "PSBT_IN_PROPRIETARY", decoded: null }));
  doc.inputs[2] = ["aa", "bb", "cc"].map((value) => ({ key: "fc00", value, name: "PSBT_IN_PROPRIETARY", decoded: null }));
  const { render, out, addedPairs, shiftAddedPairs } = editorRenderForTest(doc);
  addedPairs.set("input:1", 1); // what the Add Pair handler records per accepted add
  render();
  assert.ok(out.innerHTML.includes('data-pair="500"'), "the added pair renders for input 1 before the delete");
  // What an accepted delete of input 0 does: splice the transaction input
  // and its map, re-key the added-pair counts, and re-render.
  doc.tx.inputs.splice(0, 1);
  doc.inputs.splice(0, 1);
  shiftAddedPairs("input", 0);
  render();
  const html = out.innerHTML;
  // The over-cap map is now input 0: its added pair (index 500) must still
  // render, and 501 pairs with one overflow slot elide nothing.
  assert.ok(html.includes('data-pair="500"'), "the added pair still renders after the delete");
  assert.ok(!html.includes("more pairs (not rendered)"), "the added pair is not elided");
  // The neighbour (old input 2, three pairs, nothing added) now sits at the
  // stale key: it must not render the extra overflow row the stale count
  // would grant it (its last pair rendered twice).
  const neighbour = html.slice(html.indexOf('data-psbted-section="input:1"'), html.indexOf('data-psbted-section="output:0"'));
  assert.equal(dataRows(neighbour), 3, "the neighbouring map renders exactly its three pairs");
});

test("a pair added to an over-cap output map stays visible after an earlier output is deleted (F7 round 5)", () => {
  const doc = editorDoc(1, 0, 3);
  doc.outputs[1] = Array.from({ length: 501 }, (_, pair) => ({ key: "fc00", value: pair.toString(16), name: "PSBT_OUT_PROPRIETARY", decoded: null }));
  doc.outputs[2] = ["aa", "bb", "cc"].map((value) => ({ key: "fc00", value, name: "PSBT_OUT_PROPRIETARY", decoded: null }));
  const { render, out, addedPairs, shiftAddedPairs } = editorRenderForTest(doc);
  addedPairs.set("output:1", 1); // what the Add Pair handler records per accepted add
  render();
  assert.ok(out.innerHTML.includes('data-pair="500"'), "the added pair renders for output 1 before the delete");
  doc.tx.outputs.splice(0, 1);
  doc.outputs.splice(0, 1);
  shiftAddedPairs("output", 0);
  render();
  const html = out.innerHTML;
  assert.ok(html.includes('data-pair="500"'), "the added pair still renders after the delete");
  assert.ok(!html.includes("more pairs (not rendered)"), "the added pair is not elided");
  const neighbour = html.slice(html.indexOf('data-psbted-section="output:1"'));
  assert.equal(dataRows(neighbour), 3, "the neighbouring map renders exactly its three pairs");
});

test("a small PSBT renders every editor row and section with no elision line", () => {
  const { render, out } = editorRenderForTest(editorDoc(3, 2, 2));
  render();
  const html = out.innerHTML;
  // 3 input rows + 2 output rows + 3 maps × 2 pair rows; the empty global
  // map and the two empty output maps render their no-pairs rows.
  assert.equal(dataRows(html), 3 + 2 + 6 + 3, "every row renders");
  for (const target of ["input:0", "input:1", "input:2", "output:0", "output:1"]) {
    assert.ok(html.includes(`data-psbted-section="${target}"`), `section ${target} renders`);
  }
  assert.ok(!html.includes("(not rendered)"), "no elision line under the caps");
});

test("the compare view bounds the whole report to the render budget: 500 maps × 200 changes cannot multiply past it (F7)", () => {
  const doc = (value) => ({
    tx: {
      version: 2,
      locktime: 0,
      inputs: Array.from({ length: 500 }, (_, vout) => ({ txid: "11".repeat(32), vout, scriptSig: "", sequence: 0xffffffff })),
      outputs: [],
    },
    globals: [],
    inputs: Array.from({ length: 500 }, () => Array.from({ length: 200 }, () => ({ key: "fc00", value, name: "PSBT_IN_PROPRIETARY", decoded: null }))),
    outputs: [],
    fee: { known: false },
  });
  const before = doc("aa"), after = doc("bb");
  const diff = comparePsbtDocs(before, after);
  assert.equal(diff.changes.length, 100000, "every changed pair is analysed");
  const html = psbtDiffHtml(diff, before, after, "mainnet");
  // 9 full sections of 200 rows and one of 190: 1,990 rows, never over the
  // budget; 10 sections render, the 11th would not fit.
  const rows = (html.match(/<tr><td/g) || []).length;
  assert.equal(rows, 1990, "rows render in document order up to the budget");
  assert.ok(rows <= (vizModule.PSBT_RENDER_BUDGET ?? 2000), "never over the budget");
  assert.equal((html.match(/key-value map<\/h3>/g) || []).length, 10, "sections render until the budget is spent");
  // 100,000 changes in all; 1,990 render inside 10 sections, and the 10 rows
  // the budget cut mid-table join them: 98,010 elided changes. The 490 map
  // sections the budget also cut are sections, not changes, and a line that
  // says "changes" must not count them (red-team F7 round 6).
  assert.ok(html.includes("98010"), "the budget line counts every elided change");
  assert.ok(!html.includes("98500"), "elided sections are not miscounted as changes");
});

// --- F7 round 6 ------------------------------------------------------------

test("the nonce view does not spend its render budget on inspector sections it discards (F7 round 6)", () => {
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(500, 500);
  // Every input carries a SIGHASH_SINGLE policy warning and a partial
  // signature: on the head, the output blocks, input sections and inline
  // warnings the nonce view discards spend the whole budget (500 + 500 +
  // 500 = 1,500, then 500 r-value lines), and the per-signature rows get 0.
  doc.inputs.forEach((map) => map.push({ type: 0x03, sighash: 3 }));
  const pubkey = new Uint8Array(33).fill(2);
  doc.inputs.forEach((map) => map.push({ type: 0x02, pubkey, der: new Uint8Array(72).fill(0x30) }));
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "nonce", { network: "mainnet", transcript: "", record: false });
  assert.equal((html.match(/<strong>Input \d+<\/strong>/g) || []).length, 500, "nonce rows render up to their cap");
  assert.equal((html.match(/\(input \d+\)/g) || []).length, 500, "r-value lines render up to their cap");
});

test("an input added past the render cap renders its table row and map section (F7 round 6)", () => {
  const doc = editorDoc(500, 0);
  const { render, out, addedPairs } = editorRenderForTest(doc);
  render();
  assert.ok(!out.innerHTML.includes('data-txin="500"'), "input 500 is past the cap before the add");
  // What an accepted Add Input does: append the transaction input and its
  // (empty) map, count the add like an added pair, and re-render.
  doc.tx.inputs.push({ txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 });
  doc.inputs.push([]);
  addedPairs.set("tx:input", 1);
  render();
  const html = out.innerHTML;
  assert.ok(html.includes('data-txin="500"'), "the added input's row renders after the capped rows");
  assert.ok(html.includes('data-psbted-section="input:500"'), "the added input's map section renders");
});

test("an output added past the render cap renders its table row and map section (F7 round 6)", () => {
  const doc = editorDoc(1, 0, 500);
  const { render, out, addedPairs } = editorRenderForTest(doc);
  render();
  doc.tx.outputs.push({ value: "0", scriptPubKey: "" });
  doc.outputs.push([]);
  addedPairs.set("tx:output", 1);
  render();
  const html = out.innerHTML;
  assert.ok(html.includes('data-txout-val="500"'), "the added output's row renders after the capped rows");
  assert.ok(html.includes('data-psbted-section="output:500"'), "the added output's map section renders");
});

test("shiftAddedPairs re-keys from a snapshot, so a lower key is never overwritten (F7 round 6)", () => {
  const doc = editorDoc(3, 0);
  const { shiftAddedPairs, addedPairs } = editorRenderForTest(doc);
  // Insertion order "input:2" before "input:1": re-keying in place lands
  // "input:2" on "input:1" before that entry moves, losing its count.
  addedPairs.set("input:2", 2);
  addedPairs.set("input:1", 1);
  shiftAddedPairs("input", 0);
  assert.deepEqual(Object.fromEntries(addedPairs), { "input:0": 1, "input:1": 2 }, "both counts survive the re-key");
  // The reverse insertion order must reach the same map.
  addedPairs.clear();
  addedPairs.set("input:1", 1);
  addedPairs.set("input:2", 2);
  shiftAddedPairs("input", 0);
  assert.deepEqual(Object.fromEntries(addedPairs), { "input:0": 1, "input:1": 2 }, "insertion order cannot change the answer");
});

test("the editor summary's per-output notes spend from the view budget (F7 round 6)", () => {
  const doc = editorDoc(500, 200, 700);
  doc.tx.outputs = Array.from({ length: 700 }, () => ({ value: "1", scriptPubKey: program(2, 32), asm: "" }));
  const { render, out } = editorRenderForTest(doc);
  render();
  const html = out.innerHTML;
  const notes = (html.match(/Output #\d+/g) || []).length;
  // The notes render above the tables, so they spend from the budget first:
  // 500 notes (their own cap), then the tables render within what remains.
  // On the head the notes rendered outside the budget and the view totalled
  // 2,495 rendered elements — 500 notes plus 1,995 rows.
  assert.equal(notes, 500, "notes capped at 500");
  assert.ok(notes + dataRows(html) <= (vizModule.PSBT_RENDER_BUDGET ?? 2000), "the notes count against the view budget");
  assert.ok(html.includes("200 more notes"), "the notes' elision line appears");
});

test("a capped view counts every input's warnings through the collected list, with no extra per-input line (F7 round 7)", () => {
  const { render, captured } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(2000, 1);
  doc.inputs.forEach((map) => map.push({ type: 0x03, sighash: 3 }));
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  // Every input's warning is collected: the first 500 render inline under
  // their own sections (1,001 budget units with the output block), then the
  // collected list renders 500 of the remaining 1,500 — 1,000 paragraphs
  // shown, 1,000 elided. The analysis summary reports the policy problem
  // for every input, and the round-6 per-input hidden-warnings line (whose
  // helper re-scanned every warning, O(W²) at the load gates, and was
  // visible text the owner never approved) must not reappear.
  assert.equal((html.match(/<p class='psbt-bad'>/g) || []).length, 1000, "500 inline + 500 collected warning paragraphs");
  assert.ok(html.includes("1000 more warnings (not rendered)"), "the collected list counts the warnings the budget cut");
  assert.ok(!html.includes("more inputs have warnings"), "no per-input hidden-warnings line is rendered");
  assert.equal(captured.checks.find((check) => check.label === "SIGHASH policy").state, "problem", "the analysis still covers every input");
});

test("one input with 300,000 warnings renders capped instead of throwing (GLM 5.3 review of cd4065b)", () => {
  // A 5 MB PSBT fits hundreds of thousands of minimal inscription envelopes
  // in one input's witness. Moving that input's warnings to the collected
  // list with a spread (`warnings.push(...own)`) passed them all as call
  // arguments and threw a RangeError, so the crafted PSBT this cap exists to
  // survive killed the render instead.
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(1, 1);
  const envelopes = Array.from({ length: 300000 }, (_, envelopeIndex) => ({ envelopeIndex, source: "witness", bodyBytes: 1, unrecognizedEven: false }));
  doc.stubInscriptions = { inputs: [{ envelopes }], envelopes };
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  // The input's section and as many of its warnings as the 2,000-unit budget
  // holds render inline (2,000 - 1 output block - 1 section); the rest are
  // counted, not rendered.
  assert.equal((html.match(/<strong>Inscription envelope<\/strong>/g) || []).length, 1998, "warnings render up to the budget");
  assert.ok(html.includes("<strong>Input 0</strong>"), "the input's own section renders");
  assert.match(html, /…and \d+ more warnings \(not rendered\)\./, "the rest are counted");
  // The Nonce Inspector builds the same input sections with an unbounded
  // budget (it discards them), so its inline branch took the same spread
  // (DeepSeek V4.1 red-team and GLM 5.3 review of 8094939). Every view must
  // survive the PSBT.
  for (const view of ["nonce", "all"]) {
    assert.doesNotThrow(() => render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", view, { network: "mainnet" }), `the ${view} view renders`);
  }
});

test("the budget line counts the maps the overflow sections skipped, not the ones they rendered (F7 round 7)", () => {
  // 600 input maps: 0–499 empty, 500–597 with 10 pairs each, and the two
  // empty maps two Add Input clicks appended at 598/599. All 496 outputs
  // carry an undefined-witness-program note, so notes (496) + input rows
  // (502) + output rows (496) + the global section and its 3 pairs (4)
  // land the budget at 502 before the input map sections; the 500 empty
  // capped sections and the 2 overflow sections spend it exactly. Maps
  // 500–597 and every output map section never render: 98 × (1 section +
  // 10 pairs) + 496 × 1 = 1,574 elided items. Round 6 printed 1,554 by
  // counting the two rendered overflow maps again and skipping the two
  // unrendered middle ones.
  const doc = editorDoc(600, 0, 496);
  doc.tx.outputs.forEach((output) => (output.scriptPubKey = program(2, 32)));
  doc.globals = Array.from({ length: 3 }, (_, index) => ({ key: "fc00", value: "0" + index, name: "PSBT_GLOBAL_PROPRIETARY", decoded: null }));
  for (let index = 500; index < 598; index++) doc.inputs[index] = Array.from({ length: 10 }, (_, pair) => ({ key: "fc00", value: `${index}-${pair}`, name: "PSBT_IN_PROPRIETARY", decoded: null }));
  const { render, out, addedPairs } = editorRenderForTest(doc);
  addedPairs.set("tx:input", 2); // what two accepted Add Input clicks record
  render();
  const html = out.innerHTML;
  assert.equal((html.match(/Output #/g) || []).length, 496, "every output's note renders and spends from the budget");
  assert.ok(html.includes('data-psbted-section="input:499"'), "the capped sections render");
  assert.ok(html.includes('data-psbted-section="input:599"'), "the added inputs' overflow sections render");
  assert.ok(!html.includes('data-psbted-section="input:500"'), "the middle maps the budget cut do not render");
  assert.ok(html.includes("1574 more items (not rendered)"), "the budget line counts every unrendered map exactly once");
  assert.ok(!html.includes("1554 more items"), "the rendered overflow maps are not counted again");
});

test("Add/Delete Input, Add/Delete Output and Add Pair repaint the result panel after their re-render (F7 round 7)", () => {
  // The add handlers re-render after recording the add (it may land past
  // the rendered rows), and the delete handlers re-render after re-keying
  // the added-pair counts; render() recreates an empty #psbted-result —
  // without a renderResult() call the export panel stays blank until the
  // next keystroke or network flip. The handlers are bound to the DOM
  // inside initPsbtEditor, so this checks the source: every click handler
  // that records or re-keys an added pair must repaint the result panel
  // right after its re-render.
  const source = readFileSync(join(repoRoot, "src/js/psbt-editor.js"), "utf8");
  const handlers = [];
  const click = /addEventListener\("click", \(\) => \{/g;
  for (let match; (match = click.exec(source)); ) {
    // Brace-match the handler body; strings and comments are skipped so
    // template placeholders like `${kind}` cannot fool the counter.
    let depth = 1, state = "code", quote = "";
    let i = match.index + match[0].length;
    const start = i;
    while (i < source.length && depth > 0) {
      const char = source[i], next = source[i + 1];
      if (state === "line") { if (char === "\n") state = "code"; i++; continue; }
      if (state === "block") { if (char === "*" && next === "/") { state = "code"; i += 2; continue; } i++; continue; }
      if (state === "string") {
        if (char === "\\") { i += 2; continue; }
        if (char === quote) state = "code";
        i++;
        continue;
      }
      if (char === "/" && next === "/") { state = "line"; i += 2; continue; }
      if (char === "/" && next === "*") { state = "block"; i += 2; continue; }
      if (char === "'" || char === '"' || char === "`") { state = "string"; quote = char; i++; continue; }
      if (char === "{") depth++;
      else if (char === "}") depth--;
      i++;
    }
    handlers.push(source.slice(start, i - 1));
  }
  assert.ok(handlers.length >= 2, "the editor's click handlers were found");
  let checked = 0;
  for (const body of handlers) {
    for (const { index: at } of body.matchAll(/\baddedPairs\.set\(|\bshiftAddedPairs\(/g)) {
      const rest = body.slice(at);
      const renderAt = rest.indexOf("render();");
      assert.notEqual(renderAt, -1, "the handler re-renders after recording or re-keying the added pairs");
      assert.match(rest.slice(renderAt), /^render\(\);\s*renderResult\(\);/, "renderResult() repaints the result panel right after the re-render");
      checked++;
    }
  }
  assert.ok(checked >= 4, "the tx-add, Add Pair and both delete handlers were checked");
});

// "Show more" (the owner, 2026-10-22, after a reviewer asked whether users can
// see inputs past the cap): the Inspector passes a window of 2,000 per list
// and a step; past the window the note is followed by one button per list
// that names the next step. Hooked on data-psbt-more, never on a class.
const INSPECTOR = { inputs: 2000, outputs: 2000, step: 2000, format: (n) => n.toLocaleString("en-US") };
const moreButtons = (html) => [...html.matchAll(/<button[^>]*data-psbt-more='(\w+)'[^>]*>([^<]*)<\/button>/g)].map(([, kind, label]) => [kind, label]);

test("the Inspector shows 2,000 inputs and outputs, then one Show-more button per list naming the next step", () => {
  const { render } = hodlRenderPsbtForTest();
  const html = render(inspectorDoc(2500, 2300), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: INSPECTOR });
  assert.equal(html.match(/<strong>Input \d+<\/strong>/g)?.length ?? 0, 2000, "2,000 input sections");
  assert.equal(html.match(/<strong>Output \d+<\/strong>/g)?.length ?? 0, 2000, "2,000 output blocks");
  assert.ok(html.includes("500 more inputs not shown, still included in this transaction."));
  assert.ok(html.includes("300 more outputs not shown, still included in this transaction."));
  assert.deepEqual(moreButtons(html), [["outputs", "Show 300 more outputs"], ["inputs", "Show 500 more inputs"]]);
});

test("Show more grows the window by one step, and the button goes once a list is complete", () => {
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(5000, 3);
  const first = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: INSPECTOR });
  assert.deepEqual(moreButtons(first), [["inputs", "Show 2,000 more inputs"]], "a full step is named with the page's grouping");
  const second = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: { ...INSPECTOR, inputs: 4000 } });
  assert.equal(second.match(/<strong>Input \d+<\/strong>/g)?.length ?? 0, 4000, "4,000 input sections after one step");
  assert.ok(second.includes("<strong>Input 3999</strong>") && !second.includes("<strong>Input 4000</strong>"));
  assert.deepEqual(moreButtons(second), [["inputs", "Show 1,000 more inputs"]], "the last step names what is left");
  const third = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: { ...INSPECTOR, inputs: 6000 } });
  assert.equal(third.match(/<strong>Input \d+<\/strong>/g)?.length ?? 0, 5000, "every input once the window covers them");
  assert.deepEqual(moreButtons(third), [], "no button and no note once nothing is hidden");
  assert.ok(!third.includes("more inputs not shown"));
});

test("only a caller that can grow the window gets a Show-more button", () => {
  const { render } = hodlRenderPsbtForTest();
  const exact = render(inspectorDoc(2000, 2000), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: INSPECTOR });
  assert.deepEqual(moreButtons(exact), [], "exactly 2,000 of each: nothing hidden, no button");
  const fixed = render(inspectorDoc(1200, 3), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  assert.equal(fixed.match(/<strong>Input \d+<\/strong>/g)?.length ?? 0, 500, "without a window, the shared 500 cap");
  assert.ok(fixed.includes("700 more inputs not shown, still included in this transaction."));
  assert.deepEqual(moreButtons(fixed), [], "no step, no button");
});

test("an input with more warnings than the budget holds keeps its section, in a small PSBT (GLM 5.3 review of #1031)", () => {
  // 3 inputs; input 1 carries 2,500 envelopes. Asking for its section and all
  // its warnings at once hid input 1 entirely (and so its address and amount)
  // although the PSBT is far under the cap.
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(3, 1);
  const envelopes = Array.from({ length: 2500 }, (_, envelopeIndex) => ({ envelopeIndex, source: "witness", bodyBytes: 1, unrecognizedEven: false }));
  doc.stubInscriptions = { inputs: [{ envelopes: [] }, { envelopes }, { envelopes: [] }], envelopes };
  const html = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  for (const n of [0, 1, 2]) assert.ok(html.includes(`<strong>Input ${n}</strong>`), `input ${n}'s section renders`);
  assert.ok(!html.includes("more inputs not shown"), "no input is elided");
  assert.ok(html.indexOf("<strong>Input 1</strong>") < html.indexOf("<strong>Inscription envelope</strong>"), "input 1's warnings follow its section");
  assert.match(html, /…and \d+ more warnings \(not rendered\)\./, "the warnings past the budget are counted");
});

// A "Show more" click renders only the block it adds (Portland: up to ~21k
// inputs and ~100k outputs per transaction). The page with the block inserted
// above the list's tail must be exactly the page a full render of the grown
// window gives.
const appended = (render, doc, kind, from, limits) => {
  const ts = ["2024-01-01T00:00:00Z", "inspect"];
  const page = render(doc, new Uint8Array(), ...ts, { network: "mainnet", limits: { ...limits, [kind]: from } });
  const before = render(doc, new Uint8Array(), ...ts, { network: "mainnet", limits: { ...limits, [kind]: from }, only: { kind, from } });
  const part = render(doc, new Uint8Array(), ...ts, { network: "mainnet", limits, only: { kind, from } });
  const open = "<div data-psbt-tail='" + kind + "'>";
  const old = open + before.tail + "</div>";
  assert.equal(before.chunk, "", "nothing new at the current window");
  assert.equal(page.split(old).length, 2, "the page carries the list's tail exactly once");
  return { page: page.replace(old, part.chunk + open + part.tail + "</div>"), part };
};

test("appending the next 2,000 inputs gives exactly the page a full render of the grown window gives", () => {
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(5000, 3);
  const limits = { ...INSPECTOR, inputs: 4000 };
  const { page, part } = appended(render, doc, "inputs", 2000, limits);
  assert.equal((part.chunk.match(/<strong>Input \d+<\/strong>/g) || []).length, 2000, "the block holds only the new inputs");
  assert.ok(part.chunk.includes("<strong>Input 2000</strong>") && !part.chunk.includes("<strong>Input 1999</strong>"));
  assert.equal(page, render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits }));
});

test("appending the next 2,000 outputs gives exactly the page a full render of the grown window gives", () => {
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(2, 5000);
  const limits = { ...INSPECTOR, outputs: 4000 };
  const { page, part } = appended(render, doc, "outputs", 2000, limits);
  assert.equal((part.chunk.match(/<strong>Output \d+<\/strong>/g) || []).length, 2000);
  assert.equal(page, render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits }));
});

test("when an input already shown carries warnings, the block render declines and the click repaints", () => {
  // How many of an input's warnings render inline depends on the window, so
  // appending could leave some in neither place.
  const { render } = hodlRenderPsbtForTest();
  const part = render(inspectorDoc(3000, 1, 5), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: { ...INSPECTOR, inputs: 4000 }, only: { kind: "inputs", from: 2000 } });
  assert.equal(part, null);
});

test("the note under a capped list says the hidden inputs and outputs are still in the transaction, one or many (TC's review of #1031)", () => {
  const { render } = hodlRenderPsbtForTest();
  const one = render(inspectorDoc(501, 501), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet" });
  assert.ok(one.includes("<p class='psbt-warn'>1 more input not shown, still included in this transaction.</p>"), "one input, as a warning");
  assert.ok(one.includes("<p class='psbt-warn'>1 more output not shown, still included in this transaction.</p>"), "one output, as a warning");
  assert.ok(!/1 more (inputs|outputs)/.test(one), "never '1 more inputs'");
  const step = render(inspectorDoc(2001, 1), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: INSPECTOR });
  assert.deepEqual(moreButtons(step), [["inputs", "Show 1 more input"]]);
  const many = render(inspectorDoc(2003, 1), new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits: INSPECTOR });
  assert.ok(many.includes("3 more inputs not shown, still included in this transaction."));
});

test("an appended output block spends the derivation budget as a full render does (GLM 5.3's review of #1031)", () => {
  // Each output's declared path costs 3 of the render's 4,096 derivation
  // steps, so a full render runs out at output 1,365 and every later output
  // reads as over budget. The block for outputs 2,000+ must read the same,
  // not start from a fresh budget.
  const { render } = hodlRenderPsbtForTest({
    hodlRenderOutputHtml: (output, index, network, map, entries, derivationBudget) => {
      const derived = derivationBudget.remaining >= 3;
      derivationBudget.remaining = derived ? derivationBudget.remaining - 3 : 0;
      return `<p class='psbt-kv'><strong>Output ${index}</strong> ${derived ? "derived" : "over budget"}</p>`;
    },
  });
  const doc = inspectorDoc(2, 5000);
  const limits = { ...INSPECTOR, outputs: 4000 };
  const { page, part } = appended(render, doc, "outputs", 2000, limits);
  assert.ok(part.chunk.includes("<strong>Output 2000</strong> over budget"), "the block reads over budget, as in the full render");
  assert.ok(!part.chunk.includes("derived"));
  const full = render(doc, new Uint8Array(), "2024-01-01T00:00:00Z", "inspect", { network: "mainnet", limits });
  assert.ok(full.includes("<strong>Output 1364</strong> derived") && full.includes("<strong>Output 1365</strong> over budget"));
  assert.equal(page, full);
});

// GLM 5.3's review of #1031 (a47705c): Show more on one list grows the whole
// view's budget, so the other list's tail must follow. The real click handler
// runs against a string-backed stand-in for #psbt-out.
const pageElement = (initial) => {
  const element = { html: initial, hasAttribute: () => true, setAttribute: () => {}, focus: () => {} };
  Object.defineProperty(element, "innerHTML", { get: () => element.html, set: (value) => { element.html = value; } });
  const tailSpan = (kind) => {
    const open = "<div data-psbt-tail='" + kind + "'>", start = element.html.indexOf(open);
    if (start < 0) return null;
    let depth = 1, at = start + open.length;
    while (depth) {
      const next = element.html.indexOf("<div", at), close = element.html.indexOf("</div>", at);
      if (next >= 0 && next < close) { depth++; at = next + 4; } else { depth--; at = close + 6; }
    }
    return { start, inner: start + open.length, end: at - 6 };
  };
  element.querySelector = (selector) => {
    const kind = (selector.match(/data-psbt-tail='(\w+)'/) || [])[1];
    if (!kind || !tailSpan(kind)) return null;
    return {
      get innerHTML() { const s = tailSpan(kind); return element.html.slice(s.inner, s.end); },
      set innerHTML(value) { const s = tailSpan(kind); element.html = element.html.slice(0, s.inner) + value + element.html.slice(s.end); },
      insertAdjacentHTML: (where, value) => { const s = tailSpan(kind); element.html = element.html.slice(0, s.start) + value + element.html.slice(s.start); },
    };
  };
  return element;
};

test("Show more on outputs after inputs keeps the inputs tail equal to a full render of the grown window", () => {
  // GLM's case: inputs 2,000+ carry three warnings each (a SIGHASH_SINGLE
  // policy problem and two inscription envelopes), so the inputs tail's
  // collected warnings depend on the whole view's budget.
  const { render } = hodlRenderPsbtForTest();
  const doc = inspectorDoc(5000, 3000);
  const envelopes = [];
  doc.stubInscriptions = { inputs: doc.inputs.map((entries, index) => {
    if (index < 2000) return { envelopes: [] };
    entries.push({ type: 0x03, sighash: 3 });
    const own = [0, 1].map((k) => ({ envelopeIndex: envelopes.length + k, source: "witness", bodyBytes: 1, unrecognizedEven: false }));
    envelopes.push(...own);
    return { envelopes: own };
  }), envelopes };
  const ts = [new Uint8Array(), "2024-01-01T00:00:00Z", "inspect"];
  const last = { kind: "psbt", parsed: doc, sourceTag: ts[0], checkedAt: ts[1], network: "mainnet", limits: { ...INSPECTOR } };
  const output = pageElement(render(doc, ...ts, { network: "mainnet", limits: last.limits }));
  const showMore = new Function("document", "hodlPsbtLast", "hodlRenderPsbt", "hodlRenderRawTx", `${extractAppFunction("hodlPsbtShowMore")}; return hodlPsbtShowMore;`)(
    { getElementById: (id) => (id === "psbt-out" ? output : null) }, last, render, () => { throw new Error("not a transaction"); });
  const click = (kind) => showMore({ target: { closest: () => ({ dataset: { psbtMore: kind } }) } });
  click("inputs");
  assert.equal(output.html, render(doc, ...ts, { network: "mainnet", limits: { ...INSPECTOR, inputs: 4000 } }), "after the inputs click");
  click("outputs");
  assert.equal(output.html, render(doc, ...ts, { network: "mainnet", limits: { ...INSPECTOR, inputs: 4000, outputs: 4000 } }), "after the outputs click, the inputs tail follows the grown budget");
});
