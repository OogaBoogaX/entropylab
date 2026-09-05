// Tests for the pure half of the PSBT flow visualizer (src/js/psbt-viz.js) —
// the mempool.space-style inputs → transaction → outputs diagram rendered at
// the top of the PSBT editor. Selection state, DOM binding, the connector
// path drawing and the detail panel live in psbt-editor.js and are covered
// by the Firefox browser suite (test/browser-suite.html).
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtVizHtml } from "../src/js/psbt-viz.js";

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

// The diagram groups read-only sats with narrow no-break spaces; keep the
// escape visible instead of hiding invisible characters in assertions.
const sats = (digits) => digits.replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f");

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
  assert.match(html, /Inputs \(2\)/);
  assert.match(html, /Outputs \(2\)/);
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

test("OP_RETURN outputs get the data-carrier tag instead of an address", () => {
  const html = psbtVizHtml(syntheticDoc(), "mainnet");
  assert.ok(html.includes("OP_RETURN"), "OP_RETURN tag missing");
  assert.ok(!html.includes("psbted-viz-out"), "an OP_RETURN box must not pose as an address");
});

test("signing progress counts partial and taproot signatures", () => {
  const pairs = (names) => names.map((name) => ({ key: "02", value: "", name }));
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

test("the selected box is marked open and expanded, the rest are not", () => {
  const doc = inspectValid();
  const html = psbtVizHtml(doc, "mainnet", { kind: "input", index: 1 });
  const box = (target) => html.match(new RegExp(`<button[^>]*data-viz="${target}"[^>]*>`))[0];
  assert.ok(box("input:1").includes('aria-expanded="true"'), "selected box not expanded");
  assert.ok(!box("input:0").includes('aria-expanded="true"'), "unselected box expanded");
  assert.ok(html.includes("is-open"), "selected box is not highlighted");
  // A stale selection (out of range) selects nothing.
  const stale = psbtVizHtml(doc, "mainnet", { kind: "input", index: 9 });
  assert.ok(!stale.includes('aria-expanded="true"'), "out-of-range selection must be ignored");
});

test("the connector layer ships empty: the browser draws the lines with layout", () => {
  const html = psbtVizHtml(inspectValid(), "mainnet");
  assert.ok(html.includes('<svg class="psbted-viz-svg"'), "connector layer missing");
  assert.ok(html.includes("aria-hidden"), "decorative layer must be hidden from assistive tech");
  assert.ok(!html.includes("<path"), "paths need layout; they must not be in the pure markup");
});

test("the transaction box is a button that opens the transaction fields", () => {
  const doc = inspectValid();
  const closed = psbtVizHtml(doc, "mainnet");
  const txButton = closed.match(/<button[^>]*data-viz="tx"[^>]*>/);
  assert.ok(txButton, "transaction box is not a button");
  assert.ok(txButton[0].includes('aria-expanded="false"'), "transaction box starts closed");
  const open = psbtVizHtml(doc, "mainnet", { kind: "tx" });
  assert.ok(open.includes('class="psbted-viz-tx is-open"'), "open transaction box not highlighted");
  assert.ok(open.match(/<button[^>]*data-viz="tx"[^>]*>/)[0].includes('aria-expanded="true"'), "open transaction box not expanded");
  assert.ok(!open.includes('data-viz="input:0" aria-expanded="true"'), "transaction selection must not expand a map box");
});

test("fee states: known fee, negative fee, unknown fee", () => {
  const known = psbtVizHtml(syntheticDoc({ fee: { known: true, sats: 1412 } }), "mainnet");
  assert.ok(known.includes(`${sats("1412")} sats`), "known fee missing");
  assert.ok(known.includes("(PSBT claim)"), "known fee is not marked as a claim");
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
