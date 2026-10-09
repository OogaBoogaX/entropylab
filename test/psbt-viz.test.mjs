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
import * as vizModule from "../src/js/psbt-viz.js";
import { addressFromScript } from "../src/js/addresses.js";

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
  // A pair name alone no longer counts: the typed decode must have succeeded.
  const pairs = (names) => names.map((name) => ({ key: "02", value: "", name, decoded: { signature: "ab" } }));
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
  // typed decode is presence without validity.
  const bad = (name) => ({ key: "02", value: "", name, decoded: null, decodeError: "truncated" });
  const doc = syntheticDoc({
    inputs: [
      [bad("PSBT_IN_PARTIAL_SIG")],
      [bad("PSBT_IN_FINAL_SCRIPTSIG")],
      // A good signature alongside a malformed one still counts the good one.
      [{ key: "02", value: "", name: "PSBT_IN_PARTIAL_SIG", decoded: { signature: "ab" } }, bad("PSBT_IN_TAP_SCRIPT_SIG")],
    ],
  });
  doc.tx.inputs = [0, 1, 2].map((vout) => ({ txid: "11".repeat(32), vout, scriptSig: "", sequence: 0 }));
  const html = psbtVizHtml(doc, "mainnet");
  assert.ok(!html.includes("finalized"), "malformed final scriptSig was labeled finalized");
  assert.ok(!html.includes("2 signatures"), "malformed signatures were counted");
  assert.equal(html.match(/malformed signing field/g).length, 2, "malformed fields not flagged");
  assert.ok(html.includes("1 signature"), "the one decodable signature should still count");
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
// v0 at any other length can never be spent. Notes never block export: BIP350
// says wallets must be able to pay future versions.
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
  assert.equal(witnessProgramNote("51020000").label, "SegWit v1, 2-byte (undefined)", "only 4e73 is P2A");

  const anchor = witnessProgramNote("51024e73");
  assert.equal(anchor.label, "P2A (anchor)");
  assert.equal(anchor.tone, "info");
  assert.equal(anchor.note(3), "Output #3 is a pay-to-anchor (P2A): anyone can spend it, by design, to bump the fee.");

  const burned = witnessProgramNote(program(0, 25));
  assert.equal(burned.label, "SegWit v0, 25-byte (unspendable)");
  assert.equal(burned.tone, "bad");
  assert.equal(burned.note(4), "Output #4 is a 25-byte SegWit v0 program: no one can ever spend it.");
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
