// Offline payjoin detection UI (issue #446, BIP-78/77): the shared builders
// and card wiring in src/js/psbt-payjoin.js, plus their hookup in the
// PSBT / Nonce inspector (app.js) and the PSBT editor (psbt-editor.js).
// Fixtures mirror the crate's own payjoin tests (psbt-wasm/src/payjoin.rs):
// a signed 1-in/2-out Original and a clean BIP-78 proposal that inserts one
// finalized receiver input. Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc, psbtPayjoinCompare } from "../src/js/psbt-wasm.js";
import {
  psbtPayjoinBytesFromText,
  psbtPayjoinPaymentScriptFromText,
  psbtPayjoinSignalsHtml,
  psbtPayjoinReportHtml,
  initPsbtPayjoinCompare,
} from "../src/js/psbt-payjoin.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// --- Fixtures (the Rust test vectors, rebuilt byte for byte) ----------------

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const le32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const le64 = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const varint = (n) => {
  assert.ok(n < 0xfd, "fixtures stay below the compact-size marker");
  return Uint8Array.of(n);
};
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));

const PAYMENT = 0xaa, SENDER_SPK = 0xbb, CHANGE = 0xcc, RECEIVER_SPK = 0xee;
const spk = (byte) => Uint8Array.of(0x00, 0x14, ...Array(20).fill(byte));
const txin = (txidByte, vout) => concat([Uint8Array.from(Array(32).fill(txidByte)), le32(vout), varint(0), le32(0xfffffffd)]);
const txout = (sats, script) => concat([le64(sats), varint(script.length), script]);
const tx = (inputs, outputs) => concat([le32(2), varint(inputs.length), ...inputs, varint(outputs.length), ...outputs, le32(0)]);

const pair = (key, value) => concat([varint(key.length), key, varint(value.length), value]);
const witnessUtxo = (sats, script) => pair(Uint8Array.of(0x01), concat([le64(sats), varint(script.length), script]));
const finalWitness = pair(Uint8Array.of(0x08), Uint8Array.of(0x01, 0x00));
const psbt = (txBytes, inputMaps, outputCount) =>
  concat([
    Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]),
    pair(Uint8Array.of(0x00), txBytes),
    Uint8Array.of(0x00),
    ...inputMaps.map((map) => concat([...map, Uint8Array.of(0x00)])),
    ...Array.from({ length: outputCount }, () => Uint8Array.of(0x00)),
  ]);

// Original: one sender input (100k) paying 50k to PAYMENT and 40k change.
const originalBytes = psbt(
  tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
  [[witnessUtxo(100_000, spk(SENDER_SPK)), finalWitness]],
  2,
);
// Clean proposal: the sender input stripped, a finalized receiver input (30k)
// inserted after it, the payment output grown, change reduced by the +1k fee.
const proposalBytes = psbt(
  tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
  [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness]],
  2,
);
const paymentScriptHex = toHex(spk(PAYMENT));

const flush = () => new Promise((resolve) => setImmediate(resolve));

// --- Paste-box and payment-script parsing -----------------------------------

test("the proposal box accepts hex and base64 like the neighboring paste boxes", () => {
  assert.deepEqual(psbtPayjoinBytesFromText(toHex(proposalBytes)), proposalBytes);
  assert.deepEqual(psbtPayjoinBytesFromText(toHex(proposalBytes).toUpperCase()), proposalBytes);
  assert.deepEqual(psbtPayjoinBytesFromText(`\n ${toB64(proposalBytes)} \n`), proposalBytes);
  assert.throws(() => psbtPayjoinBytesFromText(""), /Paste a Payjoin Proposal PSBT/);
  assert.throws(() => psbtPayjoinBytesFromText("not a psbt at all"), /base64 or hex/);
});

test("the payment script is optional hex", () => {
  assert.equal(psbtPayjoinPaymentScriptFromText(""), null);
  assert.equal(psbtPayjoinPaymentScriptFromText("  \n"), null);
  assert.deepEqual(psbtPayjoinPaymentScriptFromText(paymentScriptHex), spk(PAYMENT));
  assert.throws(() => psbtPayjoinPaymentScriptFromText("abc"), /must be hex/);
  assert.throws(() => psbtPayjoinPaymentScriptFromText("zz"), /must be hex/);
});

// --- Single-file signals ------------------------------------------------------

test("the inspect document's payjoin signals render as signals, never a verdict", () => {
  const doc = psbtInspectDoc(proposalBytes);
  assert.equal(doc.payjoin.proposalShape, true);
  assert.deepEqual(doc.payjoin.candidateReceiverInputs, [1]);
  const html = psbtPayjoinSignalsHtml({ proposalShape: true, candidateReceiverInputs: [1, 3], originGroups: 2, multiWallet: true, signal: true });
  assert.match(html, /aria-label="/, "the section names itself for assistive technology");
  assert.match(html, /1, 3/, "the candidate receiver input indices are shown");
  assert.match(html, /never a verdict/);
  assert.doesNotMatch(html, /safe to sign|this is a payjoin\b/i);
});

test("a PSBT without the proposal shape renders the quiet state", () => {
  const doc = psbtInspectDoc(originalBytes);
  assert.equal(doc.payjoin.signal, false);
  const html = psbtPayjoinSignalsHtml(doc.payjoin);
  assert.match(html, /never a verdict/);
  assert.equal(psbtPayjoinSignalsHtml(null), "");
  assert.equal(psbtPayjoinSignalsHtml(undefined), "");
});

// --- Two-file checklist report -------------------------------------------------

test("a clean proposal renders receiver inputs, contribution, fee and the complete checklist", () => {
  const report = psbtPayjoinCompare({ original: originalBytes, proposal: proposalBytes, paymentScript: spk(PAYMENT) });
  assert.equal(report.payjoin, true);
  assert.deepEqual(report.receiverInputs, [1]);
  assert.equal(report.receiverContribution, "30000");
  assert.equal(report.checklist, "complete");
  const html = psbtPayjoinReportHtml(report);
  assert.match(html, /aria-label="/);
  assert.match(html, /30000/, "receiver contribution");
  assert.match(html, /10000/, "fee before");
  assert.match(html, /11000/, "fee after");
  // Six fact rows, two value-change sub-items (payment grew, change shrank),
  // and the single finding (the change reduction) as one list item each.
  assert.equal((html.match(/<li>/g) || []).length, 6 + 2 + 1);
});

test("substitution renders unconfirmed without the payment script and confirmed with it", () => {
  const swapped = psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(0xdd)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness]],
    2,
  );
  const unconfirmed = psbtPayjoinCompare({ original: originalBytes, proposal: swapped });
  assert.equal(unconfirmed.substitution.paymentOutputConfirmed, false);
  assert.match(psbtPayjoinReportHtml(unconfirmed), /original output 0/);
  const confirmed = psbtPayjoinCompare({ original: originalBytes, proposal: swapped, paymentScript: spk(PAYMENT) });
  assert.equal(confirmed.substitution.paymentOutputConfirmed, true);
  assert.match(psbtPayjoinReportHtml(confirmed), /original output 0/);
});

test("a checklist violation renders every problem as its own list item", () => {
  // The proposal drops the sender's input: an error-level violation.
  const dropped = psbt(
    tx([txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness]],
    2,
  );
  const report = psbtPayjoinCompare({ original: originalBytes, proposal: dropped });
  assert.equal(report.checklist, "problem");
  const errors = report.problems.filter((problem) => problem.severity === "error");
  assert.ok(errors.length >= 1);
  const html = psbtPayjoinReportHtml(report);
  const escaped = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  for (const problem of report.problems) {
    assert.ok(html.includes(escaped(problem.message)), `problem listed: ${problem.code}`);
    assert.ok(html.includes(escaped(problem.scope)), `scope listed: ${problem.code}`);
  }
});

test("unknown fees leave the checklist incomplete, never a success", () => {
  const noClaims = psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[finalWitness]],
    2,
  );
  const report = psbtPayjoinCompare({ original: noClaims, proposal: proposalBytes });
  assert.equal(report.checklist, "incomplete");
  assert.equal(report.fee.original, null);
  const html = psbtPayjoinReportHtml(report);
  assert.match(html, /unknown/);
});

test("the rendered report escapes hostile values — it is never an HTML sink", () => {
  const hostile = {
    payjoin: true,
    receiverInputs: [0],
    receiverContribution: '<img src=x onerror=alert(1)>',
    substitution: { originalOutput: 0, paymentOutputConfirmed: false },
    addedOutputs: [0],
    valueChanges: [{ originalOutput: 0, proposalOutput: 0, before: "<script>alert(1)</script>", after: "1" }],
    fee: { original: "<svg onload=alert(1)>", proposal: "2" },
    checklist: "problem",
    problems: [{ severity: "error", scope: '<img src=x onerror=alert(1)>', code: "x", message: "<script>alert(1)</script>" }],
    problemsTruncated: false,
  };
  const html = psbtPayjoinReportHtml(hostile);
  assert.doesNotMatch(html, /<img|<script>|<svg/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /&lt;svg/);
});

// --- Card wiring (hand-rolled DOM stubs) ---------------------------------------

const stubDom = (prefix) => {
  const elements = {};
  for (const part of ["text", "script", "go", "clear", "out", "error"]) {
    const listeners = {};
    elements[`${prefix}-${part}`] = {
      value: "",
      textContent: "",
      innerHTML: "",
      addEventListener: (type, fn) => {
        (listeners[type] ||= []).push(fn);
      },
      dispatch: (type) => {
        for (const fn of listeners[type] || []) fn();
      },
    };
  }
  globalThis.document = { getElementById: (id) => elements[id] || null };
  return elements;
};

const payjoinIds = (prefix) => ({
  text: `${prefix}-text`,
  script: `${prefix}-script`,
  go: `${prefix}-go`,
  clear: `${prefix}-clear`,
  out: `${prefix}-out`,
  error: `${prefix}-error`,
});

test("the compare card runs psbtPayjoinCompare and renders the report", async () => {
  const els = stubDom("pj");
  const card = initPsbtPayjoinCompare({ ids: payjoinIds("pj"), originalBytes: () => originalBytes });
  assert.ok(card, "all controls present, so the card wires");
  els["pj-text"].value = toHex(proposalBytes);
  els["pj-script"].value = paymentScriptHex;
  els["pj-go"].dispatch("click");
  await flush();
  assert.equal(els["pj-error"].textContent, "");
  assert.match(els["pj-out"].innerHTML, /30000/);
  assert.match(els["pj-out"].innerHTML, /11000/);
  // Clear empties the fields and the report.
  els["pj-clear"].dispatch("click");
  assert.equal(els["pj-text"].value, "");
  assert.equal(els["pj-script"].value, "");
  assert.equal(els["pj-out"].innerHTML, "");
});

test("the compare card accepts a base64 proposal", async () => {
  const els = stubDom("pj");
  initPsbtPayjoinCompare({ ids: payjoinIds("pj"), originalBytes: () => originalBytes });
  els["pj-text"].value = toB64(proposalBytes);
  els["pj-go"].dispatch("click");
  await flush();
  assert.equal(els["pj-error"].textContent, "");
  assert.match(els["pj-out"].innerHTML, /30000/);
});

test("failures land whole in the card's error element — no partial render", async () => {
  const els = stubDom("pj");
  initPsbtPayjoinCompare({ ids: payjoinIds("pj"), originalBytes: () => originalBytes });
  // A malformed proposal.
  els["pj-text"].value = "not a psbt at all";
  els["pj-go"].dispatch("click");
  await flush();
  assert.match(els["pj-error"].textContent, /base64 or hex/);
  assert.equal(els["pj-out"].innerHTML, "");
  // A malformed payment script.
  els["pj-text"].value = toHex(proposalBytes);
  els["pj-script"].value = "xyz";
  els["pj-go"].dispatch("click");
  await flush();
  assert.match(els["pj-error"].textContent, /must be hex/);
  assert.equal(els["pj-out"].innerHTML, "");
  // An unreadable original (the tool's own box is empty).
  const els2 = stubDom("pj");
  initPsbtPayjoinCompare({
    ids: payjoinIds("pj"),
    originalBytes: () => {
      throw new Error("Paste a PSBT v0 or a raw Bitcoin transaction.");
    },
  });
  els2["pj-text"].value = toHex(proposalBytes);
  els2["pj-go"].dispatch("click");
  await flush();
  assert.match(els2["pj-error"].textContent, /Paste a PSBT/);
  assert.equal(els2["pj-out"].innerHTML, "");
  // A raw transaction as the original is rejected by the comparison itself.
  const els3 = stubDom("pj");
  initPsbtPayjoinCompare({ ids: payjoinIds("pj"), originalBytes: () => tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT))]) });
  els3["pj-text"].value = toHex(proposalBytes);
  els3["pj-go"].dispatch("click");
  await flush();
  assert.ok(els3["pj-error"].textContent.length > 0, "the WASM rejection is shown");
  assert.equal(els3["pj-out"].innerHTML, "");
});

test("a missing control leaves the card unwired rather than throwing", () => {
  globalThis.document = { getElementById: () => null };
  assert.equal(initPsbtPayjoinCompare({ ids: payjoinIds("pj"), originalBytes: () => originalBytes }), null);
});

// --- Markup and wiring contracts ------------------------------------------------

test("the inspector carries the payjoin card and app.js wires it", () => {
  const shell = read("src/shell.html");
  const app = read("src/js/app.js");
  assert.match(shell, /<section class="tool-section" aria-labelledby="psbt-payjoin-heading">/);
  assert.match(shell, /<h3 id="psbt-payjoin-heading">/);
  for (const id of ["psbt-payjoin-text", "psbt-payjoin-script", "psbt-payjoin-go", "psbt-payjoin-clear", "psbt-payjoin-error", "psbt-payjoin-out"]) {
    assert.match(shell, new RegExp(`id="${id}"`), `shell carries #${id}`);
    assert.match(app, new RegExp(`"${id}"`), `app.js wires #${id}`);
  }
  assert.match(shell, /<p class="err" id="psbt-payjoin-error" role="alert"><\/p>/);
  assert.match(app, /initPsbtPayjoinCompare\(\{/);
  assert.match(app, /originalBytes: \(\) => hodlPsbtBytes\(document\.getElementById\("psbt-text"\)\.value\)/);
  // The wipe path clears the card with the rest of the tool, and editing the
  // original in the paste box invalidates a rendered report.
  assert.match(app, /payjoin\.clearAll\(\)/);
  assert.match(app, /payjoin\?\.clearReport\(\)/);
});

test("the inspector renders the single-file signals after a successful inspect", () => {
  const app = read("src/js/app.js");
  assert.match(app, /import \{ psbtInspectDoc, psbtWasmReady \} from "\.\/psbt-wasm\.js";/);
  assert.match(app, /import \{ psbtPayjoinSignalsHtml, initPsbtPayjoinCompare \} from "\.\/psbt-payjoin\.js";/);
  assert.match(app, /id="psbt-payjoin-signals"/);
  assert.match(app, /psbtPayjoinSignalsHtml\(psbtInspectDoc\(bytes\)\.payjoin\)/);
});

test("the editor renders the signals and wires its own payjoin card", () => {
  const shell = read("src/shell.html");
  const editor = read("src/js/psbt-editor.js");
  assert.match(shell, /<section class="psbted-compare" id="psbted-payjoin">/);
  for (const id of ["psbted-payjoin-text", "psbted-payjoin-script", "psbted-payjoin-go", "psbted-payjoin-clear", "psbted-payjoin-error", "psbted-payjoin-out"]) {
    assert.match(shell, new RegExp(`id="${id}"`), `shell carries #${id}`);
    assert.match(editor, new RegExp(`"${id}"`), `psbt-editor.js wires #${id}`);
  }
  assert.match(editor, /psbtPayjoinSignalsHtml\(doc\.payjoin\)/);
  assert.match(editor, /initPsbtPayjoinCompare\(\{/);
  // The original side is the editor's current build, not the textarea text.
  assert.match(editor, /return psbtBuildBytes\(psbtEditorBuildDoc\(doc\), \{ insane \}\);/);
  // Loading a different PSBT invalidates an old report, as with the diff.
  assert.match(editor, /payjoin\?\.clearReport\(\);/);
  assert.match(editor, /payjoin\?\.clearAll\(\);/);
});

test("the shared module compares through the WASM binding and escapes report values", () => {
  const payjoin = read("src/js/psbt-payjoin.js");
  assert.match(payjoin, /import \{ psbtPayjoinCompare, psbtWasmReady \} from "\.\/psbt-wasm\.js";/);
  assert.match(payjoin, /report = psbtPayjoinCompare\(\{/);
  assert.match(payjoin, /escapeHtml\(problem\.scope\)/);
  assert.match(payjoin, /escapeHtml\(problem\.message\)/);
  // Framing, in source: signals and the checklist disclaim the verdict.
  assert.match(payjoin, /never a verdict/);
  assert.match(payjoin, /Nothing here contacts a pj= endpoint or directory/);
});
