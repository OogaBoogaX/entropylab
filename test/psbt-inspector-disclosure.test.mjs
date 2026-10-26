import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { psbtSignerAuditHtml } from "../src/js/psbt-signer-audit-view.js";

const appSource = readFileSync(fileURLToPath(new URL("../src/js/app.js", import.meta.url)), "utf8");

// Extract a top-level function declaration from app.js, skipping strings and
// comments so a brace inside a message is not counted.
function extractFunction(source, name) {
  const marker = "function " + name + "(";
  const start = source.indexOf(marker);
  if (start === -1) throw new Error("function not found: " + name);
  let depth = 0;
  let mode = null;
  for (let i = source.indexOf("{", start); i < source.length; i++) {
    const c = source[i];
    const next = source[i + 1];
    if (mode === "//") { if (c === "\n") mode = null; continue; }
    if (mode === "/*") { if (c === "*" && next === "/") { mode = null; i++; } continue; }
    if (mode === "'" || mode === '"' || mode === "`") {
      if (c === "\\") { i++; continue; }
      if (c === mode) mode = null;
      continue;
    }
    if (c === "/" && next === "/") { mode = "//"; i++; continue; }
    if (c === "/" && next === "*") { mode = "/*"; i++; continue; }
    if (c === "'" || c === '"' || c === "`") { mode = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return source.slice(start, i + 1); }
  }
  throw new Error("unbalanced braces: " + name);
}

// app.js closes over the page's translator and coders; the tests supply the
// same shapes so one function can be evaluated on its own.
const interpolate = (text, vars = {}) => String(text).replace(/\{(\w+)\}/g, (match, key) => (Object.hasOwn(vars, key) ? String(vars[key]) : match));
const escapeHtml = (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const hexOf = (bytes) => Buffer.from(bytes).toString("hex");
const sats = (value) => (Number(value) / 1e8).toFixed(8);

function evaluate(name, scope) {
  const factory = new Function("scope", "with (scope) { return " + extractFunction(appSource, name) + "; }");
  return factory(scope);
}

const analysisSummary = evaluate("hodlPsbtAnalysisSummary", { hodlT: interpolate, hodlTAttr: (text) => String(text), hodlEscapeHtml: escapeHtml });
const overallLine = evaluate("hodlPsbtOverallLine", { hodlT: interpolate });
// The real nonce row, so a render-level test sees the reason the row carries.
const nonceCheck = evaluate("hodlPsbtNonceCheck", { hodlTText: interpolate });

// A fake element with the DOM surface the extracted functions touch. The
// tests never assert on classes or copy; they read data-* attributes and the
// markup the functions build.
function fakeElement(overrides = {}) {
  const element = {
    open: false,
    innerHTML: "",
    textContent: "",
    value: "",
    id: "",
    hidden: false,
    dataset: {},
    attributes: new Map(),
    inserted: [],
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    style: {},
    hasAttribute(name) { return this.attributes.has(name); },
    getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; },
    setAttribute(name, value) { this.attributes.set(name, String(value)); },
    removeAttribute(name) { this.attributes.delete(name); },
    insertAdjacentHTML(position, html) { this.inserted.push({ position, html }); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    closest() { return null; },
    matches() { return false; },
    contains() { return false; },
    focus() {},
    blur() {},
    scrollIntoView() {},
    remove() {},
    appendChild() {},
    replaceWith() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
    getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; },
  };
  return Object.assign(element, overrides);
}

// ---- analysis rows -------------------------------------------------------

test("a completed analysis row keeps its detail in one collapsed block", () => {
  const html = analysisSummary([
    { label: "Previous outputs and fee", state: "complete", detail: "Amounts came from PSBT claims." },
    { label: "SIGHASH policy", state: "problem", detail: "A malformed policy was found." },
    { label: "Output ownership / derivation", state: "incomplete", detail: "No session key was loaded." },
  ]);
  const completeRow = html.match(/<li data-psbt-check-state='complete'>.*?<\/li>/)[0];
  assert.ok(!completeRow.includes("Amounts came from PSBT claims."), "a completed row must not carry its detail inline");
  const block = html.match(/<details class='derivation-advanced' data-psbt-analysis-details>.*?<\/details>/s)[0];
  assert.ok(block.includes("Amounts came from PSBT claims."), "the completed detail must live in the collapsed block");
  const problemRow = html.match(/<li data-psbt-check-state='problem'>.*?<\/li>/)[0];
  assert.ok(problemRow.includes("A malformed policy was found."), "a problem row keeps its detail inline");
  const incompleteRow = html.match(/<li data-psbt-check-state='incomplete'>.*?<\/li>/)[0];
  assert.ok(incompleteRow.includes("No session key was loaded."), "an incomplete row keeps its detail inline");
});

// ---- the PSBT render -----------------------------------------------------

const scriptA = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x11)]);
const scriptB = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x22)]);

function psbtFixture({ outputs = [{ amount: 50000n, script: scriptA }], inputs = 1 } = {}) {
  return {
    tx: {
      version: 2,
      locktime: 0,
      inputs: Array.from({ length: inputs }, (_, index) => ({ txid: new Uint8Array(32).fill(index + 1), vout: index })),
      outputs,
    },
    inputs: Array.from({ length: inputs }, () => []),
    outputs: outputs.map(() => []),
  };
}

// Every helper hodlRenderPsbt closes over is stubbed here, so an expected
// value is never computed by the code under test.
function renderScope(overrides = {}) {
  return {
    PSBT_RENDER_LIMIT: 500,
    document: { getElementById: () => null },
    hodlT: interpolate,
    hodlTText: interpolate,
    hodlTAttr: (text) => String(text),
    hodlEscapeHtml: escapeHtml,
    hodlHex: { encode: hexOf },
    hodlHexRev: hexOf,
    hodlEq: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
    hodlSats: sats,
    hodlInspectorNetwork: () => "mainnet",
    hodlSessionOwnership: () => new Map(),
    // The same ownership rule the output-ownership warning uses: a script
    // hex lookup with the address fallback.
    matchOwnership: (map, scriptOrAddress) => {
      const key = typeof scriptOrAddress === "string" ? scriptOrAddress : hexOf(scriptOrAddress);
      return { state: map.has(key) ? "ours" : "unknown" };
    },
    hodlPsbtHd: null,
    hodlRenderOutputHtml: (output, index) => "<p class='psbt-kv'>output " + index + "</p>",
    hodlOwnershipWarning: () => "",
    hodlWitUtxo: () => null,
    hodlNonWitUtxo: () => null,
    hodlSighashPolicy: () => null,
    hodlSighashLabel: () => "SIGHASH_ALL",
    hodlPartialSigs: () => [],
    hodlTapSigsParsed: () => [],
    hodlFinalized: () => false,
    hodlAddr: () => "bc1qexample",
    hodlPublicInlineHtml: (text) => escapeHtml(text),
    hodlFind: () => [],
    hodlCompareNonces: () => ({ reused: [], possible: [], crossKey: [] }),
    hodlCompareSchnorrNonces: () => ({ reused: [], incomplete: false }),
    hodlPsbtNonceCheck: () => ({ label: "Nonce analysis", state: "complete", detail: "nonce detail" }),
    hodlPsbtReferenceVerdict: () => ({ state: "complete", problems: [], unlisted: 0 }),
    inspectPsbtInscriptions: () => ({ inputs: [], envelopes: [] }),
    cappedHtml: (items, render) => items.map(render).join(""),
    isP2tr: () => false,
    hodlPsbtAnalysisSummary: analysisSummary,
    hodlPsbtOverallLine: overallLine,
    ...overrides,
  };
}

function renderPsbt(psbt, options = {}, overrides = {}) {
  const render = evaluate("hodlRenderPsbt", renderScope(overrides));
  return render(psbt, new Uint8Array(), "2024-01-01T00:00:00.000Z", "inspect", options);
}

const glanceOf = (html) => html.match(/<p[^>]*data-psbt-glance[^>]*>([\s\S]*?)<\/p>/)[1];

test("the glance line states the total, the output count and the fee", () => {
  const html = renderPsbt(psbtFixture({ outputs: [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }] }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) });
  const glance = glanceOf(html);
  assert.ok(glance.includes("0.00050000"), "the total is the sum of the outputs");
  assert.ok(glance.includes("2 outputs"), "the count is the number of outputs");
  assert.ok(glance.includes("10000"), "the fee is the one the fees section computed");
});

test("the glance line uses the singular for one output", () => {
  const glance = glanceOf(renderPsbt(psbtFixture(), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) }));
  assert.ok(/\b1 output\b/.test(glance));
  assert.ok(!/\b1 outputs\b/.test(glance));
});

test("the glance line says the fee is unknown when it cannot be computed", () => {
  const glance = glanceOf(renderPsbt(psbtFixture()));
  assert.ok(glance.includes("fee unknown"));
  assert.ok(!glance.includes("sats"), "no fee figure is stated when the fee is unknown");
});

test("the glance line names change only when the ownership map claims an output", () => {
  const outputs = [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }];
  const owned = glanceOf(renderPsbt(psbtFixture({ outputs }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }), hodlSessionOwnership: () => new Map([[hexOf(scriptA), {}]]) }));
  assert.ok(owned.includes("0.00030000"), "the change amount is the sum of the outputs the map claims");
  const unowned = glanceOf(renderPsbt(psbtFixture({ outputs }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) }));
  assert.ok(!unowned.includes("0.00030000"), "no change part without an ownership map");
});

test("the glance line uses the Fees section's unit, never sats", () => {
  const html = renderPsbt(psbtFixture(), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) });
  const glance = glanceOf(html);
  assert.ok(glance.includes("0.00010000 BTC"), "the fee is BTC with 8 decimals, as the Fees section shows it");
  assert.ok(!glance.includes("sats"), "no sats in the glance line");
});

test("without a session key the glance line states the outputs total, change included", () => {
  const outputs = [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }];
  const glance = glanceOf(renderPsbt(psbtFixture({ outputs }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) }));
  assert.ok(glance.includes("Outputs total 0.00050000 BTC"), "the total includes every output");
  assert.ok(!glance.includes("Sends"), "no send claim without a key to classify the outputs");
});

test("with a session key the glance line counts only what does not return to the key", () => {
  const outputs = [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }];
  const glance = glanceOf(renderPsbt(psbtFixture({ outputs }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }), hodlSessionOwnership: () => new Map([[hexOf(scriptA), {}]]) }));
  assert.ok(glance.includes("Sends 0.00020000 BTC"), "the owned output is change, not a send");
  assert.ok(!glance.includes("Outputs total"));
});

test("the glance line repeats the Fees section's problem in the same severity", () => {
  const html = renderPsbt(psbtFixture(), {}, { hodlWitUtxo: () => ({ amount: 40000n, script: scriptA }) });
  const glance = glanceOf(html);
  assert.ok(glance.includes("Inconsistent claimed amounts:"), "the same problem the Fees section shows");
  assert.ok(glance.includes("outputs exceed claimed inputs by 0.00010000 BTC"));
  assert.ok(!glance.includes("fee unknown"), "a problem is never softened to fee unknown");
  const fees = html.slice(html.indexOf("Tx fees"));
  assert.ok(fees.includes("Inconsistent claimed amounts:"), "fixture: the Fees section shows the problem");
  // Severity is safety-critical here: the glance must never be calmer than
  // the detail it summarizes. It is carried as data, never read from a class.
  const glanceTag = html.match(/<p[^>]*data-psbt-glance[^>]*>/)[0];
  const severity = glanceTag.match(/data-severity='(\w+)'/);
  assert.ok(severity, "the glance carries its severity as data, not a class");
  assert.equal(severity[1], "bad", "the glance carries the problem's severity");
});

test("the glance line repeats the Fees section's conflicting-UTXO problem in the same severity", () => {
  // One input whose witness UTXO and non-witness UTXO claim different
  // amounts: the Fees section reports the conflict, so the glance must too.
  const html = renderPsbt(psbtFixture(), {}, {
    hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }),
    hodlNonWitUtxo: () => ({ amount: 50000n, script: scriptA }),
  });
  const fees = html.slice(html.indexOf("Tx fees"));
  assert.ok(fees.includes("carry conflicting witness and non-witness UTXO amounts"), "fixture: the Fees section shows the conflict");
  const glance = glanceOf(html);
  assert.ok(glance.includes("carry conflicting witness and non-witness UTXO amounts"), "the glance shows the same problem, not a calm fee unknown");
  const glanceTag = html.match(/<p[^>]*data-psbt-glance[^>]*>/)[0];
  const severity = glanceTag.match(/data-severity='(\w+)'/);
  assert.ok(severity, "the glance carries its severity as data, not a class");
  assert.equal(severity[1], "bad", "in the same severity as the Fees section");
});

test("the inputs section is collapsed when no input has a problem", () => {
  const html = renderPsbt(psbtFixture());
  const tag = html.match(/<details class='derivation-advanced' data-psbt-inputs[^>]*>/)[0];
  assert.ok(!/\bopen\b/.test(tag));
  assert.ok(!tag.includes("data-problem"));
});

test("the inputs section is open and marked when an input has a warning", () => {
  const html = renderPsbt(psbtFixture(), {}, { hodlSighashPolicy: () => { throw new Error("malformed sighash policy"); } });
  const tag = html.match(/<details class='derivation-advanced' data-psbt-inputs[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(tag));
  assert.ok(tag.includes("data-problem='true'"));
});

test("the inputs block has one heading: its summary, with no repeated Tx inputs label inside", () => {
  const html = renderPsbt(psbtFixture());
  const open = html.indexOf("<details class='derivation-advanced' data-psbt-inputs");
  const close = html.indexOf("</details>", open);
  const block = html.slice(open, close);
  assert.ok(block.includes("psbt-section-label"), "the summary carries the section band");
  assert.ok(!block.includes("Tx inputs"), "no repeated inner heading");
  assert.equal((block.match(/psbt-section-label/g) || []).length, 1, "one heading");
});

test("the answer block comes first, ahead of the analysis rows and the sections", () => {
  const html = renderPsbt(psbtFixture(), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) });
  const answer = html.indexOf("data-psbt-answer");
  const glance = html.indexOf("data-psbt-glance");
  const rows = html.indexOf("data-psbt-check-state");
  const outputs = html.indexOf("Tx outputs");
  assert.ok(answer >= 0 && glance > answer, "the glance line sits inside the answer block");
  assert.ok(answer < rows, "the answer block comes before the analysis rows");
  assert.ok(rows < outputs, "the analysis rows come before the sections");
});

test("the signer audit is inserted after the answer block, never above it", () => {
  const answer = fakeElement();
  const output = fakeElement({ querySelector: (selector) => (selector === "[data-psbt-answer]" ? answer : null) });
  const paintSignerAudit = evaluate("hodlPsbtPaintSignerAudit", { hodlPsbtSignerAuditMarkup: () => "AUDIT", hodlPsbtInsertOverall: () => {} });
  const prepend = evaluate("hodlPsbtPrependSignerAudit", {
    document: { getElementById: (id) => (id === "psbt-audit-before" ? { value: "SENT" } : null) },
    hodlPsbtBytesFromText: () => new Uint8Array([0x70]),
    isPsbtMagic: () => true,
    psbtInspectDoc: () => ({}),
    hodlPsbtSignerAuditVerify: () => undefined,
    hodlAuditSigner: () => ({ verdict: "pass" }),
    hodlPsbtSignerAuditMarkup: () => "AUDIT",
    hodlPsbtInsertOverall: () => {},
    hodlPsbtPaintSignerAudit: paintSignerAudit,
  });
  prepend(output, new Uint8Array([0x70]), "psbt", "mainnet");
  assert.equal(answer.inserted.length, 1, "the audit goes after the answer block");
  assert.equal(answer.inserted[0].position, "afterend");
  assert.equal(answer.inserted[0].html, "AUDIT");
  assert.equal(output.inserted.length, 0, "nothing is inserted above the answer block");
});

test("the folding decision reads data-problem, never the rendered class names", () => {
  for (const name of ["hodlRenderPsbt", "hodlPsbtShowMore"]) {
    const source = extractFunction(appSource, name);
    assert.ok(!/\.includes\(\s*["']psbt-(bad|warn)["']\s*\)/.test(source), `${name} must not decide folding from psbt-bad/psbt-warn`);
  }
});

// The 2-of-3 multisig shape: one input carries a Taproot signature, the other
// carries none, so signing is expected and the unsigned input is a problem.
const tapSigFixture = { r: new Uint8Array(32).fill(1), s: new Uint8Array(32).fill(2), sighash: 0, source: "tap-key", pubkey: new Uint8Array(), leafHash: null };
const multisigPsbt = () => {
  const psbt = psbtFixture({ inputs: 2 });
  psbt.inputs = [[{ type: 0x13 }], []];
  return psbt;
};
const multisigScope = {
  hodlTapSigsParsed: (entries) => (entries.length ? [tapSigFixture] : []),
  hodlTapSighashProblems: () => [],
};

test("an unsigned input where signing is expected carries data-problem and stays open", () => {
  const html = renderPsbt(multisigPsbt(), {}, multisigScope);
  const tag = html.match(/<details class='derivation-advanced' data-psbt-inputs[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(tag), "the block is open");
  assert.ok(tag.includes("data-problem='true'"), "the block carries the problem flag");
  const sections = html.split("<p class='psbt-kv'").slice(1);
  const unsigned = sections.find((section) => section.includes("Not signed yet"));
  assert.ok(unsigned, "fixture: one input is unsigned");
  assert.ok(unsigned.startsWith(" data-problem='true'"), "the unsigned input carries the problem flag");
  const signed = sections.find((section) => section.includes("signature(s) present"));
  assert.ok(signed && !signed.startsWith(" data-problem='true'"), "the signed input carries no problem flag");
});

test("the glance line states the signing progress when an input carries a signature", () => {
  const glance = glanceOf(renderPsbt(multisigPsbt(), {}, multisigScope));
  assert.ok(glance.includes("1 of 2 inputs signed"));
});

test("Show more renders inside the collapsed inputs block", () => {
  const html = renderPsbt(psbtFixture({ inputs: 3 }), { limits: { inputs: 1, outputs: 5, step: 1, format: String } });
  const open = html.indexOf("<details class='derivation-advanced' data-psbt-inputs");
  const close = html.indexOf("</details>", open);
  const button = html.indexOf("data-psbt-more='inputs'");
  assert.ok(open >= 0 && close > open);
  assert.ok(button > open && button < close, "the Show more button sits inside the inputs block");
});

test("Show more still renders a chunk and a tail for the inputs", () => {
  // The window must reach past `from`, as Show more's own repaint passes it
  // (see psbt-viz.test.mjs: limits.inputs above only.from).
  const part = renderPsbt(psbtFixture({ inputs: 3 }), { limits: { inputs: 2, outputs: 5, step: 1, format: String }, only: { kind: "inputs", from: 1 } });
  assert.equal(typeof part, "object");
  assert.ok(part.chunk.length > 0, "the new input section is rendered");
  assert.ok(!part.chunk.includes("data-psbt-inputs"), "the chunk joins the existing block, it does not open a second one");
  assert.ok(part.tail.includes("data-psbt-more='inputs'"), "the tail still carries the button");
});

// ---- Show more against a fake DOM ---------------------------------------

function showMoreHarness(render) {
  const tail = fakeElement();
  const generic = fakeElement();
  let details = fakeElement();
  let html = "";
  const output = fakeElement({
    querySelector(selector) {
      if (selector === "[data-psbt-inputs]") return details;
      if (selector === "[data-psbt-tail='inputs']") return tail;
      if (selector === "[data-psbt-tail='outputs']") return null;
      return generic;
    },
  });
  Object.defineProperty(output, "innerHTML", {
    get: () => html,
    set: (value) => { html = value; details = fakeElement(); },
  });
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array(), checkedAt: "", network: "mainnet", limits: { inputs: 1, outputs: 1, step: 1 }, audit: null };
  const button = { dataset: { psbtMore: "inputs" } };
  const event = { target: { closest: (selector) => (selector === "[data-psbt-more]" ? button : null) } };
  const scope = {
    hodlPsbtLast: last,
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlRenderPsbt: render,
    hodlRenderRawTx: render,
    hodlPsbtSignerAuditMarkup: () => "",
    hodlPsbtInsertOverall: () => {},
    hodlT: interpolate,
    hodlTText: interpolate,
    hodlTAttr: (text) => String(text),
    hodlEscapeHtml: escapeHtml,
  };
  return { scope, output, tail, event, last, get details() { return details; } };
}

test("Show more keeps the inputs block open across a repaint", () => {
  const harness = showMoreHarness(() => "<p>repainted</p>");
  harness.details.open = true;
  const showMore = evaluate("hodlPsbtShowMore", harness.scope);
  showMore(harness.event);
  assert.equal(harness.details.open, true, "the repaint must reopen the block the user had open");
});

test("Show more opens the inputs block when the new chunk carries a problem", () => {
  const harness = showMoreHarness(() => ({ chunk: "<p class='psbt-kv' data-problem='true'>problem</p>", tail: "" }));
  const showMore = evaluate("hodlPsbtShowMore", harness.scope);
  showMore(harness.event);
  assert.equal(harness.details.open, true);
  assert.equal(harness.details.hasAttribute("data-problem"), true);
});

test("Show more does not open the inputs block for a chunk that only carries a class name", () => {
  const harness = showMoreHarness(() => ({ chunk: "<p class='psbt-warn'>warning</p>", tail: "" }));
  const showMore = evaluate("hodlPsbtShowMore", harness.scope);
  showMore(harness.event);
  assert.equal(harness.details.open, false, "the class name alone decides nothing");
  assert.equal(harness.details.hasAttribute("data-problem"), false);
});

// ---- the signer audit ----------------------------------------------------

const passChecks = {
  transactionBody: "unchanged",
  utxoDeclarations: "unchanged",
  signatures: "none_added",
  sighashPolicy: "none",
  signerKeys: "no_new_signatures",
  metadata: "unchanged",
  nonceReuse: "not_checked",
  antiExfil: "not_available",
  changeOutputs: "not_checked",
};

test("the audit checks block is closed when the tier is pass", () => {
  const html = psbtSignerAuditHtml({ verdict: "pass", checks: passChecks, findings: [], stats: { newSignatures: 0 } }, null, null, "mainnet");
  const tag = html.match(/<details class="derivation-advanced" data-audit-checks[^>]*>/)[0];
  assert.ok(!/\bopen\b/.test(tag));
  assert.ok(!tag.includes("data-has-problem"));
});

test("the audit checks block is open when the tier is not pass", () => {
  const failed = psbtSignerAuditHtml({ verdict: "fail", checks: passChecks, findings: [], stats: { newSignatures: 0 } }, null, null, "mainnet");
  const failedTag = failed.match(/<details class="derivation-advanced" data-audit-checks[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(failedTag));
  assert.ok(failedTag.includes("data-has-problem"));
  const warned = psbtSignerAuditHtml({ verdict: "pass", checks: passChecks, findings: [{ code: "METADATA_ADDED", severity: "warning", evidence: {} }], stats: { newSignatures: 0 } }, null, null, "mainnet");
  const warnedTag = warned.match(/<details class="derivation-advanced" data-audit-checks[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(warnedTag));
  assert.ok(warnedTag.includes("data-has-problem"));
});

// ---- the overall line ----------------------------------------------------

const insertOverall = evaluate("hodlPsbtInsertOverall", { hodlT: interpolate });

function overallHarness({ tier, analysis }) {
  const section = fakeElement({ dataset: tier ? { auditTier: tier } : {} });
  const analysisElement = analysis ? { dataset: { psbtAnalysisOverall: analysis } } : null;
  const output = fakeElement({
    querySelector(selector) {
      if (selector === "[data-audit-section]") return section;
      if (selector === "[data-psbt-analysis-overall]") return analysisElement;
      return null;
    },
  });
  return { output, section };
}

const overallState = (options) => {
  const { output, section } = overallHarness(options);
  insertOverall(output);
  if (!section.inserted.length) return null;
  assert.equal(section.inserted[0].position, "beforebegin");
  return section.inserted[0].html.match(/data-psbt-overall-state='(\w+)'/)[1];
};

test("the overall line is red when the audit fails", () => {
  assert.equal(overallState({ tier: "fail", analysis: "complete" }), "bad");
  assert.equal(overallState({ tier: "pass", analysis: "problem" }), "bad");
});

test("the overall line is green only when the audit passes and the analysis is complete", () => {
  assert.equal(overallState({ tier: "pass", analysis: "complete" }), "ok");
});

test("the overall line is amber otherwise", () => {
  assert.equal(overallState({ tier: "pass-warnings", analysis: "complete" }), "warn");
  assert.equal(overallState({ tier: "pass", analysis: "incomplete" }), "warn");
});

test("no overall line without an audit", () => {
  assert.equal(overallState({ tier: undefined, analysis: "complete" }), null);
});

test("with no key loaded and no other problem the overall line is not amber", () => {
  const html = renderPsbt(psbtFixture(), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) });
  const state = html.match(/data-psbt-analysis-overall='(\w+)'/)[1];
  assert.equal(state, "complete", "the no-key ownership check does not count");
  assert.ok(!html.includes("ANALYSIS INCOMPLETE"));
});

test("a check incomplete for any other reason still makes the overall line amber", () => {
  // No UTXO claim: the fee check could not run, so it counts.
  const html = renderPsbt(psbtFixture());
  const state = html.match(/data-psbt-analysis-overall='(\w+)'/)[1];
  assert.equal(state, "incomplete");
});

// The audit fixture's shape: one P2WPKH input signed by one key, no session
// key loaded. One signature is all the nonce check has, so its only gap is
// the count — the case the owner ruled must not turn the overall line amber.
const oneSignatureScope = (overrides = {}) => ({
  hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }),
  hodlPartialSigs: () => [{ der: new Uint8Array([0x30, 0x44]), pubkey: new Uint8Array(33).fill(2), sighash: 1, raw: new Uint8Array([1]) }],
  hodlSigParts: () => ({ r: new Uint8Array(32).fill(1), s: new Uint8Array(32).fill(2) }),
  hodlInputScriptCode: () => new Uint8Array([0x76, 0xa9]),
  hodlScriptHasCodeSeparator: () => false,
  hodlBip143: () => new Uint8Array(32).fill(3),
  hodlSecp256k1: { verify: () => true },
  hodlPrivForPub: () => ({ key: new Uint8Array(32).fill(4), owned: true }),
  hodlRfc6979Compare: () => ({ ok: true, message: "", className: "psbt-ok" }),
  hodlCompressedPubkey: () => new Uint8Array(33).fill(2),
  hodlPsbtMasterFingerprint: () => "00000000",
  hodlPsbtDerivationFingerprints: () => ({}),
  hodlSighashProblems: () => [],
  hodlPsbtNonceCheck: nonceCheck,
  ...overrides,
});

test("a single-signature PSBT whose only nonce gap is the count is not amber", () => {
  const html = renderPsbt(psbtFixture(), {}, oneSignatureScope());
  const state = html.match(/data-psbt-analysis-overall='(\w+)'/)[1];
  assert.equal(state, "complete", "one signature is nothing to compare, not a coverage gap");
  assert.ok(!html.includes("ANALYSIS INCOMPLETE"));
  assert.ok(html.includes("data-incomplete-reason='nothing-to-compare'"), "the row carries the reason");
  // The row itself still reads Incomplete: only the overall line ignores it.
  assert.ok(/<li data-psbt-check-state='incomplete' data-incomplete-reason='nothing-to-compare'>/.test(html));
});

test("a single-signature PSBT with an unsupported signature still counts", () => {
  // The input script is one this inspection cannot rebuild a digest for, so
  // the signature really is unchecked: a coverage gap, not "nothing to
  // compare". The missing session key alone must not hide it either.
  const html = renderPsbt(psbtFixture(), {}, oneSignatureScope({ hodlPrivForPub: () => null, hodlPrivFromPath: () => null, hodlInputScriptCode: () => null }));
  const state = html.match(/data-psbt-analysis-overall='(\w+)'/)[1];
  assert.equal(state, "incomplete", "a signature that could not be checked is a real coverage gap");
  assert.ok(!html.includes("data-incomplete-reason='nothing-to-compare'"));
});

test("the audit fixture shows no amber overall line above a green audit verdict", () => {
  const html = renderPsbt(psbtFixture(), {}, oneSignatureScope());
  const analysis = html.match(/data-psbt-analysis-overall='(\w+)'/)[1];
  assert.equal(overallState({ tier: "pass", analysis }), "ok");
});

// The signer-audit fixture (returnedClean): one P2WPKH input signed by one
// key with SIGHASH_ALL, a witness_utxo, and no session key loaded. Its only
// nonce gap is that one signature has nothing to compare with; the missing
// session key blocks RFC 6979 but is not a gap in the file.
test("the audit fixture's single signature with no key is nothing to compare", () => {
  const html = renderPsbt(psbtFixture(), {}, oneSignatureScope({ hodlPrivForPub: () => null, hodlPrivFromPath: () => null }));
  const state = html.match(/data-psbt-analysis-overall='(\w+)'/)[1];
  assert.notEqual(state, "incomplete", "one signature with no key is nothing to compare, not a coverage gap");
  assert.ok(!html.includes("ANALYSIS INCOMPLETE"));
  const nonceRow = html.split("<li ").find((row) => row.includes("Nonce analysis"));
  assert.ok(nonceRow, "the Nonce row is rendered");
  assert.ok(nonceRow.startsWith("data-psbt-check-state='incomplete'"), "the row still reads Incomplete");
  assert.ok(nonceRow.includes("data-incomplete-reason='nothing-to-compare'"), "the row carries the reason");
});

test("the glance line counts an output the ownership warning treats as ours", () => {
  const outputs = [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }];
  // The map holds the address form only: the script-hex lookup misses, the
  // address fallback the ownership warning uses is what finds it.
  const map = new Map([["addr-" + hexOf(scriptA), {}]]);
  const matchOwnership = (ownership, scriptOrAddress) => {
    const key = typeof scriptOrAddress === "string" ? scriptOrAddress : hexOf(scriptOrAddress);
    return { state: ownership.has(key) ? "ours" : "unknown" };
  };
  const html = renderPsbt(psbtFixture({ outputs }), {}, {
    hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }),
    hodlSessionOwnership: () => map,
    matchOwnership,
    hodlAddr: (script) => "addr-" + hexOf(script),
  });
  const glance = glanceOf(html);
  assert.ok(glance.includes("0.00030000"), "the output the warning treats as ours counts as change");
  assert.ok(glance.includes("Sends 0.00020000 BTC"), "and it is not counted as a send");
});
