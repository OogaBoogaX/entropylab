// Rendering tests for the PSBT Signer Audit view (src/js/psbt-signer-audit-view.js).
//
// The expected wording is the approved UI plan's per-code lines (the
// specification for this feature), asserted as short stable substrings;
// structural hooks are data-audit-* attributes, never classes. The check
// tones come from the same approved table. The diff-caption expectations
// pin the documented editor default ("before = the PSBT in the editor ·
// after = the pasted PSBT.") against the new optional labels.
// Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { SIGNER_AUDIT_CODES } from "../src/js/psbt-signer-audit.js";
import { comparePsbtDocs } from "../src/js/psbt-diff.js";
import { psbtSignerAuditVerification } from "../src/js/psbt-signer-audit-verify.js";
import { psbtDiffHtml } from "../src/js/psbt-editor.js";
import { psbtSignerAuditErrorHtml, psbtSignerAuditHtml } from "../src/js/psbt-signer-audit-view.js";

const P1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SCRIPT = "0014" + "22".repeat(20);

const INFO_CODES = new Set(["SIGNATURE_ADDED", "FINALIZED", "METADATA_ENRICHMENT", "CHANGE_VERIFIED"]);
const WARNING_CODES = new Set(["METADATA_CHANGED", "MUSIG2_MATERIAL_ADDED", "METADATA_ADDED", "SIGHASH_DECLARATION_INVALID", "CHANGE_UNVERIFIED", "NONCE_REUSE_POSSIBLE", "NONCE_COVERAGE_INCOMPLETE", "ORIGIN_INCONSISTENT"]);

// One minimal finding per code, carrying the evidence shape the engine
// emits for it (src/js/psbt-signer-audit.js).
const findingFor = (code) => {
  const evidence = {
    DOC_UNDECODABLE: { side: "after", reason: "rust_bitcoin_error" },
    TX_REORDERED: { dimension: "outputs", order: [1, 0] },
    TX_INPUT_CHANGED: { index: 0, field: "input[0].txid", kind: "changed", before: "aa".repeat(32), after: "bb".repeat(32) },
    TX_OUTPUT_CHANGED: { index: 1, field: "output[1].value", kind: "changed", before: 100000, after: 99000 },
    TX_VERSION_CHANGED: { field: "version", kind: "changed", before: 2, after: 1 },
    TX_LOCKTIME_CHANGED: { field: "locktime", kind: "changed", before: 0, after: 800000 },
    UTXO_DECLARATION_CHANGED: { index: 0, name: "PSBT_IN_WITNESS_UTXO", kind: "changed", beforeValue: 150000, afterValue: 149000 },
    UNEXPECTED_SIGNER: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, expectedKeys: [P1] },
    SIGNATURE_CHANGED: { index: 0, name: "PSBT_IN_PARTIAL_SIG" },
    SIGNATURE_REMOVED: { index: 0, name: "PSBT_IN_PARTIAL_SIG" },
    SIGNATURE_MALFORMED: { index: 0, name: "PSBT_IN_PARTIAL_SIG", decodeError: "signature is too short" },
    SIGNATURE_INVALID: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1 },
    SIGNATURE_UNVERIFIED: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, reason: "budget_exhausted" },
    SIGHASH_WEAK: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, appended: 2 },
    SIGHASH_MISMATCH: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, appended: 2, declared: 1, source: "original" },
    SIGHASH_UNDEFINED: { index: 0, source: "appended", value: 4 },
    SIGHASH_DECLARATION_CHANGED: { index: 0, before: "01000000", after: "02000000" },
    SIGHASH_DECLARATION_ADDED: { index: 0, value: 2 },
    SIGHASH_DECLARATION_INVALID: { index: 0 },
    FINALIZATION_INVALID: { index: 0, reason: "signature_invalid", removedFields: ["PSBT_IN_PARTIAL_SIG"] },
    FINALIZED: { index: 0, finalFields: ["PSBT_IN_FINAL_SCRIPTWITNESS"], removedFields: ["PSBT_IN_PARTIAL_SIG"], signatures: 1 },
    FIELD_REMOVED: { index: 0, key: "06" + P1, name: "PSBT_IN_BIP32_DERIVATION" },
    FINGERPRINT_MISMATCH: { scope: "input-map", index: 0, name: "PSBT_IN_BIP32_DERIVATION", pubkey: P1, fingerprintBefore: "12345678", fingerprintAfter: "87654321" },
    METADATA_REMOVED: { scope: "output-map", index: 1, key: "06" + P1, name: "PSBT_OUT_BIP32_DERIVATION" },
    METADATA_CHANGED: { scope: "global", index: null, key: "01aa", name: "PSBT_GLOBAL_XPUB", before: "aa", after: "bb" },
    METADATA_ADDED: { scope: "input-map", index: 0, key: "0451", name: "PSBT_IN_REDEEM_SCRIPT" },
    METADATA_ENRICHMENT: { scope: "input-map", index: 0, key: "06" + P1, name: "PSBT_IN_BIP32_DERIVATION" },
    CHANGE_NOT_FROM_WALLET: { index: 1, scriptPubKey: SCRIPT, fingerprint: "12345678" },
    CHANGE_UNVERIFIED: { index: 1, scriptPubKey: SCRIPT, fingerprint: "12345678" },
    CHANGE_VERIFIED: { index: 1, scriptPubKey: SCRIPT, fingerprint: "12345678" },
    NONCE_REUSE: {},
    NONCE_CROSS_KEY: {},
    NONCE_REUSE_POSSIBLE: {},
    NONCE_COVERAGE_INCOMPLETE: {},
    ANTIEXFIL_FAILED: { signer: "jade" },
    SIGNER_UNKNOWN: { index: 0, pubkeys: [P1] },
    MUSIG2_MATERIAL_ADDED: { index: 0, name: "PSBT_IN_MUSIG2_PUB_NONCE" },
    ORIGIN_INCONSISTENT: { scope: "input-map", index: 0, name: "PSBT_IN_BIP32_DERIVATION", fingerprint: "12345678", reason: "mismatch" },
    SIGNATURE_ADDED: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, sighashAppended: 1 },
  }[code] ?? {};
  const severity = INFO_CODES.has(code) ? "info" : WARNING_CODES.has(code) ? "warning" : "critical";
  return { code, severity, scope: evidence.scope ?? null, index: evidence.index ?? null, field: null, evidence };
};

const reportFor = (findings, overrides = {}) => ({
  verdict: findings.some((f) => f.severity === "critical") ? "fail" : "pass",
  equal: findings.length === 0,
  checks: {
    transactionBody: "unchanged",
    utxoDeclarations: "unchanged",
    signatures: "none_added",
    sighashPolicy: "none",
    signerKeys: "no_new_signatures",
    metadata: "unchanged",
    nonceReuse: "not_checked",
    antiExfil: "not_available",
    changeOutputs: "not_checked",
  },
  findings,
  stats: { inputs: 1, outputs: 1, newSignatures: 0, feeBefore: null, feeAfter: null },
  diff: null,
  ...overrides,
});

const versionBumpDocs = () => {
  const before = { tx: { version: 2, locktime: 0, inputs: [], outputs: [] }, globals: [], inputs: [], outputs: [] };
  const after = { tx: { version: 3, locktime: 0, inputs: [], outputs: [] }, globals: [], inputs: [], outputs: [] };
  return { before, after, diff: comparePsbtDocs(before, after) };
};

// Every code renders a non-empty finding row, hooked on data-audit-code.
// The wording itself is not pinned (AGENTS.md: only safety-critical copy may
// be pinned, and only as a short stable substring); the fail headline's
// "Do not broadcast" is the one substring kept, in the tier tests below.
test("every signer-audit code renders a non-empty finding row", () => {
  assert.equal(SIGNER_AUDIT_CODES.length, 39, "fixture: the engine freezes 39 codes");
  for (const code of SIGNER_AUDIT_CODES) {
    const html = psbtSignerAuditHtml(reportFor([findingFor(code)]), null, null, "mainnet");
    const row = html.match(new RegExp(`<li[^>]*data-audit-code="${code}"[^>]*>([\\s\\S]*?)</li>`));
    assert.ok(row, `${code}: the row hook is missing`);
    assert.ok(row[1].replace(/<[^>]*>/g, "").trim().length > 0, `${code}: the finding line is empty`);
  }
});

test("SIGHASH_DECLARATION_ADDED renders a row at every severity", () => {
  const base = findingFor("SIGHASH_DECLARATION_ADDED");
  for (const severity of ["info", "warning", "critical"]) {
    const html = psbtSignerAuditHtml(reportFor([{ ...base, severity }]), null, null, "mainnet");
    assert.ok(html.includes('data-audit-code="SIGHASH_DECLARATION_ADDED"'), `${severity}: the row hook is missing`);
  }
});

test("the three verdict tiers render their tier hook", () => {
  const clean = psbtSignerAuditHtml(reportFor([]), null, null, "mainnet");
  assert.ok(clean.includes('data-audit-tier="pass"'));
  const warned = psbtSignerAuditHtml(reportFor([findingFor("METADATA_ADDED")]), null, null, "mainnet");
  assert.ok(warned.includes('data-audit-tier="pass-warnings"'));
  const failed = psbtSignerAuditHtml(reportFor([findingFor("TX_LOCKTIME_CHANGED")]), null, null, "mainnet");
  assert.ok(failed.includes('data-audit-tier="fail"'));
  assert.ok(failed.includes("Do not broadcast"));
});

test("a pass verdict with an unverified or invalid signature check renders the fail tier", () => {
  for (const signatures of ["unverified", "invalid"]) {
    const report = reportFor([], { checks: { ...reportFor([]).checks, signatures } });
    const html = psbtSignerAuditHtml(report, null, null, "mainnet");
    assert.ok(html.includes('data-audit-tier="fail"'), `signatures ${signatures} must render the fail tier`);
    assert.ok(html.includes('data-audit-verdict="fail"'), `signatures ${signatures} must render the fail note`);
    assert.ok(html.includes("Do not broadcast"));
  }
});

test("a missing report or verdict renders the fail tier, never a pass", () => {
  for (const report of [undefined, null, {}, { verdict: undefined }, { verdict: "unknown" }]) {
    const html = psbtSignerAuditHtml(report, null, null, "mainnet");
    assert.ok(html.includes('data-audit-tier="fail"'), `${String(report)} must render the fail tier`);
    assert.ok(html.includes('data-audit-verdict="fail"'), `${String(report)} must render the fail note`);
    assert.ok(!html.includes('data-audit-verdict="pass"'), `${String(report)} must not render the pass note`);
  }
});

test("the closing limitation note always renders", () => {
  for (const findings of [[], [findingFor("METADATA_ADDED")], [findingFor("NONCE_REUSE")]]) {
    const html = psbtSignerAuditHtml(reportFor(findings), null, null, "mainnet");
    assert.ok(html.includes("data-audit-limitation"), "the closing limitation note must always render");
  }
});

test("a group lists at most 8 findings, then one …and N more line; the verdict counts every finding", () => {
  const warnings = Array.from({ length: 10 }, (_, i) => ({
    code: "METADATA_ADDED",
    severity: "warning",
    scope: "input-map",
    index: i,
    field: null,
    evidence: { scope: "input-map", index: i, key: "0451", name: "PSBT_IN_REDEEM_SCRIPT" },
  }));
  const html = psbtSignerAuditHtml(reportFor(warnings), null, null, "mainnet");
  assert.equal((html.match(/data-audit-code="METADATA_ADDED"/g) || []).length, 8);
  assert.ok(html.includes("…and 2 more."));
  // A critical finding anywhere fails the verdict, listed or not: the cap
  // limits only what is shown, never what counts.
  const failed = psbtSignerAuditHtml(reportFor([...warnings, findingFor("TX_VERSION_CHANGED")]), null, null, "mainnet");
  assert.ok(failed.includes('data-audit-tier="fail"'));
  assert.ok(failed.includes("…and 2 more."));
});

test("within a group, critical findings render before warnings and info", () => {
  const html = psbtSignerAuditHtml(reportFor([findingFor("SIGNATURE_ADDED"), findingFor("SIGHASH_DECLARATION_INVALID"), findingFor("FIELD_REMOVED")]), null, null, "mainnet");
  const at = (code) => html.indexOf(`data-audit-code="${code}"`);
  assert.ok(at("FIELD_REMOVED") !== -1 && at("FIELD_REMOVED") < at("SIGHASH_DECLARATION_INVALID"));
  assert.ok(at("SIGHASH_DECLARATION_INVALID") < at("SIGNATURE_ADDED"));
});

test("hostile PSBT strings are escaped and bidi controls are neutralized", () => {
  const hostile = `<img src=x onerror="alert(1)">`;
  const findings = [
    { code: "METADATA_ADDED", severity: "warning", scope: "input-map", index: 0, field: null, evidence: { scope: "input-map", index: 0, key: "0451", name: hostile } },
    { code: "SIGNATURE_MALFORMED", severity: "critical", scope: "input-map", index: 0, field: null, evidence: { index: 0, name: "PSBT_IN_PARTIAL_SIG", decodeError: `bad ‮⁦signature ${hostile}` } },
    { code: "UNEXPECTED_SIGNER", severity: "critical", scope: "input-map", index: 0, field: null, evidence: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: hostile, expectedKeys: [] } },
    { code: "ANTIEXFIL_FAILED", severity: "critical", scope: null, index: null, field: null, evidence: { signer: hostile } },
    { code: "CHANGE_NOT_FROM_WALLET", severity: "critical", scope: "output", index: 1, field: null, evidence: { index: 1, scriptPubKey: hostile, fingerprint: hostile } },
  ];
  const html = psbtSignerAuditHtml(reportFor(findings), null, null, "mainnet");
  assert.ok(!html.includes("<img"), "raw HTML from a PSBT string must never reach the markup");
  assert.ok(html.includes("&lt;img"), "the escaped form is shown instead");
  assert.ok(!html.includes("‮") && !html.includes("⁦"), "bidi controls are neutralized");
});

// The approved check table: every known value maps to its tone.
const CHECK_TONES = {
  transactionBody: { unchanged: "ok", changed: "bad", reordered: "bad", unknown: "warn" },
  utxoDeclarations: { unchanged: "ok", changed: "bad", unknown: "warn" },
  signatures: { valid: "ok", invalid: "bad", unverified: "bad", removed_or_changed: "bad", none_added: "neutral", unknown: "warn" },
  sighashPolicy: { full_commitment: "ok", weak: "bad", weak_as_requested: "warn", mismatch: "bad", undefined: "bad", none: "neutral", unknown: "warn" },
  signerKeys: { match: "ok", unexpected: "bad", unknown: "bad", no_new_signatures: "neutral" },
  metadata: { unchanged: "ok", additions: "warn", mutated: "bad", unknown: "warn" },
  nonceReuse: { none_found: "ok", reuse: "bad", cross_key: "bad", possible: "warn", incomplete: "warn", not_checked: "neutral", unknown: "warn" },
  antiExfil: { verified: "ok", failed: "bad", not_available: "neutral", unknown: "warn" },
  changeOutputs: { verified: "ok", not_from_wallet: "bad", unverified: "warn", none_presented: "neutral", not_checked: "neutral", unknown: "warn" },
};

test("every check value maps to its tone, and an unrecognized value never renders green", () => {
  for (const [key, values] of Object.entries(CHECK_TONES)) {
    for (const [value, tone] of Object.entries(values)) {
      const report = reportFor([]);
      // Unfold the three unwired checks (Unknown on one of the others), so
      // their own neutral values render as rows too.
      report.checks[key === "nonceReuse" ? "antiExfil" : "nonceReuse"] = "unknown";
      report.checks[key] = value;
      const html = psbtSignerAuditHtml(report, null, null, "mainnet");
      assert.ok(html.includes(`data-audit-check="${key}" data-audit-tone="${tone}"`), `${key}.${value} must render tone ${tone}`);
    }
  }
  const report = reportFor([]);
  report.checks.transactionBody = "a_value_this_view_predates";
  const html = psbtSignerAuditHtml(report, null, null, "mainnet");
  assert.ok(html.includes('data-audit-check="transactionBody" data-audit-tone="warn"'));
  assert.ok(!html.includes('data-audit-check="transactionBody" data-audit-tone="ok"'));
});

test("every checklist row, the signature count included, is one label/value row with a toned value", () => {
  // Wicked's review of #1118: one shared row shape. The count is a value
  // like the others, in the neutral tone, distinct from a passed (ok) check.
  const html = psbtSignerAuditHtml(reportFor([], { stats: { inputs: 1, outputs: 1, newSignatures: 1, feeBefore: null, feeAfter: null } }), null, null, "mainnet");
  assert.equal((html.match(/data-audit-value/g) ?? []).length, 7, "six checks plus the signature count");
  assert.ok(html.includes('data-audit-check="newSignatures" data-audit-tone="neutral"'));
});

test("the three unwired checks fold into one Not checked here line; any other value brings their rows back", () => {
  // TC's review of #1118: nonce reuse, anti-exfil and change outputs are not
  // wired into the Inspector run, so they read "not checked" every time and
  // collapse into one line naming all three.
  const folded = psbtSignerAuditHtml(reportFor([]), null, null, "mainnet");
  assert.ok(folded.includes('data-audit-unchecked="nonceReuse antiExfil changeOutputs"'));
  for (const key of ["nonceReuse", "antiExfil", "changeOutputs"]) assert.ok(!folded.includes(`data-audit-check="${key}"`), `${key} is folded`);
  // A result is never folded away: a problem, a pass, or Unknown on any one
  // of them shows all three rows, and no line.
  for (const [key, value, tone] of [["nonceReuse", "reuse", "bad"], ["antiExfil", "verified", "ok"], ["changeOutputs", "none_presented", "neutral"], ["changeOutputs", "unknown", "warn"]]) {
    const report = reportFor([]);
    report.checks[key] = value;
    const html = psbtSignerAuditHtml(report, null, null, "mainnet");
    assert.ok(!html.includes("data-audit-unchecked"), `${key}.${value}: no folded line`);
    assert.ok(html.includes(`data-audit-check="${key}" data-audit-tone="${tone}"`), `${key}.${value} renders its row`);
    assert.equal((html.match(/data-audit-value/g) ?? []).length, 9, `${key}.${value}: all nine checks`);
  }
  // A report without checks folds nothing: all three are Unknown, in the
  // warning tone.
  const bare = psbtSignerAuditHtml({ verdict: "fail" }, null, null, "mainnet");
  assert.ok(!bare.includes("data-audit-unchecked"));
  assert.ok(bare.includes('data-audit-check="nonceReuse" data-audit-tone="warn"'));
});

test("the Not checked here note stays visible outside the folded checks block", () => {
  // TC's point 6: the checks, the note and the next disclosure are three
  // separate pieces. A passing audit folds the checks, so a note inside the
  // block would be hidden — it must render after the disclosure, outside it.
  const html = psbtSignerAuditHtml(reportFor([]), null, null, "mainnet");
  const open = html.indexOf('<details class="derivation-advanced" data-audit-checks');
  const close = html.indexOf("</details>", open);
  assert.ok(open >= 0 && close > open, "fixture: the checks block renders");
  assert.ok(!/\bopen\b/.test(html.slice(open, html.indexOf(">", open))), "fixture: a passing audit folds the checks");
  const note = html.indexOf("data-audit-unchecked");
  assert.ok(note > close, "the note renders after the disclosure, not inside it");
  const depth = (html.slice(0, note).match(/<details\b/g) || []).length - (html.slice(0, note).match(/<\/details>/g) || []).length;
  assert.equal(depth, 0, "the note is outside every details element");
});

test("the checks block's open state comes from the check tones, never the rendered class names", () => {
  const source = readFileSync(new URL("../src/js/psbt-signer-audit-view.js", import.meta.url), "utf8");
  assert.ok(!/\.includes\(\s*["']psbt-(bad|warn)["']\s*\)/.test(source), "the view must not decide folding from psbt-bad/psbt-warn");
});

test("a missing check value renders Unknown in the warning tone, never a table row named undefined", () => {
  // sighashPolicy has an "undefined" value (a real sighash state); a check
  // the report leaves out must not read it.
  const report = reportFor([]);
  delete report.checks.sighashPolicy;
  const html = psbtSignerAuditHtml(report, null, null, "mainnet");
  assert.ok(html.includes('data-audit-check="sighashPolicy" data-audit-tone="warn"'));
  report.checks.signatures = "constructor";
  assert.ok(psbtSignerAuditHtml(report, null, null, "mainnet").includes('data-audit-check="signatures" data-audit-tone="warn"'));
});

test("an undecodable-document report renders the error finding, unknown checks, and no diff", () => {
  const report = {
    verdict: "fail",
    equal: false,
    checks: Object.fromEntries(Object.keys(CHECK_TONES).map((key) => [key, "unknown"])),
    findings: [findingFor("DOC_UNDECODABLE")],
    stats: null,
    diff: null,
  };
  const html = psbtSignerAuditHtml(report, null, null, "mainnet");
  assert.ok(html.includes('data-audit-tier="fail"'));
  assert.ok(html.includes('data-audit-code="DOC_UNDECODABLE"'));
  assert.ok(html.includes('data-audit-check="transactionBody" data-audit-tone="warn"'));
  assert.ok(!html.includes("data-audit-diff"), "no diff block without a diff");
});

test("the read-error note names its case, escapes the parser's message, and carries no verdict", () => {
  // TC's review of #1118: the headline names the PSBT the error is about, so
  // a raw transaction inspected above is never blamed on the PSBT you sent.
  for (const kind of ["returned-raw", "sent-raw", "sent-unreadable", "failed"]) {
    const html = psbtSignerAuditErrorHtml({ kind });
    assert.ok(html.includes("data-audit-section"));
    assert.ok(html.includes(`data-audit-error="${kind}"`), `${kind}: its own headline`);
    assert.ok(!html.includes("data-audit-tier") && !html.includes("data-audit-verdict"), `${kind}: no verdict`);
    assert.ok(!html.includes("data-audit-error-detail"), `${kind}: no detail line without a detail`);
  }
  const html = psbtSignerAuditErrorHtml({ kind: "sent-unreadable", detail: "not base64 <script>alert(1)</script> \u202e" });
  assert.ok(html.includes("data-audit-error-detail"));
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(!html.includes("\u202e"), "bidi controls are neutralized");
  // An unknown kind, or a bare message, is the generic case.
  assert.ok(psbtSignerAuditErrorHtml({ kind: "something-new" }).includes('data-audit-error="failed"'));
  const bare = psbtSignerAuditErrorHtml("boom <b>");
  assert.ok(bare.includes('data-audit-error="failed"') && bare.includes("boom &lt;b&gt;"));
});

// The error kind comes from app.js's own run path (TC's review of #1118):
// each stage's failure is named for the PSBT it is about.
test("the audit run names which PSBT kept it from running", async () => {
  const field = { value: "SENT" };
  const app = await loadAppFunctions(["hodlPsbtPrependSignerAudit", "hodlPsbtSignerAuditMarkup"], { stubs: {
    document: { getElementById: (id) => (id === "psbt-audit-before" ? field : null) },
    hodlPsbtBytesFromText: (text) => { if (text === "BAD") throw new Error("not base64 or hex"); return new Uint8Array(text === "RAWTX" ? [2] : [0x70]); },
    isPsbtMagic: (bytes) => bytes[0] === 0x70,
    psbtInspectDoc: (bytes) => { if (bytes[0] === 0xee) throw new Error("returned decode"); return { bytes }; },
    hodlPsbtSignerAuditVerify: () => undefined,
    hodlAuditSigner: () => ({ verdict: "pass" }),
    hodlPsbtSignerAuditHtml: () => "REPORT",
    hodlPsbtSignerAuditErrorHtml: (error) => `ERROR ${error.kind}`,
  } });
  const run = (kind, returned = new Uint8Array([0x70])) => {
    const output = { insertAdjacentHTML: (_, html) => { output.html = html; } };
    return { audit: app.hodlPsbtPrependSignerAudit(output, returned, kind, "mainnet"), output };
  };
  assert.equal(run("tx").audit.error.kind, "returned-raw", "a raw transaction above is the returned side's");
  field.value = "RAWTX";
  assert.equal(run("psbt").audit.error.kind, "sent-raw");
  field.value = "BAD";
  const unreadable = run("psbt").audit;
  assert.equal(unreadable.error.kind, "sent-unreadable");
  assert.equal(unreadable.error.detail, "not base64 or hex");
  field.value = "SENT";
  const failed = run("psbt", new Uint8Array([0xee]));
  assert.equal(failed.audit.error.kind, "failed", "a throw past the sent decode is not blamed on the sent PSBT");
  assert.equal(failed.output.html, "ERROR failed");
  assert.equal(run("psbt").output.html, "REPORT");
  field.value = "  ";
  assert.equal(run("psbt").audit, null, "an empty field runs nothing");
});

// TC's review of #1118: every sentence is a translator call with
// placeholders, so the catalog sync picks it up (the view's aliased
// imports, ternary branches and reason tables included).
test("the audit's sentences are translation sources, numbers as placeholders", async () => {
  const { collectSources } = await import("../scripts/i18n-sources.mjs");
  const { fileURLToPath } = await import("node:url");
  const sources = await collectSources(fileURLToPath(new URL("..", import.meta.url)));
  for (const source of [
    "PSBT signer audit",
    "Do not broadcast this PSBT.",
    "No changes to your transaction.",
    "Transaction body",
    "Not checked",
    "Not checked here: nonce reuse, anti-exfil, change outputs.",
    "Input {n} is not what you sent.",
    "An input is not what you sent.",
    "{count} keys named in your PSBT",
    "…and {n} more.",
    "its contents are malformed",
    "The verification budget ran out before this signature could be checked.",
    "unknown pair (type 0x{type})",
    "The payload inspected above is a raw transaction, not a PSBT — the signer audit compares two PSBTs.",
    "Upload sent .psbt",
  ]) assert.ok(sources.has(source), `not a source: ${source}`);
});

test("psbtDiffHtml labels: the default output is byte-identical, custom labels rename the sides", () => {
  const { before, after, diff } = versionBumpDocs();
  const fallback = psbtDiffHtml(diff, before, after, "mainnet");
  assert.ok(fallback.includes("the PSBT in the editor"));
  assert.equal(psbtDiffHtml(diff, before, after, "mainnet", {}), fallback);
  assert.equal(psbtDiffHtml(diff, before, after, "mainnet", { copyIcon: () => "" }), fallback);
  const labeled = psbtDiffHtml(diff, before, after, "mainnet", { beforeLabel: "the PSBT you sent", afterLabel: "the returned PSBT" });
  assert.ok(labeled.includes("the PSBT you sent"));
  assert.ok(labeled.includes("the returned PSBT"));
  assert.ok(!labeled.includes("the PSBT in the editor"));
});

test("the view renders the collapsed technical diff with the sent/returned labels", () => {
  const { before, after, diff } = versionBumpDocs();
  const html = psbtSignerAuditHtml(reportFor([], { diff, equal: false }), before, after, "mainnet");
  assert.ok(html.includes("data-audit-diff"));
  assert.ok(html.includes("the PSBT you sent"));
  assert.ok(html.includes("the returned PSBT"));
  assert.ok(!html.includes("the PSBT in the editor"));
});

// The app-wide session wipe must retire a shown audit verdict with the
// field it was computed from: the rendered section holds change addresses
// and fingerprints derived from the loaded key. A static check of the wipe
// body, as test/secret-field-registry.test.mjs does for its probes.
test("the app-wide session wipe also retires a shown signer-audit verdict", () => {
  const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const start = source.indexOf("function hodlInitSecretFieldAutoClear()");
  assert.ok(start >= 0, "fixture: hodlInitSecretFieldAutoClear is in app.js");
  const next = source.indexOf("\nfunction ", start + 1);
  const body = source.slice(start, next === -1 ? undefined : next);
  const emptied = body.indexOf('psbtAuditBefore.value = ""');
  assert.ok(emptied >= 0, "fixture: the wipe empties #psbt-audit-before");
  const cleared = body.indexOf("hodlPsbtClearSignerAudit()", emptied);
  assert.ok(cleared > emptied, "the wipe must retire the rendered audit section after emptying #psbt-audit-before");
  assert.ok(cleared - emptied < 400, "the call belongs right after the #psbt-audit-before wipe");
});

// Behavior tests for the audit's UI state (Wicked's review of #1118), run
// on app.js's own functions through the slice harness, not on its text.
const fakeOutput = () => {
  const output = { innerHTML: "", childElementCount: 1 };
  output.insertAdjacentHTML = (where, html) => { output.innerHTML = html + output.innerHTML; };
  // Only the audit section is ever found: Show more's tail and "next" lookups
  // get nothing, as on a page whose lists are fully shown.
  output.querySelector = (selector = "[data-audit-section]") =>
    selector.includes("data-audit-section") && output.innerHTML.startsWith("AUDIT")
      ? { remove: () => { output.innerHTML = output.innerHTML.replace(/^AUDIT[^|]*\|/, ""); } }
      : null;
  return output;
};

test("retiring a shown verdict re-enables Inspect even when the inputs trim back to the inspected ones", async () => {
  const fields = { "psbt-text": { value: "RETURNED" }, "psbt-audit-before": { value: "SENT" } };
  const output = fakeOutput();
  const element = (id) => fields[id] ?? (id === "psbt-out" ? output : { value: "", hidden: false, classList: { toggle: () => {} } });
  const enabled = {};
  const app = await loadAppFunctions(["hodlPsbtClearSignerAudit", "hodlMarkPsbtInspected", "hodlSyncPsbtControls"], { settable: ["hodlPsbtInspected", "hodlPsbtLast"], stubs: {
    document: { getElementById: element },
    hodlSetButtonEnabled: (id, on) => { enabled[id] = on; },
    hodlPsbtBytes: (text) => { if (!String(text).trim()) throw new Error("empty"); return new Uint8Array([1]); },
    hodlStationPassphraseStamp: () => "",
    hodlPsbtPriv: null,
    hodlPsbtHd: null,
    hodlPsbtSessionSpec: { key: "No session key. Inspect-only mode." },
    hodlPsbtNonceHistory: [],
  } });
  const inspected = {};
  app.__set.hodlPsbtInspected(inspected);
  app.__set.hodlPsbtLast(null);
  const showAudit = () => { output.innerHTML = "AUDIT fail|inspection"; };

  // Inspect ran on this pair: the button waits for a change.
  app.hodlMarkPsbtInspected("psbt-go");
  app.hodlSyncPsbtControls();
  assert.equal(enabled["psbt-go"], false);

  // A trailing space retires the verdict; the trimmed inputs still match
  // the old stamp, yet Inspect must come back so the verdict can be restored.
  showAudit();
  fields["psbt-audit-before"].value = "SENT ";
  app.hodlPsbtClearSignerAudit();
  assert.equal(output.querySelector(), null, "the verdict is gone");
  assert.equal(enabled["psbt-go"], true);

  // Edit and revert: the same.
  app.hodlMarkPsbtInspected("psbt-go");
  showAudit();
  fields["psbt-audit-before"].value = "SENTx";
  fields["psbt-audit-before"].value = "SENT";
  app.hodlPsbtClearSignerAudit();
  assert.equal(enabled["psbt-go"], true);

  // A returned PSBT that does not decode still never enables Inspect.
  showAudit();
  fields["psbt-text"].value = "";
  app.hodlPsbtClearSignerAudit();
  assert.equal(enabled["psbt-go"], false);
});

test("a language change paints a failing audit again; a retired one stays gone", async () => {
  const outputs = { "psbt-out": fakeOutput(), "nonce-out": fakeOutput() };
  const app = await loadAppFunctions(["hodlRefreshPsbtLocale", "hodlPsbtClearSignerAudit"], { settable: ["hodlPsbtLast", "hodlNonceLast", "hodlPsbtInspected"], stubs: {
    document: { getElementById: (id) => outputs[id] ?? null },
    hodlPaintPsbtSession: () => {},
    hodlPaintPsbtKeyNotes: () => {},
    hodlSetPsbtError: () => {},
    hodlSetNonceError: () => {},
    hodlPsbtSyncNonceHistoryControls: () => {},
    hodlSyncPsbtControls: () => {},
    hodlRenderPsbt: () => "inspection",
    hodlRenderRawTx: () => "inspection",
    hodlPsbtSignerAuditHtml: (report) => `AUDIT ${report.verdict}|`,
    hodlPsbtSignerAuditErrorHtml: (error) => `AUDIT error ${error.kind}|`,
  } });
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array([1]), checkedAt: "t", network: "mainnet", audit: { report: { verdict: "fail" }, beforeDoc: {}, afterDoc: {}, network: "mainnet" } };
  app.__set.hodlPsbtLast(last);
  app.__set.hodlNonceLast(null);
  app.__set.hodlPsbtInspected({});
  app.hodlRefreshPsbtLocale();
  assert.equal(outputs["psbt-out"].innerHTML, "AUDIT fail|inspection", "the critical verdict survives the switch");

  app.hodlPsbtClearSignerAudit();
  assert.equal(last.audit, null);
  app.hodlRefreshPsbtLocale();
  assert.equal(outputs["psbt-out"].innerHTML, "inspection", "a retired verdict is not painted back");

  // An audit that could not run (its error) is painted again the same way.
  last.audit = { error: { kind: "sent-raw" } };
  app.hodlRefreshPsbtLocale();
  assert.equal(outputs["psbt-out"].innerHTML, "AUDIT error sent-raw|inspection");
});

test("an audit upload that finishes after the session ends writes nothing back, success or error", async () => {
  const field = { value: "" };
  const errors = [];
  let cleared = 0;
  const app = await loadAppFunctions(["hodlPsbtLoadAuditUpload", "hodlPsbtRetireAuditUploads"], { stubs: {
    document: { getElementById: (id) => (id === "psbt-audit-before" ? field : null) },
    psbtBytesFromUpload: (bytes) => bytes,
    hodlBytesToB64: () => "SENT-B64",
    hodlPsbtClearSignerAudit: () => { cleared += 1; },
    hodlSetPsbtError: (spec) => { errors.push(spec); },
    hodlSyncPsbtControls: () => {},
  } });
  const pending = () => {
    let settle;
    const promise = new Promise((resolve, reject) => { settle = { resolve, reject }; });
    return { chosen: { arrayBuffer: () => promise }, settle };
  };

  // Control: an upload nothing interrupts fills the field.
  let read = pending(), load = app.hodlPsbtLoadAuditUpload(read.chosen);
  read.settle.resolve(new ArrayBuffer(4));
  await load;
  assert.equal(field.value, "SENT-B64");

  // The session ends while the read is pending: nothing comes back.
  field.value = "";
  read = pending();
  load = app.hodlPsbtLoadAuditUpload(read.chosen);
  app.hodlPsbtRetireAuditUploads();
  read.settle.resolve(new ArrayBuffer(4));
  await load;
  assert.equal(field.value, "", "a retired upload does not restore the cleared field");

  // Nor does a retired read that fails show its stale error.
  read = pending();
  load = app.hodlPsbtLoadAuditUpload(read.chosen);
  app.hodlPsbtRetireAuditUploads();
  read.settle.reject(new Error("read failed"));
  await load;
  assert.deepEqual(errors, []);
  assert.equal(cleared, 1, "only the uninterrupted upload retired a verdict");
});

test("Show more's full repaint keeps the audit; an edit after a repaint retires the cached one too", async () => {
  // Wicked's recheck: a full Show-more repaint dropped the audit from the
  // page while its report stayed cached, so an edit could not retire it and a
  // language change painted the obsolete verdict back.
  const output = fakeOutput();
  Object.assign(output, { hasAttribute: () => true, setAttribute() {}, focus() {} });
  const app = await loadAppFunctions(["hodlPsbtShowMore", "hodlPsbtClearSignerAudit", "hodlRefreshPsbtLocale"], { settable: ["hodlPsbtLast", "hodlNonceLast", "hodlPsbtInspected"], stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    // A string, not a block: Show more paints the whole run again.
    hodlRenderPsbt: () => "inspection",
    hodlRenderRawTx: () => "inspection",
    hodlPsbtSignerAuditHtml: (report) => `AUDIT ${report.verdict}|`,
    hodlPsbtSignerAuditErrorHtml: (error) => `AUDIT error ${error.kind}|`,
    hodlSyncPsbtControls: () => {},
    hodlPaintPsbtSession: () => {},
    hodlPaintPsbtKeyNotes: () => {},
    hodlSetPsbtError: () => {},
    hodlSetNonceError: () => {},
    hodlPsbtSyncNonceHistoryControls: () => {},
  } });
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array([1]), checkedAt: "t", network: "mainnet", limits: { inputs: 50, outputs: 50, step: 50 }, audit: { report: { verdict: "fail" }, beforeDoc: {}, afterDoc: {}, network: "mainnet" } };
  app.__set.hodlPsbtLast(last);
  app.__set.hodlNonceLast(null);
  app.__set.hodlPsbtInspected({});
  output.innerHTML = "AUDIT fail|inspection";
  app.hodlPsbtShowMore({ target: { closest: () => ({ dataset: { psbtMore: "inputs" } }) } });
  assert.equal(output.innerHTML, "AUDIT fail|inspection", "the full repaint keeps the verdict above the inspection");

  // A repaint that left the verdict off the page, then an edit: the cached
  // report is retired anyway, so a language change cannot bring it back.
  output.innerHTML = "inspection";
  app.hodlPsbtClearSignerAudit();
  assert.equal(last.audit, null, "the cached verdict is retired even when it is not on screen");
  app.hodlRefreshPsbtLocale();
  assert.equal(output.innerHTML, "inspection");
});

test("both session wipes retire pending audit uploads", () => {
  const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const bodyOf = (name) => {
    const start = source.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `fixture: ${name} is in app.js`);
    const next = source.indexOf("\nfunction ", start + 1);
    return source.slice(start, next === -1 ? undefined : next);
  };
  assert.ok(bodyOf("hodlEndPsbtSession").includes("hodlPsbtRetireAuditUploads()"), "End Session retires pending uploads");
  assert.ok(bodyOf("hodlInitSecretFieldAutoClear").includes("hodlPsbtRetireAuditUploads()"), "the app-wide wipe retires pending uploads");
});

// Item 3: a PSBT with very many inputs must not overflow the argument limit
// in the transaction serializer (concatBytes spread), which would downgrade
// the whole audit to unverified.
test("a PSBT with very many inputs does not overflow the argument limit", () => {
  const count = 50000;
  const inputs = Array.from({ length: count }, () => ({ txid: "ab".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }));
  const doc = {
    tx: { version: 2, locktime: 0, inputs, outputs: [{ value: "1000", scriptPubKey: "51" }] },
    globals: [],
    inputs: inputs.map(() => []),
    outputs: [[]],
  };
  const result = psbtSignerAuditVerification(doc, doc);
  assert.equal(result.complete, true);
  assert.deepEqual(result.signatures, []);
});

// Item 4: the technical diff prints each pair's decodeError; that text is
// untrusted, so bidi controls must be neutralized before it reaches the line.
test("the technical diff neutralizes bidi controls in a pair's decodeError", () => {
  const before = { tx: { version: 2, locktime: 0, inputs: [], outputs: [] }, globals: [{ key: "ff00", value: "00", name: null, decodeError: "bad \u202e\u2066 signature" }], inputs: [], outputs: [] };
  const after = { tx: { version: 2, locktime: 0, inputs: [], outputs: [] }, globals: [], inputs: [], outputs: [] };
  const diff = comparePsbtDocs(before, after);
  const html = psbtSignerAuditHtml(reportFor([], { diff, equal: false }), before, after, "mainnet");
  assert.ok(!html.includes("\u202e") && !html.includes("\u2066"), "bidi controls in a decodeError must be neutralized");
});

test("retiring a shown verdict removes the combined overall line", async () => {
  const overall = { removed: false, remove() { this.removed = true; } };
  const section = { removed: false, remove() { this.removed = true; } };
  const output = {
    querySelector(selector) {
      if (selector === "[data-audit-section]") return section;
      if (selector === "[data-psbt-overall]") return overall;
      return null;
    },
  };
  const app = await loadAppFunctions(["hodlPsbtClearSignerAudit"], { settable: ["hodlPsbtLast", "hodlPsbtInspected"], stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlSyncPsbtControls: () => {},
  } });
  app.__set.hodlPsbtLast({ audit: { report: { verdict: "pass" } } });
  app.__set.hodlPsbtInspected({});
  app.hodlPsbtClearSignerAudit();
  assert.equal(section.removed, true, "the audit section is removed");
  assert.equal(overall.removed, true, "the overall line is removed with it");
});

test("a language change paints the audit after the answer block and recomputes the overall line", async () => {
  const answer = { inserted: [], insertAdjacentHTML(position, html) { this.inserted.push({ position, html }); } };
  const output = {
    innerHTML: "",
    querySelector(selector) {
      if (selector === "[data-psbt-answer]") return answer;
      return null;
    },
    insertAdjacentHTML(position, html) { this.innerHTML = html + this.innerHTML; },
  };
  let overallCalls = 0;
  const app = await loadAppFunctions(["hodlRefreshPsbtLocale", "hodlPsbtPaintSignerAudit"], { settable: ["hodlPsbtLast", "hodlNonceLast"], stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlPaintPsbtSession: () => {},
    hodlPaintPsbtKeyNotes: () => {},
    hodlSetPsbtError: () => {},
    hodlSetNonceError: () => {},
    hodlPsbtSyncNonceHistoryControls: () => {},
    hodlRenderPsbt: () => "inspection",
    hodlRenderRawTx: () => "inspection",
    hodlPsbtSignerAuditMarkup: () => "AUDIT",
    hodlPsbtInsertOverall: () => { overallCalls += 1; },
  } });
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array([1]), checkedAt: "t", network: "mainnet", audit: { report: { verdict: "pass" } } };
  app.__set.hodlPsbtLast(last);
  app.__set.hodlNonceLast(null);
  app.hodlRefreshPsbtLocale();
  assert.equal(answer.inserted.length, 1, "the audit is inserted after the answer block");
  assert.equal(answer.inserted[0].position, "afterend");
  assert.equal(answer.inserted[0].html, "AUDIT");
  assert.equal(overallCalls, 1, "the overall line is recomputed");
});
