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
  signatures: { valid: "ok", invalid: "bad", unverified: "bad", removed_or_changed: "bad", none_added: "muted", unknown: "warn" },
  sighashPolicy: { full_commitment: "ok", weak: "bad", weak_as_requested: "warn", mismatch: "bad", undefined: "bad", none: "muted", unknown: "warn" },
  signerKeys: { match: "ok", unexpected: "bad", unknown: "bad", no_new_signatures: "muted" },
  metadata: { unchanged: "ok", additions: "warn", mutated: "bad", unknown: "warn" },
  nonceReuse: { none_found: "ok", reuse: "bad", cross_key: "bad", possible: "warn", incomplete: "warn", not_checked: "muted", unknown: "warn" },
  antiExfil: { verified: "ok", failed: "bad", not_available: "muted", unknown: "warn" },
  changeOutputs: { verified: "ok", not_from_wallet: "bad", unverified: "warn", none_presented: "muted", not_checked: "muted", unknown: "warn" },
};

test("every check value maps to its tone, and an unrecognized value never renders green", () => {
  for (const [key, values] of Object.entries(CHECK_TONES)) {
    for (const [value, tone] of Object.entries(values)) {
      const report = reportFor([]);
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
  assert.ok(!html.includes("<details"), "no diff block without a diff");
});

test("the parse-error note escapes its message and carries no verdict", () => {
  const html = psbtSignerAuditErrorHtml(`not base64 <script>alert(1)</script>`);
  assert.ok(html.includes("data-audit-section"));
  assert.ok(!html.includes("data-audit-tier"));
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
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
  assert.ok(html.includes("<details"));
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

// Item 2: retiring a shown verdict must not bypass the Inspect button's own
// rules — the ordinary input sync decides the button state, so a field that
// does not decode never enables Inspect.
test("retiring a shown signer-audit verdict re-enables Inspect for the same inputs", () => {
  const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const start = source.indexOf("function hodlPsbtClearSignerAudit()");
  assert.ok(start >= 0, "fixture: hodlPsbtClearSignerAudit is in app.js");
  const next = source.indexOf("\nfunction ", start + 1);
  const body = source.slice(start, next === -1 ? undefined : next);
  assert.ok(body.includes("hodlSyncPsbtControls()"), "the retirement must let the input sync decide the Inspect button");
  assert.ok(!body.includes('"psbt-go"'), "the retirement must not touch the Inspect button directly");
  assert.ok(!/disabled\s*=\s*false/.test(body), "the retirement must not force-enable Inspect");
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
