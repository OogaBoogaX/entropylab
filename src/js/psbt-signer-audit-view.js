// HTML rendering for the PSBT Signer Audit (engine: psbt-signer-audit.js).
//
// Pure string building, unit-tested under Node; app.js prepends the result
// to the PSBT Inspector's output when the optional "PSBT you sent" field is
// filled. The view never decides safety: it renders the engine's verdict,
// checks and findings exactly as reported — a fail can never paint as a
// pass, and a check value the maps below do not know renders as "Unknown"
// in the warning tone, never green. Every PSBT-derived string is escaped
// before it reaches the markup (tHtml escapes its placeholder values; the
// rest passes escapeHtml), and free text (parser and decoder messages) is
// additionally neutralized against bidi and invisible codepoints. Markup
// and escaping follow psbt-editor.js; the layout follows the PSBT security
// analysis (hodlPsbtAnalysisSummary in app.js). Every user-visible sentence
// is a translator call with {placeholders}, so numbers and names never
// split a sentence; app.js paints the audit again on a language change.
import { addressFromScript } from "./addresses.js";
import { hex as hexCoder } from "./coders.js";
import { t, tAttr as TA, tHtml as T } from "./i18n.js";
import { hodlNeutralizeControls } from "./i18n-sanitize.js";
import { psbtDiffHtml } from "./psbt-editor.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const shorten = (hex, head = 10, tail = 6) => {
  const text = String(hex ?? "");
  return text.length > head + tail + 2 ? text.slice(0, head) + "…" + text.slice(-tail) : text;
};

// An own-property lookup in a value or reason table: only a string key the
// table itself holds — a missing check (undefined) or an engine value such
// as "constructor" falls through to the default, so it can neither read
// the sighash table's "undefined" row nor hand the translator a function.
const lookup = (table, key) => (typeof key === "string" && Object.hasOwn(table, key) ? table[key] : undefined);

// Findings list at most this many rows per group, then one "…and N more"
// line (the psbtSanitizeHtml slice(0, 8) precedent). The cap only limits
// what is listed — the verdict is the engine's and always counts every
// finding.
const GROUP_LIMIT = 8;

// Group order is fixed: read errors first, then what matters most before
// broadcast — the transaction itself, signatures and keys, the user's
// change, nonce/anti-exfil, and everything else last. A code no group names
// (a newer engine) falls into the last group rather than vanishing. The
// titles are translated at render time, in the same order.
const FINDING_GROUPS = [
  ["DOC_UNDECODABLE"],
  ["TX_REORDERED", "TX_INPUT_CHANGED", "TX_OUTPUT_CHANGED", "TX_VERSION_CHANGED", "TX_LOCKTIME_CHANGED", "UTXO_DECLARATION_CHANGED"],
  ["UNEXPECTED_SIGNER", "SIGNATURE_CHANGED", "SIGNATURE_REMOVED", "SIGNATURE_MALFORMED", "SIGNATURE_INVALID", "SIGNATURE_UNVERIFIED", "SIGHASH_WEAK", "SIGHASH_MISMATCH", "SIGHASH_UNDEFINED", "SIGHASH_DECLARATION_CHANGED", "SIGHASH_DECLARATION_ADDED", "SIGHASH_DECLARATION_INVALID", "FINALIZATION_INVALID", "FIELD_REMOVED", "FINGERPRINT_MISMATCH", "SIGNER_UNKNOWN", "MUSIG2_MATERIAL_ADDED", "SIGNATURE_ADDED", "FINALIZED"],
  ["CHANGE_NOT_FROM_WALLET", "CHANGE_UNVERIFIED", "CHANGE_VERIFIED"],
  ["NONCE_REUSE", "NONCE_CROSS_KEY", "NONCE_REUSE_POSSIBLE", "NONCE_COVERAGE_INCOMPLETE", "ANTIEXFIL_FAILED"],
  ["METADATA_REMOVED", "METADATA_CHANGED", "METADATA_ADDED", "METADATA_ENRICHMENT", "ORIGIN_INCONSISTENT"],
];
const groupTitles = () => [T("Read errors"), T("Your transaction"), T("Signatures and keys"), T("Your change"), T("Nonce and anti-exfil"), T("Other PSBT data")];

// Info findings take the normal text colour (no class); only their detail
// line is muted, as in the analysis rows.
const SEVERITY_TONE = { critical: "psbt-bad", warning: "psbt-warn", info: "" };
const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 };
// A neutral value (none added, no new signatures, the count) inherits the
// text colour: it is neither a pass nor a problem.
const TONE_CLASS = { ok: "psbt-ok", warn: "psbt-warn", bad: "psbt-bad", neutral: "" };

// The checks, in display order. Each known value maps to a label and a
// tone; a value the map does not know renders as "Unknown" in the warning
// tone — never green. Built at render time so the labels follow the
// current language.
const checkRows = () => [
  ["transactionBody", T("Transaction body"), {
    unchanged: [T("Unchanged"), "ok"],
    changed: [T("Changed"), "bad"],
    reordered: [T("Reordered"), "bad"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["utxoDeclarations", T("UTXO declarations"), {
    unchanged: [T("Unchanged"), "ok"],
    changed: [T("Changed"), "bad"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["signatures", T("Signatures"), {
    valid: [T("Valid"), "ok"],
    invalid: [T("Invalid"), "bad"],
    unverified: [T("Unverified"), "bad"],
    removed_or_changed: [T("Removed or changed"), "bad"],
    none_added: [T("None added"), "neutral"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["sighashPolicy", T("Sighash policy"), {
    full_commitment: [T("Full commitment"), "ok"],
    weak: [T("Weak"), "bad"],
    weak_as_requested: [T("Weak, as requested"), "warn"],
    mismatch: [T("Mismatch"), "bad"],
    undefined: [T("Undefined"), "bad"],
    none: [T("None"), "neutral"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["signerKeys", T("Signer keys"), {
    match: [T("Match"), "ok"],
    unexpected: [T("Unexpected"), "bad"],
    unknown: [T("Unknown"), "bad"],
    no_new_signatures: [T("No new signatures"), "neutral"],
  }],
  ["metadata", T("PSBT metadata"), {
    unchanged: [T("Unchanged"), "ok"],
    additions: [T("Additions"), "warn"],
    mutated: [T("Mutated"), "bad"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["nonceReuse", T("Nonce reuse"), {
    none_found: [T("None found"), "ok"],
    reuse: [T("Reuse found"), "bad"],
    cross_key: [T("Cross-key reuse"), "bad"],
    possible: [T("Possible"), "warn"],
    incomplete: [T("Incomplete"), "warn"],
    not_checked: [T("Not checked"), "neutral"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["antiExfil", T("Anti-exfil"), {
    verified: [T("Verified"), "ok"],
    failed: [T("Failed"), "bad"],
    not_available: [T("Not available"), "neutral"],
    unknown: [T("Unknown"), "warn"],
  }],
  ["changeOutputs", T("Change outputs"), {
    verified: [T("Verified"), "ok"],
    not_from_wallet: [T("Not from the loaded key"), "bad"],
    unverified: [T("Unverified"), "warn"],
    none_presented: [T("None presented"), "neutral"],
    not_checked: [T("Not checked"), "neutral"],
    unknown: [T("Unknown"), "warn"],
  }],
];

// The Inspector run path does not wire nonce, anti-exfil or wallet inputs
// into the audit, so these three checks report "not checked" every time.
// While all three do, they collapse into one "Not checked here" line; any
// other value — a problem, a pass, or Unknown — brings all three rows back,
// so a result is never folded away.
const UNCHECKED = { nonceReuse: "not_checked", antiExfil: "not_available", changeOutputs: "not_checked" };

// A sighash value as the usual token. These are technical names, marked
// data-i18n-skip so the translation sweep leaves them alone.
const sighashToken = (value) => {
  if (typeof value !== "number") return "unknown";
  const base = value & 0x7f;
  const name = value === 0 ? "SIGHASH_DEFAULT" : base === 1 ? "SIGHASH_ALL" : base === 2 ? "SIGHASH_NONE" : base === 3 ? "SIGHASH_SINGLE" : "0x" + value.toString(16);
  return name + ((value & 0x80) && base >= 1 && base <= 3 ? " | ANYONECANPAY" : "");
};

// A PSBT field name, or the pair's type byte when the decoder did not know
// the field: plain text for a sentence placeholder, and a data-i18n-skip
// span when the name stands alone as a detail line.
const fieldName = (ev) => ev?.name
  ? String(ev.name)
  : t("unknown pair (type 0x{type})", { type: String(ev?.key ?? "").slice(0, 2) || "??" });
const fieldNameHtml = (ev) => ev?.name ? `<span data-i18n-skip>${escapeHtml(ev.name)}</span>` : escapeHtml(fieldName(ev));

const whereDetail = (ev) => ev?.scope === "global"
  ? T("in the global map")
  : ev?.scope === "output-map"
    ? T("on output {n}", { n: ev.index })
    : ev?.scope === "input-map"
      ? T("on input {n}", { n: ev.index })
      : null;

// Script → address goes through rust-bitcoin (the same addressFromScript
// the inspector and editor use); unknown templates fall back to the
// shortened script hex.
const scriptAddress = (scriptHex, network) => {
  try {
    return addressFromScript(hexCoder.decode(String(scriptHex ?? "")), network);
  } catch {
    return null;
  }
};

const changeTargetDetail = (ev, network) => {
  const parts = [];
  const address = scriptAddress(ev.scriptPubKey, network);
  if (address) parts.push(T("address {address}", { address }));
  else if (ev.scriptPubKey) parts.push(T("script {script}", { script: shorten(ev.scriptPubKey, 16, 8) }));
  if (ev.fingerprint) parts.push(T("fingerprint {fingerprint}", { fingerprint: ev.fingerprint }));
  return parts.join(" · ") || null;
};

const changeDetail = (ev, isInput) => {
  if (ev.kind === "added") return T(isInput ? "The returned transaction has an input you did not send." : "The returned transaction has an output you did not send.");
  if (ev.kind === "removed") return T(isInput ? "An input you sent is missing from the returned transaction." : "An output you sent is missing from the returned transaction.");
  if (ev.kind === "unpaired") return T(isInput ? "The inputs could not be paired one-to-one between the two PSBTs." : "The outputs could not be paired one-to-one between the two PSBTs.");
  if (ev.field && String(ev.field).endsWith(".value")) return T("Amount changed: {before} → {after} sats.", { before: String(ev.before), after: String(ev.after) });
  if (ev.field && String(ev.field).endsWith(".scriptPubKey")) return T("The output script (address) changed.");
  if (ev.field) return T("Field {field} was changed.", { field: String(ev.field).split(".").pop() });
  return null;
};

// One finding's approved one-line text plus an optional detail line. Each
// sentence is one translator call; the input or output number is a
// placeholder, and a finding without an index reads "an input"/"an output".
// Technical values that stand alone (field names, sighash tokens) are
// escaped here and marked data-i18n-skip.
const findingText = (f, network) => {
  const ev = f.evidence ?? {};
  const i = f.index ?? ev.index ?? null;
  const none = i === null;
  const n = { n: i };
  const token = (value) => `<span data-i18n-skip>${escapeHtml(sighashToken(value))}</span>`;
  switch (f.code) {
    case "DOC_UNDECODABLE": {
      const sent = ev.side === "before";
      const reason = t(lookup({
        malformed_document: "its contents are malformed",
        rust_bitcoin_error: "the reference parser rejected it",
        tx_sanity_error: "its transaction is invalid",
        duplicate_keys: "it contains duplicate keys",
      }, ev.reason) ?? "it could not be decoded");
      return [T("One of the two PSBTs could not be read safely — the audit cannot vouch for it."), T(sent ? "The PSBT you sent: {reason}." : "The returned PSBT: {reason}.", { reason })];
    }
    case "TX_REORDERED": {
      const outputs = ev.dimension === "outputs";
      return [T(outputs ? "The signer changed the order of the outputs." : "The signer changed the order of the inputs."), T("The same items appear in a different order.")];
    }
    case "TX_INPUT_CHANGED":
      return [T(none ? "An input is not what you sent." : "Input {n} is not what you sent.", n), changeDetail(ev, true)];
    case "TX_OUTPUT_CHANGED":
      return [T(none ? "An output is not what you sent." : "Output {n} is not what you sent.", n), changeDetail(ev, false)];
    case "TX_VERSION_CHANGED":
      return [T("The transaction version changed ({before} → {after}).", { before: String(ev.before), after: String(ev.after) }), null];
    case "TX_LOCKTIME_CHANGED":
      return [T("The locktime changed ({before} → {after}).", { before: String(ev.before), after: String(ev.after) }), null];
    case "UTXO_DECLARATION_CHANGED": {
      const amounts = ev.beforeValue !== undefined && ev.afterValue !== undefined;
      return [
        T(none ? "What an input claims to spend was changed." : "What input {n} claims to spend was changed.", n),
        T(amounts ? "{before} → {after} sats. The fee and every signature commitment change with it." : "The fee and every signature commitment change with it.", { before: String(ev.beforeValue), after: String(ev.afterValue) }),
      ];
    }
    case "UNEXPECTED_SIGNER": {
      const parts = [];
      const count = Array.isArray(ev.expectedKeys) ? ev.expectedKeys.length : 0;
      if (ev.pubkey) parts.push(T("key {key}", { key: shorten(ev.pubkey) }));
      parts.push(T(count === 1 ? "{count} key named in your PSBT" : "{count} keys named in your PSBT", { count }));
      return [T(none ? "An input was signed by a key your PSBT does not name." : "Input {n} was signed by a key your PSBT does not name.", n), parts.join(" · ")];
    }
    case "SIGNATURE_CHANGED":
      return [T(none ? "A signature on an input was altered." : "A signature on input {n} was altered.", n), ev.name ? fieldNameHtml(ev) : null];
    case "SIGNATURE_REMOVED":
      return [T(none ? "A signature on an input was removed." : "A signature on input {n} was removed.", n), ev.name ? fieldNameHtml(ev) : null];
    case "SIGNATURE_MALFORMED":
      return [T(none ? "A new signature on an input is malformed." : "A new signature on input {n} is malformed.", n), ev.decodeError ? escapeHtml(hodlNeutralizeControls(String(ev.decodeError))) : null];
    case "SIGNATURE_INVALID":
      return [T(none ? "The new signature on an input does not verify." : "The new signature on input {n} does not verify.", n), null];
    case "SIGNATURE_UNVERIFIED": {
      const reason = T(lookup({
        budget_exhausted: "The verification budget ran out before this signature could be checked.",
        verification_unavailable: "No signature verification was available for this run.",
        not_checked: "This signature was not checked.",
      }, ev.reason) ?? "This signature was not checked.");
      return [T(none ? "The new signature on an input could not be checked." : "The new signature on input {n} could not be checked.", n), reason];
    }
    case "SIGHASH_WEAK":
      return [T(none ? "The new signature on an input does not commit to the whole transaction." : "The new signature on input {n} does not commit to the whole transaction.", n), token(ev.appended)];
    case "SIGHASH_MISMATCH":
      return [
        T(none ? "The signature on an input commits to a different sighash than declared." : "The signature on input {n} commits to a different sighash than declared.", n),
        T("appended {appended} vs declared {declared}", { appended: sighashToken(ev.appended), declared: sighashToken(ev.declared) }),
      ];
    case "SIGHASH_UNDEFINED": {
      const value = typeof ev.value === "number" ? ev.value.toString(16) : "??";
      const appended = ev.source === "appended";
      return [
        T(none ? "An input uses an undefined sighash value (0x{value})." : "Input {n} uses an undefined sighash value (0x{value}).", { n: i, value }),
        ev.source ? T(appended ? "Reported from the signature's appended byte." : "Reported from the declared sighash field.") : null,
      ];
    }
    case "SIGHASH_DECLARATION_CHANGED":
      return [T(none ? "The signer changed or removed the sighash declaration on an input." : "The signer changed or removed the sighash declaration on input {n}.", n), null];
    case "SIGHASH_DECLARATION_ADDED": {
      const value = typeof ev.value === "number" ? ev.value : null;
      if (f.severity === "info") return [T(none ? "A full-commitment sighash was declared on an input." : "A full-commitment sighash was declared on input {n}.", n), token(value)];
      if (f.severity === "warning") return [T(none ? "The weak sighash declared on an input is the one your PSBT requested." : "The weak sighash declared on input {n} is the one your PSBT requested.", n), token(value)];
      return [T(none ? "A weak sighash was declared on an input." : "A weak sighash was declared on input {n}.", n), token(value)];
    }
    case "SIGHASH_DECLARATION_INVALID":
      return [T(none ? "The PSBT you sent declares an invalid sighash on an input." : "The PSBT you sent declares an invalid sighash on input {n}.", n), null];
    case "FINALIZATION_INVALID": {
      const reason = T(lookup({
        no_signatures: "No verifiable signature was provided for the final script.",
        signature_invalid: "A final signature is invalid.",
        unverified: "The final script could not be checked.",
      }, ev.reason) ?? "The final script could not be checked.");
      return [T(none ? "An input was finalized, but the final script could not be verified." : "Input {n} was finalized, but the final script could not be verified.", n), reason];
    }
    case "FINALIZED":
      return [T(none ? "An input was finalized." : "Input {n} was finalized.", n), T("The final script verifies.")];
    case "FIELD_REMOVED":
      return [T(none ? "A field was removed from an input without valid finalization." : "A field was removed from input {n} without valid finalization.", n), fieldNameHtml(ev)];
    case "FINGERPRINT_MISMATCH": {
      const detail = ev.fingerprintBefore !== undefined && ev.fingerprintAfter !== undefined
        ? T("fingerprint {before} → {after}", { before: String(ev.fingerprintBefore), after: String(ev.fingerprintAfter) })
        : ev.pathBefore !== undefined && ev.pathAfter !== undefined
          ? T("path {before} → {after}", { before: String(ev.pathBefore), after: String(ev.pathAfter) })
          : null;
      return [T("A key's origin changed."), detail];
    }
    case "METADATA_REMOVED":
      return [T("The signer removed PSBT field {field}.", { field: fieldName(ev) }), whereDetail(ev)];
    case "METADATA_CHANGED":
      return [T("The signer changed PSBT field {field}.", { field: fieldName(ev) }), whereDetail(ev)];
    case "METADATA_ADDED":
      return [T("The signer added PSBT field {field}.", { field: fieldName(ev) }), whereDetail(ev)];
    case "METADATA_ENRICHMENT":
      return [T("The signer added expected PSBT field {field}.", { field: fieldName(ev) }), whereDetail(ev)];
    case "CHANGE_NOT_FROM_WALLET":
      return [T(none ? "An output claims to be your change but does not belong to the loaded key." : "Output {n} claims to be your change but does not belong to the loaded key.", n), changeTargetDetail(ev, network)];
    case "CHANGE_UNVERIFIED":
      return [T(none ? "An output looks like change but could not be verified." : "Output {n} looks like change but could not be verified.", n), T("The fingerprint matches the loaded key, but no wallet script set was available to compare.")];
    case "CHANGE_VERIFIED":
      return [T(none ? "An output is change back to your wallet." : "Output {n} is change back to your wallet.", n), changeTargetDetail(ev, network)];
    case "NONCE_REUSE":
      return [T("A signature reuses a nonce seen before — this can leak the private key."), T("Do not broadcast.")];
    case "NONCE_CROSS_KEY":
      return [T("The same nonce appears under two different keys — this can leak a private key."), T("Do not broadcast.")];
    case "NONCE_REUSE_POSSIBLE":
      return [T("Possible nonce reuse — could not confirm."), null];
    case "NONCE_COVERAGE_INCOMPLETE":
      return [T("The nonce check did not cover every signature."), null];
    case "ANTIEXFIL_FAILED":
      return [T("The anti-exfiltration check failed."), ev.signer ? T("Signer: {signer}.", { signer: hodlNeutralizeControls(String(ev.signer)) }) : null];
    case "SIGNER_UNKNOWN":
      return [T(none ? "An input has a new signature, but the PSBT you sent names no signing keys for it." : "Input {n} has a new signature, but the PSBT you sent names no signing keys for it.", n), null];
    case "MUSIG2_MATERIAL_ADDED":
      return [T(none ? "MuSig2 signing data was added to an input." : "MuSig2 signing data was added to input {n}.", n), T("{field} — not verified.", { field: fieldName(ev) })];
    case "SIGNATURE_ADDED": {
      const parts = [];
      if (ev.pubkey) parts.push(T("key {key}", { key: shorten(ev.pubkey) }));
      if (typeof ev.sighashAppended === "number") parts.push(token(ev.sighashAppended));
      return [T(none ? "New signature on an input." : "New signature on input {n}.", n), parts.join(" · ") || null];
    }
    case "ORIGIN_INCONSISTENT": {
      const reason = T(lookup({
        mismatch: "does not derive from the matching global xpub",
        hardened_gap: "not checked (hardened gap on the remaining path)",
        malformed: "origin field is malformed",
        malformed_key: "key is not valid for this record type (not checked)",
        budget_exhausted: "not checked (analysis budget exhausted)",
      }, ev.reason) ?? "not checked (no applicable global xpub)");
      return [T("A key's stated origin does not match the global xpub."), reason];
    }
    default:
      // A code this view predates still renders, escaped, never dropped.
      return [`<span data-i18n-skip>${escapeHtml(String(f.code ?? "unknown finding"))}</span>`, null];
  }
};

const findingRow = (f, network) => {
  const [headline, detail] = findingText(f, network);
  const tone = SEVERITY_TONE[f?.severity] ?? "psbt-warn";
  return `<li${tone ? ` class="${tone}"` : ""} data-audit-code="${escapeHtml(String(f?.code ?? "unknown"))}">${headline}${detail ? `<br><span class="muted">${detail}</span>` : ""}</li>`;
};

// The technical diff prints each pair's decodeError verbatim (psbt-editor.js
// pairCell). That text comes from the PSBT, so it is untrusted: neutralize
// bidi and invisible codepoints in the copies handed to the diff, exactly as
// the finding rows do, so a hostile decodeError cannot reorder the line.
const neutralizePairText = (pair) => {
  if (!pair || typeof pair !== "object" || typeof pair.decodeError !== "string") return pair;
  return { ...pair, decodeError: hodlNeutralizeControls(pair.decodeError) };
};
const neutralizeDocText = (doc) => {
  if (!doc || typeof doc !== "object") return doc;
  const copy = { ...doc };
  if (Array.isArray(doc.globals)) copy.globals = doc.globals.map(neutralizePairText);
  if (Array.isArray(doc.inputs)) copy.inputs = doc.inputs.map((map) => (Array.isArray(map) ? map.map(neutralizePairText) : map));
  if (Array.isArray(doc.outputs)) copy.outputs = doc.outputs.map((map) => (Array.isArray(map) ? map.map(neutralizePairText) : map));
  return copy;
};

const heading = () => `<p class="label psbt-section-label">${T("PSBT signer audit")}</p>`;

// The audit report as one section, in the analysis's shape: the heading,
// the verdict as bold status text, the checks, the grouped findings, the
// collapsed technical diff, and the closing limitation note, which always
// renders. The section is prepended to the Inspector's output, so the live
// region announces the heading and verdict first.
export const psbtSignerAuditHtml = (report, beforeDoc, afterDoc, network, { copyIcon = () => "" } = {}) => {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  // Defense in depth: a signature the engine could not check (or found
  // invalid) is never painted as a pass, whatever the verdict says.
  const signatures = report?.checks?.signatures;
  // A missing report or verdict is never a pass: only an exact "pass" may
  // paint the pass tier, so a report the engine did not produce cannot show
  // "No changes to your transaction".
  const tier = report?.verdict !== "pass" || signatures === "unverified" || signatures === "invalid"
    ? "fail"
    : findings.some((f) => f.severity === "warning") ? "pass-warnings" : "pass";
  const verdict = tier === "fail"
    ? `<p class="psbt-bad" data-audit-verdict="fail"><strong>${T("Do not broadcast this PSBT.")}</strong> ${T("One or more critical checks failed — details below.")}</p>`
    : tier === "pass-warnings"
      ? `<p class="psbt-warn" data-audit-verdict="pass-warnings"><strong>${T("Your transaction is unchanged — review the warnings below.")}</strong></p>`
      : `<p class="psbt-ok" data-audit-verdict="pass"><strong>${T("No changes to your transaction.")}</strong></p>`;
  // One label/value row per check and for the signature count, as in the
  // analysis rows: the value sits beside its label and its tone only
  // colours it. A neutral value takes no class (the text colour).
  const valueRow = (label, value, key, tone) => {
    const className = TONE_CLASS[tone] ?? "psbt-warn";
    return `<li><span class="label">${label}</span> — <span${className ? ` class="${className}"` : ""} data-audit-value data-audit-check="${key}" data-audit-tone="${tone}">${value}</span></li>`;
  };
  const checks = report?.checks ?? {};
  const folded = Object.entries(UNCHECKED).every(([key, value]) => checks[key] === value);
  const visibleChecks = checkRows().filter(([key]) => !(folded && Object.hasOwn(UNCHECKED, key)));
  const tones = [];
  const rows = visibleChecks.map(([key, label, values]) => {
    const [text, tone] = lookup(values, checks[key]) ?? [T("Unknown"), "warn"];
    tones.push(tone);
    return valueRow(label, text, key, tone);
  }).join("");
  const stats = report?.stats && report.stats.newSignatures > 0
    ? valueRow(T("New signatures"), escapeHtml(String(report.stats.newSignatures)), "newSignatures", "neutral")
    : "";
  // The check rows collapse into one block, but a block that holds a problem
  // or a warning never does: it opens and says so, whatever the tier.
  const rowsHtml = rows + stats;
  // The block's own state, never the rendered class names: a bad or warn
  // check value opens it, whatever the tier.
  const rowsProblem = tones.some((tone) => tone === "bad" || tone === "warn");
  // The "Not checked here" note renders directly after the checks disclosure,
  // outside it: a passing audit folds the checks, and the caveat must stay
  // visible. It draws no rule of its own — the next group's label is the one
  // separator — so it is a plain muted line, never a section label.
  const unchecked = folded
    ? `<p class="muted" data-audit-unchecked="${Object.keys(UNCHECKED).join(" ")}">${T("Not checked here: nonce reuse, anti-exfil, change outputs.")}</p>`
    : "";
  const checksBlock = `<details class="derivation-advanced" data-audit-checks${tier !== "pass" || rowsProblem ? " open data-has-problem" : ""}><summary>${T("Show the {n} checks", { n: visibleChecks.length + (stats ? 1 : 0) })}</summary><ul>${rowsHtml}</ul></details>${unchecked}`;
  const groupOf = (code) => {
    const at = FINDING_GROUPS.findIndex((codes) => codes.includes(code));
    return at === -1 ? FINDING_GROUPS.length - 1 : at;
  };
  const buckets = FINDING_GROUPS.map(() => []);
  findings.forEach((f, order) => buckets[groupOf(f?.code)].push({ f, order }));
  for (const bucket of buckets) bucket.sort((a, b) => (SEVERITY_RANK[a.f?.severity] ?? 1) - (SEVERITY_RANK[b.f?.severity] ?? 1) || a.order - b.order);
  const titles = groupTitles();
  const groups = buckets.map((items, groupIndex) => {
    if (!items.length) return "";
    const shown = items.slice(0, GROUP_LIMIT), more = items.length - shown.length;
    const list = shown.map(({ f }) => findingRow(f, network)).join("");
    return `<p class="label psbt-section-label">${titles[groupIndex]}</p><ul>${list}${more > 0 ? `<li class="muted">${T("…and {n} more.", { n: more })}</li>` : ""}</ul>`;
  }).join("");
  const diff = report?.diff
    ? `<details class="derivation-advanced" data-audit-diff><summary>${T("Show every difference (technical)")}</summary>${psbtDiffHtml(report.diff, neutralizeDocText(beforeDoc), neutralizeDocText(afterDoc), network, { copyIcon, beforeLabel: t("the PSBT you sent"), afterLabel: t("the returned PSBT") })}</details>`
    : "";
  return `<section class="psbt-analysis-summary" data-audit-section data-audit-tier="${tier}" aria-label="${TA("PSBT signer audit")}">${heading()}${verdict}${checksBlock}${groups}${diff}<p class="edge-note is-private" data-audit-limitation>${T("This audit checks what changed between the two PSBTs and what EntropyLab can verify — signatures are checked against the previous outputs the PSBT claims, not the blockchain. It does not prove the signing device or its firmware is trustworthy.")}</p></section>`;
};

// The fail-closed read error: there is no verdict to show, only what kept
// the audit from running — named for the PSBT it is about, so a raw
// transaction in the Inspector is never blamed on the PSBT you sent. app.js
// passes { kind, detail }: "returned-raw" (the inspected payload is a raw
// transaction), "sent-raw" (the sent field decodes, but not to a PSBT),
// "sent-unreadable" (the sent field does not decode; detail is the parser's
// message), or "failed" (anything else). A bare string is treated as
// "failed" with that detail.
export const psbtSignerAuditErrorHtml = (error) => {
  const { kind, detail } = typeof error === "object" && error !== null ? error : { kind: "failed", detail: error };
  const headline = kind === "returned-raw"
    ? T("The payload inspected above is a raw transaction, not a PSBT — the signer audit compares two PSBTs.")
    : kind === "sent-raw"
      ? T("The “PSBT you sent” field does not hold a PSBT — paste the PSBT you gave the signer, in base64 or hex.")
      : kind === "sent-unreadable"
        ? T("The PSBT you sent could not be read — check the base64 or hex.")
        : T("The signer audit could not run on these two PSBTs.");
  const kindName = kind === "returned-raw" || kind === "sent-raw" || kind === "sent-unreadable" ? kind : "failed";
  const extra = typeof detail === "string" && detail.trim() ? `<p class="muted" data-audit-error-detail>${escapeHtml(hodlNeutralizeControls(detail))}</p>` : "";
  return `<section class="psbt-analysis-summary" data-audit-section aria-label="${TA("PSBT signer audit")}">${heading()}<p class="psbt-bad" data-audit-error="${kindName}"><strong>${headline}</strong></p>${extra}</section>`;
};
