// HTML rendering for the PSBT Signer Audit (engine: psbt-signer-audit.js).
//
// Pure string building, unit-tested under Node; app.js prepends the result
// to the PSBT Inspector's output when the optional "PSBT you sent" field is
// filled. The view never decides safety: it renders the engine's verdict,
// checks and findings exactly as reported — a fail can never paint as a
// pass, and a check value the maps below do not know renders as "Unknown"
// in the warning tone, never green. Every PSBT-derived string passes
// escapeHtml before it reaches the markup, and free text (parser and
// decoder messages) is additionally neutralized against bidi and invisible
// codepoints. Markup and escaping follow psbt-editor.js; user-visible
// English is plain text in the markup for the content sweep to translate.
import { addressFromScript } from "./addresses.js";
import { hex as hexCoder } from "./coders.js";
import { hodlNeutralizeControls } from "./i18n-sanitize.js";
import { psbtDiffHtml } from "./psbt-editor.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const shorten = (hex, head = 10, tail = 6) => {
  const text = String(hex ?? "");
  return text.length > head + tail + 2 ? text.slice(0, head) + "…" + text.slice(-tail) : text;
};

// Findings list at most this many rows per group, then one "…and N more"
// line (the psbtSanitizeHtml slice(0, 8) precedent). The cap only limits
// what is listed — the verdict is the engine's and always counts every
// finding.
const GROUP_LIMIT = 8;

// Group order is fixed: read errors first, then what matters most before
// broadcast — the transaction itself, signatures and keys, the user's
// change, nonce/anti-exfil, and everything else last. A code no group names
// (a newer engine) falls into the last group rather than vanishing.
const FINDING_GROUPS = [
  ["Read errors", ["DOC_UNDECODABLE"]],
  ["Your transaction", ["TX_REORDERED", "TX_INPUT_CHANGED", "TX_OUTPUT_CHANGED", "TX_VERSION_CHANGED", "TX_LOCKTIME_CHANGED", "UTXO_DECLARATION_CHANGED"]],
  ["Signatures and keys", ["UNEXPECTED_SIGNER", "SIGNATURE_CHANGED", "SIGNATURE_REMOVED", "SIGNATURE_MALFORMED", "SIGNATURE_INVALID", "SIGNATURE_UNVERIFIED", "SIGHASH_WEAK", "SIGHASH_MISMATCH", "SIGHASH_UNDEFINED", "SIGHASH_DECLARATION_CHANGED", "SIGHASH_DECLARATION_ADDED", "SIGHASH_DECLARATION_INVALID", "FINALIZATION_INVALID", "FIELD_REMOVED", "FINGERPRINT_MISMATCH", "SIGNER_UNKNOWN", "MUSIG2_MATERIAL_ADDED", "SIGNATURE_ADDED", "FINALIZED"]],
  ["Your change", ["CHANGE_NOT_FROM_WALLET", "CHANGE_UNVERIFIED", "CHANGE_VERIFIED"]],
  ["Nonce and anti-exfil", ["NONCE_REUSE", "NONCE_CROSS_KEY", "NONCE_REUSE_POSSIBLE", "NONCE_COVERAGE_INCOMPLETE", "ANTIEXFIL_FAILED"]],
  ["Other PSBT data", ["METADATA_REMOVED", "METADATA_CHANGED", "METADATA_ADDED", "METADATA_ENRICHMENT", "ORIGIN_INCONSISTENT"]],
];

const SEVERITY_TONE = { critical: "psbt-bad", warning: "psbt-warn", info: "muted" };
const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 };
const TONE_CLASS = { ok: "psbt-ok", warn: "psbt-warn", bad: "psbt-bad", muted: "muted" };

// The nine checks, in display order. Each known value maps to a label and a
// tone; a value the map does not know renders as "Unknown" in the warning
// tone — never green.
const CHECK_ROWS = [
  ["transactionBody", "Transaction body", {
    unchanged: ["Unchanged", "ok"],
    changed: ["Changed", "bad"],
    reordered: ["Reordered", "bad"],
    unknown: ["Unknown", "warn"],
  }],
  ["utxoDeclarations", "UTXO declarations", {
    unchanged: ["Unchanged", "ok"],
    changed: ["Changed", "bad"],
    unknown: ["Unknown", "warn"],
  }],
  ["signatures", "Signatures", {
    valid: ["Valid", "ok"],
    invalid: ["Invalid", "bad"],
    unverified: ["Unverified", "bad"],
    removed_or_changed: ["Removed or changed", "bad"],
    none_added: ["None added", "muted"],
    unknown: ["Unknown", "warn"],
  }],
  ["sighashPolicy", "Sighash policy", {
    full_commitment: ["Full commitment", "ok"],
    weak: ["Weak", "bad"],
    weak_as_requested: ["Weak, as requested", "warn"],
    mismatch: ["Mismatch", "bad"],
    undefined: ["Undefined", "bad"],
    none: ["None", "muted"],
    unknown: ["Unknown", "warn"],
  }],
  ["signerKeys", "Signer keys", {
    match: ["Match", "ok"],
    unexpected: ["Unexpected", "bad"],
    unknown: ["Unknown", "bad"],
    no_new_signatures: ["No new signatures", "muted"],
  }],
  ["metadata", "PSBT metadata", {
    unchanged: ["Unchanged", "ok"],
    additions: ["Additions", "warn"],
    mutated: ["Mutated", "bad"],
    unknown: ["Unknown", "warn"],
  }],
  ["nonceReuse", "Nonce reuse", {
    none_found: ["None found", "ok"],
    reuse: ["Reuse found", "bad"],
    cross_key: ["Cross-key reuse", "bad"],
    possible: ["Possible", "warn"],
    incomplete: ["Incomplete", "warn"],
    not_checked: ["Not checked", "muted"],
    unknown: ["Unknown", "warn"],
  }],
  ["antiExfil", "Anti-exfil", {
    verified: ["Verified", "ok"],
    failed: ["Failed", "bad"],
    not_available: ["Not available", "muted"],
    unknown: ["Unknown", "warn"],
  }],
  ["changeOutputs", "Change outputs", {
    verified: ["Verified", "ok"],
    not_from_wallet: ["Not from the loaded key", "bad"],
    unverified: ["Unverified", "warn"],
    none_presented: ["None presented", "muted"],
    not_checked: ["Not checked", "muted"],
    unknown: ["Unknown", "warn"],
  }],
];

// A sighash value as the usual token. These are technical names, marked
// data-i18n-skip so the translation sweep leaves them alone.
const sighashToken = (value) => {
  if (typeof value !== "number") return "unknown";
  const base = value & 0x7f;
  const name = value === 0 ? "SIGHASH_DEFAULT" : base === 1 ? "SIGHASH_ALL" : base === 2 ? "SIGHASH_NONE" : base === 3 ? "SIGHASH_SINGLE" : "0x" + value.toString(16);
  return name + ((value & 0x80) && base >= 1 && base <= 3 ? " | ANYONECANPAY" : "");
};

// A PSBT field name, or the pair's type byte when the decoder did not know
// the field. Technical names: data-i18n-skip.
const fieldNameHtml = (ev) => ev?.name
  ? `<span data-i18n-skip>${escapeHtml(ev.name)}</span>`
  : `unknown pair (type 0x${escapeHtml(String(ev?.key ?? "").slice(0, 2) || "??")})`;

const whereDetail = (ev) => ev?.scope === "global"
  ? "in the global map"
  : ev?.scope === "output-map"
    ? `on output ${ev.index}`
    : ev?.scope === "input-map"
      ? `on input ${ev.index}`
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
  if (address) parts.push(`address ${escapeHtml(address)}`);
  else if (ev.scriptPubKey) parts.push(`script <span data-i18n-skip>${escapeHtml(shorten(ev.scriptPubKey, 16, 8))}</span>`);
  if (ev.fingerprint) parts.push(`fingerprint <span data-i18n-skip>${escapeHtml(ev.fingerprint)}</span>`);
  return parts.join(" · ") || null;
};

const changeDetail = (ev, kind) => {
  if (ev.kind === "added") return `The returned transaction has ${kind === "input" ? "an input" : "an output"} you did not send.`;
  if (ev.kind === "removed") return `${kind === "input" ? "An input" : "An output"} you sent is missing from the returned transaction.`;
  if (ev.kind === "unpaired") return `The ${kind}s could not be paired one-to-one between the two PSBTs.`;
  if (ev.field && String(ev.field).endsWith(".value")) return `Amount changed: ${escapeHtml(String(ev.before))} → ${escapeHtml(String(ev.after))} sats.`;
  if (ev.field && String(ev.field).endsWith(".scriptPubKey")) return "The output script (address) changed.";
  if (ev.field) return `Field ${escapeHtml(String(ev.field).split(".").pop())} was changed.`;
  return null;
};

// One finding's approved one-line text plus an optional detail line. Every
// interpolation is escaped here; field names and sighash tokens are
// technical names and marked data-i18n-skip.
const findingText = (f, network) => {
  const ev = f.evidence ?? {};
  const i = f.index ?? ev.index ?? null;
  const input = i === null ? "An input" : `Input ${i}`;
  const output = i === null ? "An output" : `Output ${i}`;
  const onInput = i === null ? "an input" : `input ${i}`;
  const token = (value) => `<span data-i18n-skip>${escapeHtml(sighashToken(value))}</span>`;
  switch (f.code) {
    case "DOC_UNDECODABLE": {
      const side = ev.side === "before" ? "The PSBT you sent" : "The returned PSBT";
      const reason = {
        malformed_document: "its contents are malformed",
        rust_bitcoin_error: "the reference parser rejected it",
        tx_sanity_error: "its transaction is invalid",
        duplicate_keys: "it contains duplicate keys",
      }[ev.reason] ?? "it could not be decoded";
      return ["One of the two PSBTs could not be read safely — the audit cannot vouch for it.", `${side}: ${reason}.`];
    }
    case "TX_REORDERED":
      return [`The signer changed the order of the ${ev.dimension === "outputs" ? "outputs" : "inputs"}.`, "The same items appear in a different order."];
    case "TX_INPUT_CHANGED":
      return [`${input} is not what you sent.`, changeDetail(ev, "input")];
    case "TX_OUTPUT_CHANGED":
      return [`${output} is not what you sent.`, changeDetail(ev, "output")];
    case "TX_VERSION_CHANGED":
      return [`The transaction version changed (${escapeHtml(String(ev.before))} → ${escapeHtml(String(ev.after))}).`, null];
    case "TX_LOCKTIME_CHANGED":
      return [`The locktime changed (${escapeHtml(String(ev.before))} → ${escapeHtml(String(ev.after))}).`, null];
    case "UTXO_DECLARATION_CHANGED": {
      const amounts = ev.beforeValue !== undefined && ev.afterValue !== undefined ? `${escapeHtml(String(ev.beforeValue))} → ${escapeHtml(String(ev.afterValue))} sats. ` : "";
      return [`What ${onInput} claims to spend was changed.`, `${amounts}The fee and every signature commitment change with it.`];
    }
    case "UNEXPECTED_SIGNER": {
      const parts = [];
      if (ev.pubkey) parts.push(`key <span data-i18n-skip>${escapeHtml(shorten(ev.pubkey))}</span>`);
      parts.push(`${Array.isArray(ev.expectedKeys) ? ev.expectedKeys.length : 0} key(s) named in your PSBT`);
      return [`${input} was signed by a key your PSBT does not name.`, parts.join(" · ")];
    }
    case "SIGNATURE_CHANGED":
      return [`A signature on ${onInput} was altered.`, ev.name ? fieldNameHtml(ev) : null];
    case "SIGNATURE_REMOVED":
      return [`A signature on ${onInput} was removed.`, ev.name ? fieldNameHtml(ev) : null];
    case "SIGNATURE_MALFORMED":
      return [`A new signature on ${onInput} is malformed.`, ev.decodeError ? escapeHtml(hodlNeutralizeControls(String(ev.decodeError))) : null];
    case "SIGNATURE_INVALID":
      return [`The new signature on ${onInput} does not verify.`, null];
    case "SIGNATURE_UNVERIFIED": {
      const reason = {
        budget_exhausted: "The verification budget ran out before this signature could be checked.",
        verification_unavailable: "No signature verification was available for this run.",
        not_checked: "This signature was not checked.",
      }[ev.reason] ?? "This signature was not checked.";
      return [`The new signature on ${onInput} could not be checked.`, reason];
    }
    case "SIGHASH_WEAK":
      return [`The new signature on ${onInput} does not commit to the whole transaction.`, token(ev.appended)];
    case "SIGHASH_MISMATCH":
      return [`The signature on ${onInput} commits to a different sighash than declared.`, `appended ${token(ev.appended)} vs declared ${token(ev.declared)}`];
    case "SIGHASH_UNDEFINED":
      return [`${input} uses an undefined sighash value (0x${typeof ev.value === "number" ? ev.value.toString(16) : "??"}).`, ev.source ? `Reported from ${ev.source === "appended" ? "the signature's appended byte" : "the declared sighash field"}.` : null];
    case "SIGHASH_DECLARATION_CHANGED":
      return [`The signer changed or removed the sighash declaration on ${onInput}.`, null];
    case "SIGHASH_DECLARATION_ADDED": {
      const value = typeof ev.value === "number" ? ev.value : null;
      if (f.severity === "info") return [`A full-commitment sighash was declared on ${onInput}.`, token(value)];
      if (f.severity === "warning") return [`The weak sighash declared on ${onInput} is the one your PSBT requested.`, token(value)];
      return [`A weak sighash was declared on ${onInput}.`, token(value)];
    }
    case "SIGHASH_DECLARATION_INVALID":
      return [`The PSBT you sent declares an invalid sighash on ${onInput}.`, null];
    case "FINALIZATION_INVALID": {
      const reason = {
        no_signatures: "No verifiable signature was provided for the final script.",
        signature_invalid: "A final signature is invalid.",
        unverified: "The final script could not be checked.",
      }[ev.reason] ?? "The final script could not be checked.";
      return [`${input} was finalized, but the final script could not be verified.`, reason];
    }
    case "FINALIZED":
      return [`${input} was finalized.`, "The final script verifies."];
    case "FIELD_REMOVED":
      return [`A field was removed from ${onInput} without valid finalization.`, fieldNameHtml(ev)];
    case "FINGERPRINT_MISMATCH": {
      const detail = ev.fingerprintBefore !== undefined && ev.fingerprintAfter !== undefined
        ? `fingerprint <span data-i18n-skip>${escapeHtml(ev.fingerprintBefore)}</span> → <span data-i18n-skip>${escapeHtml(ev.fingerprintAfter)}</span>`
        : ev.pathBefore !== undefined && ev.pathAfter !== undefined
          ? `path <span data-i18n-skip>${escapeHtml(ev.pathBefore)}</span> → <span data-i18n-skip>${escapeHtml(ev.pathAfter)}</span>`
          : null;
      return ["A key's origin changed.", detail];
    }
    case "METADATA_REMOVED":
      return [`The signer removed PSBT data: ${fieldNameHtml(ev)}.`, whereDetail(ev)];
    case "METADATA_CHANGED":
      return [`The signer changed PSBT data: ${fieldNameHtml(ev)}.`, whereDetail(ev)];
    case "METADATA_ADDED":
      return [`The signer added PSBT data: ${fieldNameHtml(ev)}.`, whereDetail(ev)];
    case "METADATA_ENRICHMENT":
      return [`The signer added expected data: ${fieldNameHtml(ev)}.`, whereDetail(ev)];
    case "CHANGE_NOT_FROM_WALLET":
      return [`${output} claims to be your change but does not belong to the loaded key.`, changeTargetDetail(ev, network)];
    case "CHANGE_UNVERIFIED":
      return [`${output} looks like change but could not be verified.`, "The fingerprint matches the loaded key, but no wallet script set was available to compare."];
    case "CHANGE_VERIFIED":
      return [`${output} is change back to your wallet.`, changeTargetDetail(ev, network)];
    case "NONCE_REUSE":
      return ["A signature reuses a nonce seen before — this can leak the private key.", "Do not broadcast."];
    case "NONCE_CROSS_KEY":
      return ["The same nonce appears under two different keys — this can leak a private key.", "Do not broadcast."];
    case "NONCE_REUSE_POSSIBLE":
      return ["Possible nonce reuse — could not confirm.", null];
    case "NONCE_COVERAGE_INCOMPLETE":
      return ["The nonce check did not cover every signature.", null];
    case "ANTIEXFIL_FAILED":
      return ["The anti-exfiltration check failed.", ev.signer ? `Signer: ${escapeHtml(String(ev.signer))}.` : null];
    case "SIGNER_UNKNOWN":
      return [`${input} has a new signature, but the PSBT you sent names no signing keys for it.`, null];
    case "MUSIG2_MATERIAL_ADDED":
      return [`MuSig2 signing data was added to ${onInput}.`, `${fieldNameHtml(ev)} — not verified.`];
    case "SIGNATURE_ADDED": {
      const parts = [];
      if (ev.pubkey) parts.push(`key <span data-i18n-skip>${escapeHtml(shorten(ev.pubkey))}</span>`);
      if (typeof ev.sighashAppended === "number") parts.push(token(ev.sighashAppended));
      return [`New signature on ${onInput}.`, parts.join(" · ") || null];
    }
    case "ORIGIN_INCONSISTENT": {
      const reason = {
        mismatch: "does not derive from the matching global xpub",
        hardened_gap: "not checked (hardened gap on the remaining path)",
        malformed: "origin field is malformed",
        malformed_key: "key is not valid for this record type (not checked)",
        budget_exhausted: "not checked (analysis budget exhausted)",
      }[ev.reason] ?? "not checked (no applicable global xpub)";
      return ["A key's stated origin does not match the global xpub.", reason];
    }
    default:
      // A code this view predates still renders, escaped, never dropped.
      return [`<span data-i18n-skip>${escapeHtml(String(f.code ?? "unknown finding"))}</span>`, null];
  }
};

const findingRow = (f, network) => {
  const [headline, detail] = findingText(f, network);
  const tone = SEVERITY_TONE[f?.severity] ?? "psbt-warn";
  return `<li class="${tone}" data-audit-code="${escapeHtml(String(f?.code ?? "unknown"))}">${headline}${detail ? `<br><span class="muted">${detail}</span>` : ""}</li>`;
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

// The audit report as one section: the verdict note first (it is prepended
// to the Inspector's output, so it is what the live region announces), then
// the nine checks, the grouped findings, the collapsed technical diff, and
// the closing limitation note, which always renders.
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
  const note = tier === "fail"
    ? `<p class="edge-note is-private" data-audit-verdict="fail"><strong>Do not broadcast this PSBT</strong><br>One or more critical checks failed — details below.</p>`
    : tier === "pass-warnings"
      ? `<p class="edge-note is-info" data-audit-verdict="pass-warnings"><strong>Your transaction is unchanged — review the warnings below</strong></p>`
      : `<p class="edge-note is-public" data-audit-verdict="pass"><strong>No changes to your transaction</strong></p>`;
  const checkRows = CHECK_ROWS.map(([key, label, values]) => {
    const [text, tone] = values[report?.checks?.[key]] ?? ["Unknown", "warn"];
    return `<li><span class="label">${label}</span> — <span class="${TONE_CLASS[tone]}" data-audit-check="${key}" data-audit-tone="${tone}">${text}</span></li>`;
  }).join("");
  const stats = report?.stats && report.stats.newSignatures > 0
    ? `<li><span class="label">New signatures</span> — <span class="muted">${escapeHtml(String(report.stats.newSignatures))}</span></li>`
    : "";
  const groupOf = (code) => {
    const at = FINDING_GROUPS.findIndex(([, codes]) => codes.includes(code));
    return at === -1 ? FINDING_GROUPS.length - 1 : at;
  };
  const buckets = FINDING_GROUPS.map(() => []);
  findings.forEach((f, order) => buckets[groupOf(f?.code)].push({ f, order }));
  for (const bucket of buckets) bucket.sort((a, b) => (SEVERITY_RANK[a.f?.severity] ?? 1) - (SEVERITY_RANK[b.f?.severity] ?? 1) || a.order - b.order);
  const groups = FINDING_GROUPS.map(([title], groupIndex) => {
    const items = buckets[groupIndex];
    if (!items.length) return "";
    const shown = items.slice(0, GROUP_LIMIT), more = items.length - shown.length;
    const rows = shown.map(({ f }) => findingRow(f, network)).join("");
    return `<p class="label psbt-section-label">${title}</p><ul>${rows}${more > 0 ? `<li class="muted">…and ${more} more.</li>` : ""}</ul>`;
  }).join("");
  const diff = report?.diff
    ? `<details class="derivation-advanced"><summary>Show every difference (technical)</summary>${psbtDiffHtml(report.diff, neutralizeDocText(beforeDoc), neutralizeDocText(afterDoc), network, { copyIcon, beforeLabel: "the PSBT you sent", afterLabel: "the returned PSBT" })}</details>`
    : "";
  return `<section class="psbt-analysis-summary" data-audit-section data-audit-tier="${tier}" aria-label="PSBT signer audit">${note}<p class="label psbt-section-label">PSBT signer audit</p><ul>${checkRows}${stats}</ul>${groups}${diff}<p class="edge-note is-muted" data-audit-limitation>This audit checks what changed between the two PSBTs and what EntropyLab can verify — signatures are checked against the previous outputs the PSBT claims, not the blockchain. It does not prove the signing device or its firmware is trustworthy.</p></section>`;
};

// The fail-closed read error: the sent PSBT (or the pair) did not decode,
// so there is no verdict to show — one red note, escaped, and no checks.
export const psbtSignerAuditErrorHtml = (message) =>
  `<section class="psbt-analysis-summary" data-audit-section aria-label="PSBT signer audit"><p class="edge-note is-private"><strong>The PSBT you sent could not be read — check base64 or hex.</strong><br>${escapeHtml(hodlNeutralizeControls(String(message ?? "")))}</p></section>`;
