// Offline payjoin detection UI (issue #446, BIP-78/77). The detection itself
// runs in the rust-bitcoin WebAssembly crate (psbt-wasm/src/payjoin.rs,
// reached through src/js/psbt-wasm.js); this module renders the two reports
// and wires the two-file checklist card shared by the PSBT / Nonce inspector
// (app.js) and the PSBT editor (psbt-editor.js).
//
// Framing is load-bearing: a single PSBT yields signals only (a payjoin
// proposal's shape also occurs in coinjoins and collaborative batches, and a
// fully re-signed payjoin looks like any other transaction), and the two-file
// report states the BIP-78 sender-checklist facts decidable from the files.
// Neither is a verdict, and nothing here contacts a pj= endpoint or a BIP-77
// directory, accepts BIP-21 URI parameters, or reads raw transactions — the
// comparison takes PSBTs only.
import { tHtml as hodlT, t as hodlTText, tAttr as hodlTAttr } from "./i18n.js";
import { psbtPayjoinCompare, psbtWasmReady } from "./psbt-wasm.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// Paste-box decode for the proposal PSBT: base64 or hex under the same rules
// and bounds as the inspector's hodlPsbtBytes (app.js) and the editor's
// psbtBytesFromText (psbt-editor.js) — 5 MB decoded, 7 MB of text. Whether
// the bytes are a PSBT (and not a raw transaction) is the WASM's call; its
// error names the file that failed.
export const psbtPayjoinBytesFromText = (raw) => {
  const value = String(raw ?? "").trim(), compact = value.replace(/\s/g, "");
  if (!value) throw new Error(hodlTText("Paste a Payjoin Proposal PSBT (base64 or hex)."));
  if (compact.length > 7e6) throw new Error(hodlTText("This PSBT is too large to check safely."));
  let bytes;
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && compact.length >= 10) {
    bytes = new Uint8Array(compact.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  } else {
    let binary;
    try {
      binary = atob(compact);
    } catch {
      throw new Error(hodlTText("That does not look like a PSBT in base64 or hex."));
    }
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  }
  if (bytes.length > 5e6) throw new Error(hodlTText("This PSBT is too large to check safely."));
  return bytes;
};

// The optional BIP-21 payment output's scriptPubKey, as hex. Empty means
// unknown: a lone replaced output is then reported as an unconfirmed
// substitution instead of a confirmed payment-output replacement.
export const psbtPayjoinPaymentScriptFromText = (raw) => {
  const compact = String(raw ?? "").trim().replace(/\s/g, "");
  if (!compact) return null;
  if (!/^(?:[0-9a-f]{2})+$/i.test(compact)) throw new Error(hodlTText("The payment script must be hex (an even number of 0-9/a-f digits)."));
  const bytes = new Uint8Array(compact.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  return bytes;
};

// Single-PSBT signals (the inspect document's `payjoin` field), rendered in
// the analysis-summary style of the editor's sanitize section. Signals are
// facts about the file's shape, introduced with their counterexamples so the
// section can never read as a payjoin verdict.
export const psbtPayjoinSignalsHtml = (payjoin) => {
  if (!payjoin) return "";
  const candidates = Array.isArray(payjoin.candidateReceiverInputs) ? payjoin.candidateReceiverInputs : [];
  const groups = Number.isSafeInteger(payjoin.originGroups) ? payjoin.originGroups : 0;
  const shape = payjoin.proposalShape
    ? hodlT("Mixed finalization: input(s) {inputs} are finalized while the rest are not — the shape of a payjoin proposal, whose receiver finalizes only its own inputs.", { inputs: candidates.join(", ") })
    : hodlT("Finalization is uniform across inputs — not the shape of a payjoin proposal.");
  const wallets = groups >= 2
    ? hodlT("Inputs declare {groups} wallet groups by BIP-32 master fingerprint — more than one wallet contributed inputs.", { groups })
    : groups === 1
      ? hodlT("Inputs with a BIP-32 origin share a single wallet group.")
      : hodlT("No BIP-32 origins declare which wallets the inputs came from.");
  const tone = payjoin.signal ? "warn" : "muted";
  const heading = payjoin.signal ? hodlT("Payjoin-like pattern(s) in this PSBT") : hodlT("No payjoin-like pattern in this PSBT");
  return `<section class="psbted-sanitize psbt-analysis-summary" aria-label="${hodlTAttr("Payjoin signals")}">
    <p class="label">${hodlT("Payjoin signals (BIP-78/77)")}</p>
    <p class="psbted-note-${tone}"><strong>${heading}</strong></p>
    <ul><li>${shape}</li><li>${wallets}</li></ul>
    <p class="muted">${hodlT("Signals only, never a verdict: patterns like this also occur in coinjoins and collaborative batches, and a fully re-signed payjoin looks like any other transaction. Nothing here contacts a pj= endpoint or directory.")}</p>
  </section>`;
};

// The two-file BIP-78 sender-checklist report (psbtPayjoinCompare's output).
// Every interpolated value passes escapeHtml or hodlT's encoding: report
// strings name scopes and verdicts but are never trusted as markup.
export const psbtPayjoinReportHtml = (report) => {
  if (!report || typeof report !== "object") return "";
  const receiverInputs = Array.isArray(report.receiverInputs) ? report.receiverInputs : [];
  const addedOutputs = Array.isArray(report.addedOutputs) ? report.addedOutputs : [];
  const valueChanges = Array.isArray(report.valueChanges) ? report.valueChanges : [];
  const problems = Array.isArray(report.problems) ? report.problems : [];
  // Interpolated only through hodlT placeholders, which encode for the sink.
  const sats = (value) => (value == null ? hodlTText("unknown") : `${value} sats`);

  const rows = [];
  rows.push(`<li><strong>${hodlT("Payjoin")}</strong> — ${report.payjoin
    ? hodlT("the proposal adds receiver input(s): {inputs}", { inputs: receiverInputs.join(", ") })
    : hodlT("the proposal adds no receiver inputs — valid, but not an actual payjoin.")}</li>`);
  rows.push(`<li><strong>${hodlT("Receiver contribution")}</strong> — ${report.receiverContribution == null
    ? hodlT("unknown (a receiver input carries no valid UTXO claim)")
    : hodlT("{sats} sats", { sats: report.receiverContribution })}</li>`);
  const substitution = report.substitution && typeof report.substitution === "object" ? report.substitution : null;
  rows.push(`<li><strong>${hodlT("Output substitution")}</strong> — ${!substitution
    ? hodlT("no original output was replaced.")
    : substitution.paymentOutputConfirmed
      ? hodlT("original output {index} was replaced — confirmed as the payment output.", { index: substitution.originalOutput })
      : hodlT("original output {index} was replaced; this is allowed only for the payment output — supply the payment script to confirm.", { index: substitution.originalOutput })}</li>`);
  rows.push(`<li><strong>${hodlT("Added outputs")}</strong> — ${addedOutputs.length
    ? hodlT("proposal output(s) with no counterpart in the original: {outputs}", { outputs: addedOutputs.join(", ") })
    : hodlT("none.")}</li>`);
  rows.push(`<li><strong>${hodlT("Value changes")}</strong> — ${valueChanges.length
    ? `<ul>${valueChanges.map((change) => `<li>${hodlT("original output {original} → proposal output {proposal}: {before} → {after}", {
        original: change.originalOutput,
        proposal: change.proposalOutput,
        before: sats(change.before),
        after: sats(change.after),
      })}</li>`).join("")}</ul>`
    : hodlT("no matched output changed value.")}</li>`);
  const fee = report.fee && typeof report.fee === "object" ? report.fee : {};
  rows.push(`<li><strong>${hodlT("Fee")}</strong> — ${hodlT("{before} → {after}", { before: sats(fee.original), after: sats(fee.proposal) })}</li>`);

  // Three-state like the sanitize banner; an unrecognized state must never
  // render as success.
  const checklist = report.checklist === "complete" && !problems.some((problem) => problem.severity === "error")
    ? ["ok", hodlT("Sender checklist complete for the two files")]
    : report.checklist === "problem" || problems.some((problem) => problem.severity === "error")
      ? ["bad", hodlT("Sender checklist problem found")]
      : ["warn", hodlT("Sender checklist incomplete — the fee is unknown for at least one PSBT")];
  const items = problems
    .map((problem) => `<li><span class="psbted-note-${problem.severity === "error" ? "bad" : "warn"}">${escapeHtml(problem.scope)}</span> — ${escapeHtml(problem.message)}</li>`)
    .join("");

  return `<section class="psbted-sanitize psbt-analysis-summary" aria-label="${hodlTAttr("Payjoin proposal checklist")}">
    <p class="label">${hodlT("Payjoin proposal — BIP-78 sender checklist")}</p>
    <p class="psbted-note-${checklist[0]}"><strong>${checklist[1]}</strong></p>
    <ul>${rows.join("")}</ul>
    ${items ? `<ul>${items}</ul>` : ""}
    ${report.problemsTruncated ? `<p class="muted">${hodlT("List truncated; more problems exist than are shown.")}</p>` : ""}
    <p class="muted">${hodlT("Facts from the two PSBTs only. pjos=0 and the fee-contribution parameters live in the BIP-21 URI and the payjoin request, not in the PSBTs, so what depends on them is reported here for the user to judge. Nothing here contacts a pj= endpoint or directory.")}</p>
  </section>`;
};

// Wires one "Check a payjoin proposal" card: the Original PSBT comes from the
// host tool (the inspector's paste box, the editor's current build) through
// `originalBytes`, the proposal and optional payment script from the card's
// own fields. Any failure — unreadable original, malformed proposal, WASM
// rejection — lands whole in the card's error element and leaves the report
// area empty, so a failed check never renders a partial report.
export const initPsbtPayjoinCompare = ({ ids, originalBytes }) => {
  const element = (id) => document.getElementById(id);
  const text = element(ids.text), script = element(ids.script), go = element(ids.go);
  const clear = element(ids.clear), out = element(ids.out), error = element(ids.error);
  if (!text || !go || !out || !error) return null;
  const setError = (message) => {
    error.textContent = message || "";
  };
  const clearReport = () => {
    out.innerHTML = "";
    setError("");
  };
  const clearAll = () => {
    text.value = "";
    if (script) script.value = "";
    clearReport();
  };
  go.addEventListener("click", () => {
    psbtWasmReady
      .then(() => {
        clearReport();
        let report;
        try {
          report = psbtPayjoinCompare({
            original: originalBytes(),
            proposal: psbtPayjoinBytesFromText(text.value),
            paymentScript: psbtPayjoinPaymentScriptFromText(script ? script.value : ""),
          });
        } catch (exception) {
          setError(exception instanceof Error ? exception.message : String(exception));
          return;
        }
        out.innerHTML = psbtPayjoinReportHtml(report);
      })
      .catch((exception) => setError(exception instanceof Error ? exception.message : String(exception)));
  });
  if (clear) clear.addEventListener("click", clearAll);
  return { clearAll, clearReport };
};
