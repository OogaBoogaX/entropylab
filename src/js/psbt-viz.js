// Transaction-flow visualizer for the PSBT editor: a mempool.space-style
// diagram of the unsigned transaction — one box per input on the left, one
// box per output on the right, the transaction summary in the middle, and a
// bezier connector drawn from every box into the transaction (the
// mempool.space flow look).
//
// The module is pure (document in, HTML string out) so it is unit-tested
// under Node; psbt-editor.js renders it, owns the selection state, binds the
// click targets, and draws the connector paths into the (here empty) SVG
// layer once the boxes have layout. Every box is a button (data-viz=
// "input:N" / "output:N" / "tx"); activating one opens that part's fields in
// the panel under the diagram — the maps for inputs/outputs, the
// version/locktime section for the transaction box. Output amounts are
// editable right in their boxes (the same data-txout-val fields the
// transaction table binds), so the diagram is also the editing surface —
// WYSIWYG.
//
// Input amount claims are classified locally from the already-decoded PSBT
// fields. A valid non-witness UTXO whose txid matches the input outpoint is
// independently established by the supplied transaction bytes. A witness
// UTXO alone remains an unverified claim. Verification requires both witness
// and validated non-witness claims to agree on amount and scriptPubKey.
// Disagreement is a mismatch. No network lookup is performed.
import { addressFromScript } from "./addresses.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\"/g, "&quot;").replace(/'/g, "&#39;");

const hexToBytes = (hex) => {
  const out = new Uint8Array(String(hex).length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(String(hex).slice(i * 2, i * 2 + 2), 16);
  return out;
};

// Decode a script into a user-facing address when the script type is supported.
const addressFor = (scriptHex, network) => {
  try {
    return addressFromScript(hexToBytes(scriptHex), network);
  } catch {
    return null;
  }
};

// Keep long identifiers readable in the compact input/output boxes.
const shortenMiddle = (text, head = 10, tail = 8) => {
  const value = String(text ?? "");
  return value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
};

// Group satoshi amounts with narrow no-break spaces for readability.
const groupSats = (value) => String(value).replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f");

// Identify the common script templates used to label outputs in the diagram.
const scriptKind = (scriptHex, asm) => {
  const hex = String(scriptHex ?? "");
  if (/^76a914[0-9a-f]{40}88ac$/i.test(hex)) return "P2PKH";
  if (/^a914[0-9a-f]{40}87$/i.test(hex)) return "P2SH";
  if (/^0014[0-9a-f]{40}$/i.test(hex)) return "P2WPKH";
  if (/^0020[0-9a-f]{64}$/i.test(hex)) return "P2WSH";
  if (/^5120[0-9a-f]{64}$/i.test(hex)) return "P2TR";
  if (/^6a/i.test(hex) || String(asm ?? "").startsWith("OP_RETURN")) return "OP_RETURN";
  return null;
};

// Prefer the validated non-witness claim when both claims agree. If either
// amount or scriptPubKey disagrees, preserve the conflict so the UI can show
// a mismatch rather than silently selecting one claim.
const claimedPrevout = (pairs) => {
  const witness = pairs.find((pair) => pair.name === "PSBT_IN_WITNESS_UTXO" && pair.decoded);
  const nonWitness = pairs.find((pair) => pair.name === "PSBT_IN_NON_WITNESS_UTXO" && pair.decoded?.prevout);
  const witnessClaim = witness && { value: witness.decoded.value, scriptPubKey: witness.decoded.scriptPubKey };
  const nonWitnessClaim = nonWitness && { value: nonWitness.decoded.prevout.value, scriptPubKey: nonWitness.decoded.prevout.scriptPubKey };
  if (witnessClaim && nonWitnessClaim) {
    const amountMismatch = witnessClaim.value !== nonWitnessClaim.value;
    const scriptMismatch = witnessClaim.scriptPubKey !== nonWitnessClaim.scriptPubKey;
    if (amountMismatch || scriptMismatch) {
      return {
        conflict: {
          amounts: [witnessClaim.value, nonWitnessClaim.value],
          script: scriptMismatch,
          value: nonWitnessClaim.value,
          scriptPubKey: nonWitnessClaim.scriptPubKey,
        },
      };
    }
    return nonWitnessClaim;
  }
  return witnessClaim ?? nonWitnessClaim ?? null;
};

// Verification status is derived from the existing psbt-wasm validation:
// a decoded non-witness prevout is only exposed after the supplied transaction
// matches the input outpoint and the referenced output exists. This is a UI
// projection only; no second UTXO validator is performed here. Per #191's
// verification contract, a definitive Verified state additionally requires a
// decoded witness UTXO whose amount and scriptPubKey agree with that validated
// non-witness prevout.
const utxoVerification = (pairs) => {
  const claim = claimedPrevout(pairs);
  if (claim?.conflict) return "mismatch";
  const hasWitness = pairs.some((pair) => pair.name === "PSBT_IN_WITNESS_UTXO" && pair.decoded);
  const hasNonWitness = pairs.some((pair) => pair.name === "PSBT_IN_NON_WITNESS_UTXO" && pair.decoded?.prevout);
  return hasWitness && hasNonWitness ? "verified" : "unverified";
};

// Calculate the fee only from inputs whose UTXO amounts and scripts are
// independently established by the existing inspector validation. This keeps
// the fee claim separate from the ordinary PSBT-provided fee calculation.
const independentlyVerifiedFee = (doc) => {
  if (!doc.tx.inputs.length || doc.inputs.length !== doc.tx.inputs.length) return null;

  let totalIn = 0n;
  for (let index = 0; index < doc.tx.inputs.length; index++) {
    const pairs = doc.inputs[index] ?? [];
    if (utxoVerification(pairs) !== "verified") return null;
    const claim = claimedPrevout(pairs);
    if (!claim || claim.conflict) return null;
    try {
      totalIn += BigInt(claim.value);
    } catch {
      return null;
    }
  }

  let totalOut = 0n;
  for (const output of doc.tx.outputs) {
    try {
      totalOut += BigInt(output.value);
    } catch {
      return null;
    }
  }

  return totalIn - totalOut;
};

const SIGNING_PAIR_NAMES = ["PSBT_IN_PARTIAL_SIG", "PSBT_IN_TAP_KEY_SIG", "PSBT_IN_TAP_SCRIPT_SIG"];
const FINAL_PAIR_NAMES = ["PSBT_IN_FINAL_SCRIPTSIG", "PSBT_IN_FINAL_SCRIPTWITNESS"];

// Signing readiness is separate from UTXO verification: malformed signing
// fields are surfaced, partial signatures are counted, and final fields win.
const signingStatus = (pairs) => {
  const decodedOk = (pair) => pair.decoded && !pair.decodeError;
  const finals = pairs.filter((pair) => FINAL_PAIR_NAMES.includes(pair.name));
  if (finals.some(decodedOk)) return { text: "finalized", tone: "psbted-note-ok" };
  const sigs = pairs.filter((pair) => SIGNING_PAIR_NAMES.includes(pair.name) && decodedOk(pair)).length;
  if (sigs) return { text: `${sigs} signature${sigs === 1 ? "" : "s"}`, tone: "" };
  const malformed = finals.length + pairs.filter((pair) => SIGNING_PAIR_NAMES.includes(pair.name)).length;
  if (malformed) return { text: "malformed signing field", tone: "psbted-note-bad" };
  return { text: "unsigned", tone: "muted" };
};

// Render the fee summary while preserving the inspector's unknown/conflict states.
const feeHtml = (doc) => {
  const verifiedFee = independentlyVerifiedFee(doc);
  if (verifiedFee !== null) {
    return verifiedFee < 0n
      ? `<span class="psbted-note-bad">outputs exceed independently verified inputs</span>`
      : `<span class="psbted-viz-feenum">${groupSats(verifiedFee)} sats</span> <span class="psbted-note-ok">(independently verified)</span>`;
  }

  if (doc.fee?.known) {
    return doc.fee.sats === null
      ? `<span class="psbted-note-bad">${escapeHtml(doc.fee?.error || "outputs exceed claimed inputs")}</span>`
      : `<span class="psbted-viz-feenum">${groupSats(doc.fee.sats)} sats</span> <span class="muted">(PSBT claim)</span>`;
  }
  return doc.fee?.error
    ? `<span class="psbted-note-bad">${escapeHtml(doc.fee.error)}</span>`
    : `<span class="muted" title="an input carries no amount claim">unknown</span>`;
};

// Render one input box, including the amount claim and its verification state.
const inputBox = (doc, index, network, selected) => {
  const input = doc.tx.inputs[index];
  const pairs = doc.inputs[index] ?? [];
  const claim = claimedPrevout(pairs);
  const conflict = claim?.conflict;
  const verification = utxoVerification(pairs);
  const address = claim && !conflict ? addressFor(claim.scriptPubKey, network) : null;
  const label = address ? shortenMiddle(address) : claim && !conflict ? shortenMiddle(claim.scriptPubKey, 12, 10) : `${shortenMiddle(input.txid, 8, 6)}:${input.vout}`;
  const status = signingStatus(pairs);
  const kind = claim && !conflict ? scriptKind(claim.scriptPubKey) : null;
  const open = selected?.kind === "input" && selected.index === index;
  const verificationText = verification === "verified" ? "verified" : verification === "mismatch" ? "mismatch" : "unverified";
  const verificationTone = verification === "verified" ? "psbted-note-ok" : verification === "mismatch" ? "psbted-note-bad" : "muted";
  const amountHtml = conflict
    ? conflict.script
      ? `<span class="psbted-note-bad">${verificationText}: conflicting scriptPubKeys${conflict.amounts[0] !== conflict.amounts[1] ? ` and amounts: ${groupSats(conflict.amounts[0])} vs ${groupSats(conflict.amounts[1])} sats` : ""}</span>`
      : `<span class="psbted-note-bad">${verificationText}: conflicting claims: ${groupSats(conflict.amounts[0])} vs ${groupSats(conflict.amounts[1])} sats</span>`
    : claim
      ? `${groupSats(claim.value)} sats <span class="${verificationTone}" title="${verification === "verified" ? "amount and scriptPubKey independently established by agreement between the validated non-witness UTXO and the witness UTXO" : "not verified: both witness and matching non-witness UTXO claims are required"}">(${verificationText})</span>`
      : `<span class="muted">no amount claim</span> <span class="${verificationTone}" title="not verified: both witness and matching non-witness UTXO claims are required">(${verificationText})</span>`;
  return `<div class="psbted-viz-box${open ? " is-open" : ""}">
    <button type="button" class="psbted-viz-open" data-viz="input:${index}" aria-expanded="${open}" aria-label="Input ${index}, ${escapeHtml(address ?? label)}: show and edit this input's PSBT fields">
      <span class="psbted-viz-idx">#${index}</span>
      <span class="psbted-viz-id psbted-viz-in"${address ? ` title="${escapeHtml(address)}"` : ""}>${escapeHtml(label)}</span>
    </button>
    <p class="psbted-viz-amount">${amountHtml}</p>
    <p class="psbted-viz-sub" title="spends ${escapeHtml(input.txid)}:${escapeHtml(String(input.vout))}">${kind ? `<span class="psbted-viz-kind">${escapeHtml(kind)}</span> · ` : ""}<span class="${status.tone}">${escapeHtml(status.text)}</span></p>
  </div>`;
};

// Render one output box with its editable satoshi amount and script label.
const outputBox = (doc, index, network, selected) => {
  const output = doc.tx.outputs[index];
  const address = addressFor(output.scriptPubKey, network);
  const kind = scriptKind(output.scriptPubKey, output.asm);
  const label = address ? shortenMiddle(address) : kind === "OP_RETURN" ? "OP_RETURN" : shortenMiddle(output.scriptPubKey, 12, 10) || "(empty script)";
  const sub = address ? (kind ?? "script") : shortenMiddle(output.asm || output.scriptPubKey, 24, 12) || "script";
  const open = selected?.kind === "output" && selected.index === index;
  return `<div class="psbted-viz-box${open ? " is-open" : ""}">
    <button type="button" class="psbted-viz-open" data-viz="output:${index}" aria-expanded="${open}" aria-label="Output ${index}, ${escapeHtml(address ?? label)}: show and edit this output's PSBT fields">
      <span class="psbted-viz-idx">#${index}</span>
      <span class="psbted-viz-id ${address || !kind ? "psbted-viz-out" : "psbted-viz-tag"}"${address ? ` title="${escapeHtml(address)}"` : ""}>${escapeHtml(label)}</span>
    </button>
    <p class="psbted-viz-amount"><input class="psbted-viz-sats" data-txout-val="${index}" value="${escapeHtml(String(output.value))}" inputmode="numeric" spellcheck="false" autocomplete="off" aria-label="Output ${index} value in sats"> sats</p>
    <p class="psbted-viz-sub"><span class="muted">${escapeHtml(sub)}</span></p>
  </div>`;
};

// Pure renderer: build the three-column transaction flow and keep input/output
// boxes as the editing surface used by psbt-editor.js.
export const psbtVizHtml = (doc, network, selected = null) => {
  const inputs = doc.tx.inputs.map((_, index) => inputBox(doc, index, network, selected)).join("");
  const outputs = doc.tx.outputs.map((_, index) => outputBox(doc, index, network, selected)).join("");
  // The aggregate total is still a claim unless every input amount is known;
  // the per-input labels provide the more precise verification state.
  const inputsHint = doc.totalIn === null
    ? "amounts as claimed by the PSBT; not verified unless matching witness and non-witness UTXO claims agree"
    : `${groupSats(doc.totalIn)} sats claimed; not verified unless matching witness and non-witness UTXO claims agree`;
  const txOpen = selected?.kind === "tx";
  return `<div class="psbted-viz">
  <svg class="psbted-viz-svg" aria-hidden="true" focusable="false"></svg>
  <div class="psbted-viz-cols">
    <div class="psbted-viz-col">
      <h3 class="psbted-viz-heading">Inputs (${doc.tx.inputs.length})</h3>
      <p class="psbted-viz-hint muted">${inputsHint}</p>
      ${inputs || `<div class="psbted-viz-box muted">No inputs.</div>`}
    </div>
    <div class="psbted-viz-mid">
      <div class="psbted-viz-arrow" aria-hidden="true"></div>
      <button type="button" class="psbted-viz-tx${txOpen ? " is-open" : ""}" data-viz="tx" aria-expanded="${txOpen}" aria-label="Unsigned transaction: show and edit the version and locktime fields">
        <span class="psbted-viz-txline"><strong>PSBT v${escapeHtml(String(doc.psbtVersion))}</strong> · unsigned tx</span>
        <span class="psbted-viz-txline muted">version ${escapeHtml(String(doc.tx.version))} · locktime ${escapeHtml(String(doc.tx.locktime))}</span>
        <span class="psbted-viz-txline">fee ${feeHtml(doc)}</span>
      </button>
      <div class="psbted-viz-arrow" aria-hidden="true"></div>
    </div>
    <div class="psbted-viz-col">
      <h3 class="psbted-viz-heading">Outputs (${doc.tx.outputs.length})</h3>
      <p class="psbted-viz-hint muted">${doc.totalOut === null ? "outputs total unknown — amounts overflow u64" : `${groupSats(doc.totalOut)} sats in total`} · editable in the boxes</p>
      ${outputs || `<div class="psbted-viz-box muted">No outputs.</div>`}
    </div>
  </div>
</div>`;
};