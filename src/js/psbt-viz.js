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
// Amounts on input boxes are the PSBT's own claims (witness / non-witness
// UTXO pairs); like the rest of the editor they are not verified against the
// chain, and the inputs column says so.
import { addressFromScript } from "./addresses.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const hexToBytes = (hex) => {
  const out = new Uint8Array(String(hex).length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(String(hex).slice(i * 2, i * 2 + 2), 16);
  return out;
};

// One renderer for the whole app: rust-bitcoin's Address::from_script via
// the entropylab-wasm crate, exactly what the inspector shows — exotic
// witness programs (off-curve v1 keys, v1 ≠ 32 bytes, v2–v16) get their
// bech32m address here too instead of diverging to a hex fallback
// (issue #354). Unknown templates still return null and show the script hex.
const addressFor = (scriptHex, network) => {
  try {
    return addressFromScript(hexToBytes(scriptHex), network);
  } catch {
    return null;
  }
};

// Middle-ellipsis for the dense boxes: a full address or txid never fits.
const shortenMiddle = (text, head = 10, tail = 8) => {
  const value = String(text ?? "");
  return value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
};

// Digit grouping for the read-only amounts (a raw 9-digit sat count is
// unscannable). Narrow no-break spaces keep a grouped number on one line.
// Editable fields (the output sats inputs) stay raw for typing.
const groupSats = (value) => String(value).replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f");

// Well-known script templates, tagged like a block explorer would. Anything
// else returns null and the box falls back to the raw script hex.
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

// The amount an input claims to spend, resolved as a set so map order cannot
// change the answer (issue #324): when both a witness UTXO and a verified
// non-witness UTXO claim exist they must agree, otherwise the box shows a
// conflict warning instead of picking one. The verified non-witness claim's
// script wins the label when both are present and consistent. Pairs that
// fail their typed decode claim nothing.
const claimedPrevout = (pairs) => {
  const witness = pairs.find((pair) => pair.name === "PSBT_IN_WITNESS_UTXO" && pair.decoded);
  const nonWitness = pairs.find((pair) => pair.name === "PSBT_IN_NON_WITNESS_UTXO" && pair.decoded?.prevout);
  const witnessClaim = witness && { value: witness.decoded.value, scriptPubKey: witness.decoded.scriptPubKey };
  const nonWitnessClaim = nonWitness && { value: nonWitness.decoded.prevout.value, scriptPubKey: nonWitness.decoded.prevout.scriptPubKey };
  if (witnessClaim && nonWitnessClaim) {
    return witnessClaim.value === nonWitnessClaim.value ? nonWitnessClaim : { conflict: [witnessClaim.value, nonWitnessClaim.value] };
  }
  return witnessClaim ?? nonWitnessClaim ?? null;
};

const SIGNING_PAIR_NAMES = ["PSBT_IN_PARTIAL_SIG", "PSBT_IN_TAP_KEY_SIG", "PSBT_IN_TAP_SCRIPT_SIG"];
const FINAL_PAIR_NAMES = ["PSBT_IN_FINAL_SCRIPTSIG", "PSBT_IN_FINAL_SCRIPTWITNESS"];

// Signing progress of one input. A pair name only states the field's
// presence; malformed bytes keep the name even when the typed decode failed,
// so "signed"/"finalized" requires a successful decode and a decode failure
// reads as malformed, never as progress (issue #328).
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

// sats null with every input claimed marks an invalid fee: the document's
// error string says why (negative fee, u64 overflow, or past MAX_MONEY).
const feeHtml = (doc) => {
  if (doc.fee?.known) {
    return doc.fee.sats === null
      ? `<span class="psbted-note-bad">${escapeHtml(doc.fee?.error || "outputs exceed claimed inputs")}</span>`
      : `<span class="psbted-viz-feenum">${groupSats(doc.fee.sats)} sats</span> <span class="muted">(PSBT claim)</span>`;
  }
  return doc.fee?.error
    ? `<span class="psbted-note-bad">${escapeHtml(doc.fee.error)}</span>`
    : `<span class="muted" title="an input carries no amount claim">unknown</span>`;
};

const inputBox = (doc, index, network, selected) => {
  const input = doc.tx.inputs[index];
  const pairs = doc.inputs[index] ?? [];
  const claim = claimedPrevout(pairs);
  const conflict = claim?.conflict;
  const address = claim && !conflict ? addressFor(claim.scriptPubKey, network) : null;
  // Boxes stay dense: identifiers truncate mid-string (the full text is in
  // the tooltip and the button's aria-label).
  const label = address ? shortenMiddle(address) : claim && !conflict ? shortenMiddle(claim.scriptPubKey, 12, 10) : `${shortenMiddle(input.txid, 8, 6)}:${input.vout}`;
  const status = signingStatus(pairs);
  // The prevout's script template tags the box like a block explorer would.
  const kind = claim && !conflict ? scriptKind(claim.scriptPubKey) : null;
  const open = selected?.kind === "input" && selected.index === index;
  return `<div class="psbted-viz-box${open ? " is-open" : ""}">
    <button type="button" class="psbted-viz-open" data-viz="input:${index}" aria-expanded="${open}" aria-label="Input ${index}, ${escapeHtml(address ?? label)}: show and edit this input's PSBT fields">
      <span class="psbted-viz-idx">#${index}</span>
      <span class="psbted-viz-id psbted-viz-in"${address ? ` title="${escapeHtml(address)}"` : ""}>${escapeHtml(label)}</span>
    </button>
    <p class="psbted-viz-amount">${conflict ? `<span class="psbted-note-bad">conflicting claims: ${groupSats(conflict[0])} vs ${groupSats(conflict[1])} sats</span>` : claim ? `${groupSats(claim.value)} sats` : `<span class="muted">no amount claim</span>`}</p>
    <p class="psbted-viz-sub" title="spends ${escapeHtml(input.txid)}:${escapeHtml(String(input.vout))}">${kind ? `<span class="psbted-viz-kind">${escapeHtml(kind)}</span> · ` : ""}<span class="${status.tone}">${escapeHtml(status.text)}</span></p>
  </div>`;
};

const outputBox = (doc, index, network, selected) => {
  const output = doc.tx.outputs[index];
  const address = addressFor(output.scriptPubKey, network);
  const kind = scriptKind(output.scriptPubKey, output.asm);
  const label = address ? shortenMiddle(address) : kind === "OP_RETURN" ? "OP_RETURN" : shortenMiddle(output.scriptPubKey, 12, 10) || "(empty script)";
  // The sub-line adds what the label does not already say: the script
  // template for addressed outputs, the asm for data-carrier/raw scripts.
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

// The diagram. `doc` is the editor's inspection document (fresh from
// psbtInspectDoc or carrying pending field edits); `selected` is the open
// box ({ kind: "input"|"output", index } or { kind: "tx" }) or null. The SVG
// layer ships empty: psbt-editor.js measures the laid-out boxes and draws
// the connector paths into it (no layout in this pure module).
export const psbtVizHtml = (doc, network, selected = null) => {
  const inputs = doc.tx.inputs.map((_, index) => inputBox(doc, index, network, selected)).join("");
  const outputs = doc.tx.outputs.map((_, index) => outputBox(doc, index, network, selected)).join("");
  // Column totals ride in the hint lines; the inputs side can only total
  // when every input carries a claim (doc.totalIn is null otherwise).
  const inputsHint = doc.totalIn === null
    ? "amounts as claimed by the PSBT, not verified"
    : `${groupSats(doc.totalIn)} sats claimed, not verified`;
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
