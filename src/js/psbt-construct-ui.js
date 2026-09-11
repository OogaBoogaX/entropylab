// Injects the unsigned-PSBT constructor into the PSBT Editor card.
// Kept in its own module so the large editor/shell files do not have to
// change for the first landing. Never signs.
import { constructUnsignedPsbtDoc } from "./psbt-construct.js";
import { psbtBuildBytes, psbtWasmReady } from "./psbt-wasm.js";

const base64Encode = (bytes) => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};

const network = () =>
  document.getElementById("network-picker")?.dataset.network === "testnet" ? "testnet" : "mainnet";

const rowHtml = (kind) =>
  kind === "input"
    ? `<div class="psbted-construct-row tool-section" data-construct-kind="input">
        <label class="field">txid <input data-c="txid" spellcheck="false" autocomplete="off" autocapitalize="off"></label>
        <label class="field">vout <input data-c="vout" inputmode="numeric" autocomplete="off"></label>
        <label class="field">amount (sats or BTC) <input data-c="value" inputmode="decimal" autocomplete="off"></label>
        <label class="field">spent script or address <input data-c="script" spellcheck="false" autocomplete="off" autocapitalize="off" placeholder="address · OP_… ASM · 0x raw hex"></label>
        <label class="field">sequence (optional) <input data-c="sequence" placeholder="4294967293" autocomplete="off"></label>
      </div>`
    : `<div class="psbted-construct-row tool-section" data-construct-kind="output">
        <label class="field">amount (sats or BTC) <input data-c="value" inputmode="decimal" autocomplete="off"></label>
        <label class="field">address or script <input data-c="script" spellcheck="false" autocomplete="off" autocapitalize="off" placeholder="address · OP_… ASM · 0x raw hex · text"></label>
      </div>`;

const readRows = (root, kind) =>
  [...root.querySelectorAll(`[data-construct-kind="${kind}"]`)].map((row) => {
    const get = (name) => row.querySelector(`[data-c="${name}"]`)?.value ?? "";
    return kind === "input"
      ? { txid: get("txid"), vout: get("vout"), value: get("value"), script: get("script"), sequence: get("sequence") }
      : { value: get("value"), script: get("script") };
  });

export const initPsbtConstructUi = () => {
  if (typeof document === "undefined") return;
  const card = document.getElementById("psbted-card");
  if (!card || document.getElementById("psbted-construct")) return;

  if (!document.getElementById("psbted-construct-style")) {
    const style = document.createElement("style");
    style.id = "psbted-construct-style";
    style.textContent = ".psbted-construct-row{display:grid;gap:8px;margin:0 0 12px}.psbted-construct-row input{min-width:0}.psbted-construct-meta{gap:16px;margin-bottom:16px}.psbted-construct-meta .field{max-width:11em}";
    document.head.append(style);
  }

  const section = document.createElement("section");
  section.className = "tool-section";
  section.id = "psbted-construct";
  section.innerHTML = `<h3 id="psbted-construct-heading">Construct unsigned PSBT</h3>
    <p class="muted">Build a BIP-174 v0 PSBT from prevouts and destinations you already know. Amounts and scripts are claims you type — nothing is fetched from a chain. The result is unsigned. Sign it on a hardware wallet or Bitcoin Core.</p>
    <div class="psbted-construct-meta row">
      <label class="field">Version <input id="psbted-construct-version" value="2" inputmode="numeric" autocomplete="off"></label>
      <label class="field">Locktime <input id="psbted-construct-locktime" value="0" inputmode="numeric" autocomplete="off"></label>
    </div>
    <h4>Inputs</h4>
    <p class="muted field-note">Each input needs txid, vout, spent amount, and the spent script or address. A witness UTXO claim is attached so a signer can fee-check without a previous transaction.</p>
    <div id="psbted-construct-inputs">${rowHtml("input")}</div>
    <div class="row tool-actions"><button class="btn secondary" id="psbted-construct-add-in" type="button">Add input</button></div>
    <h4>Outputs</h4>
    <div id="psbted-construct-outputs">${rowHtml("output")}</div>
    <div class="row tool-actions"><button class="btn secondary" id="psbted-construct-add-out" type="button">Add output</button></div>
    <div class="row tool-actions"><button class="btn primary" id="psbted-construct-go" type="button">Build unsigned PSBT</button></div>
    <p class="muted" id="psbted-construct-fee" aria-live="polite"></p>`;

  const text = document.getElementById("psbted-text");
  if (text?.parentElement === card) card.insertBefore(section, text.parentElement);
  else card.prepend(section);

  const inputs = document.getElementById("psbted-construct-inputs");
  const outputs = document.getElementById("psbted-construct-outputs");
  document.getElementById("psbted-construct-add-in")?.addEventListener("click", () => {
    inputs.insertAdjacentHTML("beforeend", rowHtml("input"));
  });
  document.getElementById("psbted-construct-add-out")?.addEventListener("click", () => {
    outputs.insertAdjacentHTML("beforeend", rowHtml("output"));
  });
  document.getElementById("psbted-construct-go")?.addEventListener("click", () => {
    const error = document.getElementById("psbted-error");
    const fee = document.getElementById("psbted-construct-fee");
    if (error) error.textContent = "";
    if (fee) fee.textContent = "";
    psbtWasmReady
      .then(() => {
        const built = constructUnsignedPsbtDoc({
          version: document.getElementById("psbted-construct-version")?.value,
          locktime: document.getElementById("psbted-construct-locktime")?.value,
          inputs: readRows(inputs, "input"),
          outputs: readRows(outputs, "output"),
          network: network(),
        });
        const bytes = psbtBuildBytes(built);
        const box = document.getElementById("psbted-text");
        if (box) box.value = base64Encode(bytes);
        if (fee) fee.textContent = `Claimed fee ${built.claimedFeeSats.toString()} sats from typed amounts. Sign elsewhere.`;
        document.getElementById("psbted-load")?.click();
      })
      .catch((exception) => {
        if (error) error.textContent = exception.message || String(exception);
      });
  });
};

if (typeof document !== "undefined") {
  const boot = () => initPsbtConstructUi();
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
}
