import { createModal } from "./modal.js";
import { copyText, resetCopiedIcon, showCopiedIcon } from "./clipboard.js";
// Expandable cells: one standard truncation for long text in dense UI tables,
// with a click-to-expand overlay window for viewing (and, when the cell is
// editable, editing) the full value.
//
// A PSBT pair value can hold an entire previous transaction, and a decoded
// tap-leaf script can run to hundreds of opcodes; rendering those verbatim
// stretches the editor tables into thousand-pixel columns. The rule here is
// the same everywhere: at most EXPAND_LIMIT characters are shown inline
// (head … tail, with the total length stated); activating the cell opens one
// shared overlay with the full text in a real editor window.
//
// The module keeps no state besides the one overlay: cells carry their full
// text in a data-exp attribute, so re-rendering a table never leaves stale
// registry entries behind. Editable cells announce their saved text through
// an "expandable:apply" CustomEvent bubbling from the cell; listeners update
// their own model (the overlay never reaches into anyone's state).
//
// truncateText and expandableHtml are pure and unit-tested under Node;
// initExpandable is the only DOM entry point.

export const EXPAND_LIMIT = 64;
const EXPAND_HEAD = 32;
const EXPAND_TAIL = 16;

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// The one truncation rule. Returns the text untouched at or under the limit.
export const truncateText = (text) => {
  const value = String(text ?? "");
  if (value.length <= EXPAND_LIMIT) return { truncated: false, preview: value };
  return { truncated: true, preview: `${value.slice(0, EXPAND_HEAD)}…${value.slice(-EXPAND_TAIL)}` };
};

// How long the full text is, phrased for the cell and the overlay. Even-length
// hex gets a byte count as well, since pair keys/values are hex by convention.
export const expandSizeLabel = (text) => {
  const length = String(text ?? "").length;
  return length % 2 === 0 && /^(?:[0-9a-f])+$/i.test(String(text)) && length > 0
    ? `${length} hex chars (${length / 2} bytes)`
    : `${length} characters`;
};

// Cell markup: the full text when it fits, otherwise a button with the
// truncated preview that opens the overlay. `label` names the field in the
// overlay title; `editAttrs` (extra attributes, e.g. data-kind/data-map/
// data-pair) marks the cell editable — Apply then writes back through the
// "expandable:apply" event on the button.
export const expandableHtml = (text, { label = "Full value", editAttrs = "" } = {}) => {
  const value = String(text ?? "");
  const { truncated, preview } = truncateText(value);
  if (!truncated) return escapeHtml(value);
  const edit = editAttrs ? ` data-exp-edit="" ${editAttrs}` : "";
  return `<button type="button" class="exp-cell" data-exp="${escapeHtml(value)}" data-exp-label="${escapeHtml(label)}"${edit} ` +
    `aria-label="${escapeHtml(label)}: truncated; activate to open the full ${value.length}-character value in an editor window">` +
    `${escapeHtml(preview)} <span class="exp-len">${escapeHtml(expandSizeLabel(value))}</span></button>`;
};

export const initExpandable = ({ copy: copyIcon = () => "", copied: copiedIcon = () => "" } = {}) => {
  if (document.getElementById("exp-overlay")) return;
  const modal = createModal({
    id: "exp-overlay",
    className: "exp-overlay",
    focusables: () => [...overlay.querySelectorAll("textarea, button")],
    onDismiss: () => close(),
    card: `
    <div class="modal-card exp-card" role="dialog" aria-modal="true" aria-labelledby="exp-title">
      <p class="modal-title exp-title" id="exp-title"></p>
      <p class="exp-meta muted" id="exp-meta"></p>
      <textarea id="exp-text" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
      <div class="row modal-actions">
        <button type="button" class="copy-button boxed-copy-button" id="exp-copy" aria-label="Copy" title="Copy"></button>
        <span class="modal-actions-end">
          <button class="btn primary" id="exp-apply" type="button">Apply</button>
          <button class="btn red" id="exp-close" type="button">Close</button>
        </span>
      </div>
    </div>`,
  });
  const overlay = modal.overlay;
  const text = overlay.querySelector("#exp-text"), apply = overlay.querySelector("#exp-apply"), copyButton = overlay.querySelector("#exp-copy");
  copyButton.innerHTML = copyIcon();
  let cell = null;

  // A cell value can hold an entire previous transaction, or a pasted PSBT
  // carrying an xprv in a proprietary field; once the dialog is out of scope
  // (closed, or the page going away) it keeps none of it.
  const release = () => {
    text.value = "";
    overlay.querySelector("#exp-title").textContent = "";
    overlay.querySelector("#exp-meta").textContent = "";
  };
  const close = () => {
    modal.hide();
    release();
    cell = null;
  };
  // The overlay is a body-level sibling of every wiped view, so station and
  // editor wipes cannot reach it; it tears itself down with the page.
  const teardown = () => {
    modal.hide({ restoreFocus: false });
    release();
    cell = null;
  };
  addEventListener("pagehide", teardown);
  addEventListener("pageshow", (event) => {
    if (event.persisted) teardown();
  });
  const open = (target) => {
    cell = target;
    const value = target.dataset.exp ?? "";
    overlay.querySelector("#exp-title").textContent = target.dataset.expLabel || "Full value";
    overlay.querySelector("#exp-meta").textContent = expandSizeLabel(value);
    text.value = value;
    const editable = "expEdit" in target.dataset;
    text.readOnly = !editable;
    apply.hidden = !editable;
    // A check left over from the last opening goes back to the copy icon
    // and its label.
    resetCopiedIcon(copyButton, { copyIcon: copyIcon() });
    modal.show(text, target);
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest?.(".exp-cell");
    if (target) open(target);
  });
  overlay.querySelector("#exp-close").addEventListener("click", close);
  copyButton.addEventListener("click", () => {
    copyText(text.value, { host: overlay }).then((copied) => {
      if (copied && modal.isOpen()) showCopiedIcon(copyButton, { copyIcon: copyIcon(), copiedIcon: copiedIcon() });
    });
  });
  apply.addEventListener("click", () => {
    if (!cell) return;
    const target = cell, value = text.value;
    target.dataset.exp = value;
    // Refresh the preview and label in place; if the edit brought the text
    // under the limit the cell still shows it, and the next table re-render
    // restores the plain-input form.
    const { preview } = truncateText(value);
    const label = target.dataset.expLabel || "Full value";
    target.setAttribute("aria-label", `${label}: truncated; activate to open the full ${value.length}-character value in an editor window`);
    target.replaceChildren(document.createTextNode(`${preview} `), Object.assign(document.createElement("span"), { className: "exp-len", textContent: expandSizeLabel(value) }));
    target.dispatchEvent(new CustomEvent("expandable:apply", { bubbles: true, detail: { text: value } }));
    close();
  });
};
