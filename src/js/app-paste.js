// EntropyLab's paste control for its own clipboard: a button below each secret
// field that writes the value copied to EntropyLab's clipboard back into the field.
// It never reads the system clipboard (no navigator.clipboard.readText, no
// paste event): the value comes from app-clipboard.js alone.
import { appClipboardHas } from "./app-clipboard.js";

export const APP_PASTE_TARGETS = [
  "seed", "key", "hex", "pass", "bip85-key", "bip47-key", "bip47-pass",
  "sp-key", "sp-pass", "psbt-key", "psbt-pass", "nonce-key", "nonce-pass",
  "ln-seed", "ln-pass", "core-add-text", "journal-input", "journal-phrase",
];

const byId = (root, id) => (typeof root?.getElementById === "function" ? root : document).getElementById(id);

// Each control is named for its field (several can share a screen) and stays
// in place, disabled while nothing is copied, so the layout never jumps.
export const decorateAppPaste = (root = document, { pasteIcon = () => "", labelFor = () => "Paste" } = {}) => {
  const doc = typeof root?.getElementById === "function" ? root : document;
  for (const id of APP_PASTE_TARGETS) {
    const field = byId(root, id);
    if (!field || doc.querySelector(`[data-app-paste="${id}"]`)) continue;
    const row = field.ownerDocument.createElement("div");
    row.setAttribute("class", "row");
    row.setAttribute("data-app-paste-row", "");
    const button = field.ownerDocument.createElement("button");
    button.setAttribute("type", "button");
    button.setAttribute("class", "copy-button boxed-copy-button");
    button.setAttribute("data-app-paste", id);
    button.setAttribute("aria-controls", id);
    const label = labelFor(id);
    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
    button.innerHTML = pasteIcon();
    button.disabled = !appClipboardHas();
    row.appendChild(button);
    const anchor = field.closest("label") || field.closest(".dice-input-shell") || field;
    anchor.after(row);
  }
};

export const syncAppPaste = (doc = document) => {
  for (const button of doc.querySelectorAll("button[data-app-paste]")) button.disabled = !appClipboardHas();
};

export const initAppPaste = ({ fill, doc = document } = {}) => {
  const onSync = () => syncAppPaste(doc);
  const onClick = (event) => {
    const button = event.target?.closest?.("button[data-app-paste]");
    if (!button || button.disabled) return;
    const field = doc.getElementById(button.dataset.appPaste);
    if (!field || field.disabled || field.readOnly || field.hasAttribute?.("readonly") || !appClipboardHas()) return;
    if (typeof fill === "function") fill(field);
  };
  doc.addEventListener("hodl:app-clipboard", onSync);
  doc.addEventListener("click", onClick);
  return () => {
    doc.removeEventListener("hodl:app-clipboard", onSync);
    doc.removeEventListener("click", onClick);
  };
};
