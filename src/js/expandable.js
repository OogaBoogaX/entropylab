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

export const initExpandable = () => {
  if (document.getElementById("exp-overlay")) return;
  const overlay = document.createElement("div");
  overlay.className = "exp-overlay no-print";
  overlay.id = "exp-overlay";
  overlay.hidden = true;
  /* i18n-static-shell */
  overlay.innerHTML = `
    <div class="exp-card" role="dialog" aria-modal="true" aria-labelledby="exp-title">
      <p class="exp-title" id="exp-title"></p>
      <p class="exp-meta muted" id="exp-meta"></p>
      <textarea id="exp-text" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
      <div class="row exp-actions">
        <button class="btn secondary" id="exp-copy" type="button" data-i18n="expandable.copy">Copy</button>
        <button class="btn primary" id="exp-apply" type="button" data-i18n="expandable.apply">Apply</button>
        <button class="btn secondary" id="exp-close" type="button" data-i18n="expandable.close">Close</button>
      </div>
    </div>`;
  document.body.append(overlay);
  const text = overlay.querySelector("#exp-text"), apply = overlay.querySelector("#exp-apply");
  let cell = null;

  const close = () => {
    overlay.hidden = true;
    cell?.focus({ preventScroll: true });
    cell = null;
  };
  const open = (target) => {
    cell = target;
    const value = target.dataset.exp ?? "";
    overlay.querySelector("#exp-title").textContent = target.dataset.expLabel || "Full value";
    overlay.querySelector("#exp-meta").textContent = expandSizeLabel(value);
    text.value = value;
    const editable = "expEdit" in target.dataset;
    text.readOnly = !editable;
    apply.hidden = !editable;
    overlay.hidden = false;
    text.focus();
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest?.(".exp-cell");
    if (target) open(target);
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });
  overlay.querySelector("#exp-close").addEventListener("click", close);
  overlay.querySelector("#exp-copy").addEventListener("click", () => {
    navigator.clipboard?.writeText(text.value).catch(() => {});
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
