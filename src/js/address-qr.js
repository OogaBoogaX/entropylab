// Per-address QR codes. Every row of an address table gets a compact QR
// button so any derived address — not just the first one — can be verified
// by scanning it with a signing device, instead of retyping 42 characters
// on an air-gapped machine.
//
// The pattern mirrors expandable.js: the button markup is a pure function
// unit-tested under Node; initAddressQr is the only DOM entry point and
// keeps no state besides the one shared overlay. Buttons carry the address
// in a data attribute, so virtualized table re-renders never leave stale
// registry entries behind.

import { t, tAttr, tHtml } from "./i18n.js";
import { createModal } from "./modal.js";
import { copyText } from "./clipboard.js";

// An address or an xpub reads in full; a PSBT export does not, so anything
// past this length shows head and tail around an ellipsis. The code and the
// copy control still carry every byte.
const DISPLAY_LIMIT = 256;
const shortenMiddle = (value, head = 32, tail = 20) =>
  value.length > head + tail + 1 ? `${value.slice(0, head)}\u2026${value.slice(-tail)}` : value;

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// Row markup: a small button rendered next to the address text. `label`
// names the address ("Address #3") for the overlay title and the aria-label.
// Addresses are public data, so the button is also shown in tables that
// include a WIF column — but it only ever encodes the address.
export const addressQrButtonHtml = (address, label, { animate = "" } = {}) => {
  const value = String(address ?? "");
  if (!value) return "";
  const caption = String(label ?? "") || value;
  // `animate` names a payload kind the overlay can ask its frames provider to
  // split — a PSBT past a single code's capacity becomes a UR sequence rather
  // than losing bytes or losing its button.
  const animated = animate ? ` data-address-qr-animate="${escapeHtml(animate)}"` : "";
  return `<button type="button" class="addr-qr no-print" data-address-qr="${escapeHtml(value)}" data-address-qr-label="${escapeHtml(caption)}"${animated} aria-label="${tAttr("Show QR code for {label}", { label: caption })}">${tHtml("QR")}</button>`;
};

// A WIF button identifies its current address row, not the private key. The
// click resolves the row from live wallet state and encodes the WIF then.
export const privateQrButtonHtml = (row, label) => {
  if (!row?.privateKey || !row.address || !row.path || !Number.isSafeInteger(row.branch) || row.branch < 0 || !Number.isSafeInteger(row.index) || row.index < 0) return "";
  const caption = t("WIF for {label}", { label: String(label ?? "") });
  return `<button type="button" class="addr-qr no-print" data-private-qr data-private-qr-branch="${row.branch}" data-private-qr-index="${row.index}" data-private-qr-path="${escapeHtml(row.path)}" data-private-qr-address="${escapeHtml(row.address)}" aria-label="${tAttr("Show QR code for {label}", { label: caption })}">${tHtml("QR")}</button>`;
};

// One shared overlay for every address table. `renderQr` is injected by the
// caller (app.js passes its hodlQrSvg) so the QR options — error correction,
// colors, size — stay defined next to every other QR the app renders. The
// copy and copied icons come in the same way, so the address copy control
// wears the glyphs every other copy button in the app does.
export const initAddressQr = (renderQr, icons = {}, { frames = null, privateValue = null } = {}) => {
  if (typeof renderQr !== "function" || document.getElementById("addr-qr-overlay")) return;
  // The address text and the copy button both copy. Only the button takes a
  // tab stop, so a keyboard reaches one copy control, not two. The button sits
  // with Close in the actions row, copy on the left and Close on the right, so
  // the address keeps the card's full width. The icon turning to a check is the
  // visible confirmation; the note speaks it, unseen.
  const modal = createModal({
    id: "addr-qr-overlay",
    className: "addr-qr-overlay",
    focusables: () => [text, copyButton, closeButton],
    onDismiss: () => close(),
    card: `
    <div class="modal-card addr-qr-card" role="dialog" aria-modal="true" aria-labelledby="addr-qr-title">
      <p class="modal-title addr-qr-title" id="addr-qr-title"></p>
      <p class="edge-note is-private" id="addr-qr-private-warning" hidden></p>
      <p class="field-note" id="addr-qr-path" translate="no" hidden></p>
      <div class="qr addr-qr-image" id="addr-qr-image"></div>
      <p class="field-note addr-qr-note" id="addr-qr-note" aria-live="polite"></p>
      <p class="addr-qr-address-row">
        <button type="button" class="mono addr-qr-address" id="addr-qr-address" translate="no" tabindex="-1"></button>
        <span class="sr-only" id="addr-qr-copied" aria-live="polite"></span>
      </p>
      <div class="row modal-actions">
        <button type="button" class="copy-button boxed-copy-button addr-qr-copy" id="addr-qr-copy"></button>
        <button class="btn red" id="addr-qr-close" type="button"></button>
      </div>
    </div>`,
  });
  const overlay = modal.overlay;
  const title = overlay.querySelector("#addr-qr-title"),
    privateWarning = overlay.querySelector("#addr-qr-private-warning"),
    path = overlay.querySelector("#addr-qr-path"),
    image = overlay.querySelector("#addr-qr-image"),
    note = overlay.querySelector("#addr-qr-note"),
    text = overlay.querySelector("#addr-qr-address"),
    copyButton = overlay.querySelector("#addr-qr-copy"),
    copiedNote = overlay.querySelector("#addr-qr-copied"),
    closeButton = overlay.querySelector("#addr-qr-close");
  closeButton.textContent = t("Close");
  const addressCopyLabel = t("Copy address"),
    copyIcon = icons.copy?.() ?? "",
    copiedIcon = icons.copied?.() ?? "";
  text.title = addressCopyLabel;
  image.title = addressCopyLabel;
  let payload = "", // the full value; the line above may show it shortened
    privateMode = false,
    frameTimer = 0, // cycling a UR sequence, when the payload needs one
    copiedTimer = 0;

  const resetCopied = () => {
    const copyLabel = privateMode ? t("Copy WIF") : addressCopyLabel;
    clearTimeout(copiedTimer);
    copyButton.classList.remove("is-copied");
    copyButton.innerHTML = copyIcon;
    copyButton.setAttribute("aria-label", copyLabel);
    copyButton.title = copyLabel;
    copiedNote.textContent = "";
  };
  const showCopied = () => {
    copyButton.classList.add("is-copied");
    copyButton.innerHTML = copiedIcon;
    copyButton.setAttribute("aria-label", t("Copied"));
    copyButton.title = t("Copied");
    copiedNote.textContent = t("Copied");
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(resetCopied, 1600);
  };
  const copy = () => {
    const value = payload;
    if (!value) return;
    // The fallback field goes inside the dialog, and focus comes back to the
    // copy button if removing that field let it fall out of the overlay.
    copyText(value, { host: overlay }).then((copied) => {
      // The overlay may have closed, or moved on to another address, while
      // the clipboard answered: confirm only the copy still on show.
      if (overlay.hidden || payload !== value) return;
      if (copied) showCopied();
      if (!overlay.contains(document.activeElement)) copyButton.focus({ preventScroll: true });
    });
  };
  resetCopied();

  const close = ({ restoreFocus = true } = {}) => {
    modal.hide({ restoreFocus });
    clearInterval(frameTimer);
    frameTimer = 0;
    note.textContent = "";
    // The payload can be an edited PSBT: no textual copy stays either.
    title.textContent = "";
    privateWarning.textContent = "";
    privateWarning.hidden = true;
    path.textContent = "";
    path.hidden = true;
    overlay.querySelector(".modal-card").removeAttribute("aria-describedby");
    text.textContent = "";
    delete text.dataset.private;
    image.replaceChildren(); // drop the rendered QR so a closed overlay holds no stale address
    delete image.dataset.private;
    payload = "";
    privateMode = false;
    resetCopied();
  };
  // The overlay is a body-level sibling of every wiped view, so station and
  // editor wipes cannot reach it; it tears itself down with the page.
  const teardown = () => {
    modal.hide({ restoreFocus: false });
    clearInterval(frameTimer);
    frameTimer = 0;
    note.textContent = "";
    title.textContent = "";
    privateWarning.textContent = "";
    privateWarning.hidden = true;
    path.textContent = "";
    path.hidden = true;
    overlay.querySelector(".modal-card").removeAttribute("aria-describedby");
    text.textContent = "";
    delete text.dataset.private;
    image.replaceChildren();
    delete image.dataset.private;
    payload = "";
    privateMode = false;
    resetCopied();
  };
  addEventListener("pagehide", teardown);
  addEventListener("pageshow", (event) => {
    if (event.persisted) teardown();
  });
  const open = (target) => {
    let secret = null;
    if (target.hasAttribute("data-private-qr")) {
      try { secret = privateValue?.(target); } catch { return; }
    }
    if (target.hasAttribute("data-private-qr") && !secret) return;
    const value = secret?.value ?? target.dataset.addressQr ?? "";
    if (!value) return;
    clearInterval(frameTimer);
    frameTimer = 0;
    privateMode = Boolean(secret);
    title.textContent = secret ? t("WIF for {label}", { label: secret.label }) : target.dataset.addressQrLabel || value;
    privateWarning.hidden = !privateMode;
    privateWarning.textContent = privateMode ? t("This QR contains a private key. Anyone who scans or copies it can spend from this address.") : "";
    path.hidden = !privateMode;
    path.textContent = privateMode ? secret.path : "";
    if (privateMode) {
      overlay.querySelector(".modal-card").setAttribute("aria-describedby", "addr-qr-private-warning");
      image.dataset.private = "";
      text.dataset.private = "";
      text.title = t("Copy WIF");
      image.removeAttribute("title");
    } else {
      overlay.querySelector(".modal-card").removeAttribute("aria-describedby");
      delete image.dataset.private;
      delete text.dataset.private;
      text.title = addressCopyLabel;
      image.title = addressCopyLabel;
    }
    payload = value;
    text.textContent = value.length > DISPLAY_LIMIT ? shortenMiddle(value) : value;
    // A payload the provider splits is scanned as a sequence: one code could
    // not hold it, and a truncated code would hand the signer a broken file.
    const kind = privateMode ? "" : target.dataset.addressQrAnimate || "";
    const parts = kind && typeof frames === "function" ? frames(value, kind) : null;
    if (Array.isArray(parts) && parts.length > 1) {
      let frame = 0;
      const draw = () => {
        image.innerHTML = renderQr(parts[frame]);
        note.textContent = t("Animated UR · part {n} of {total}. Keep scanning until your signer has every part.", { n: frame + 1, total: parts.length });
        frame = (frame + 1) % parts.length;
      };
      draw();
      frameTimer = setInterval(draw, 600);
    } else {
      note.textContent = "";
      try {
        image.innerHTML = renderQr(value);
      } catch {
        image.replaceChildren();
        note.textContent = t("This value is too large for a single QR code.");
      }
    }
    resetCopied();
    modal.show(closeButton, target);
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest?.("[data-address-qr], [data-private-qr]");
    if (target) open(target);
  });
  closeButton.addEventListener("click", () => close());
  text.addEventListener("click", copy);
  copyButton.addEventListener("click", copy);
  image.addEventListener("click", () => { if (!privateMode) copy(); });
  return { closePrivate: () => { if (privateMode) close({ restoreFocus: false }); } };
};
