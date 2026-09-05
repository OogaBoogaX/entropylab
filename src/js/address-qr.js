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

import { t } from "./i18n.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// Row markup: a small button rendered next to the address text. `label`
// names the address ("Address #3") for the overlay title and the aria-label.
// Addresses are public data, so the button is also shown in tables that
// include a WIF column — but it only ever encodes the address.
export const addressQrButtonHtml = (address, label) => {
  const value = String(address ?? "");
  if (!value) return "";
  const caption = String(label ?? "") || value;
  return `<button type="button" class="addr-qr no-print" data-address-qr="${escapeHtml(value)}" data-address-qr-label="${escapeHtml(caption)}" aria-label="${escapeHtml(t("Show QR code for {label}", { label: caption }))}">${escapeHtml(t("QR"))}</button>`;
};

// One shared overlay for every address table. `renderQr` is injected by the
// caller (app.js passes its hodlQrSvg) so the QR options — error correction,
// colors, size — stay defined next to every other QR the app renders.
export const initAddressQr = (renderQr) => {
  if (typeof renderQr !== "function" || document.getElementById("addr-qr-overlay")) return;
  const overlay = document.createElement("div");
  overlay.className = "addr-qr-overlay no-print";
  overlay.id = "addr-qr-overlay";
  overlay.hidden = true;
  overlay.innerHTML = `
    <div class="addr-qr-card" role="dialog" aria-modal="true" aria-labelledby="addr-qr-title">
      <p class="addr-qr-title" id="addr-qr-title"></p>
      <div class="qr addr-qr-image" id="addr-qr-image"></div>
      <p class="mono addr-qr-address" id="addr-qr-address"></p>
      <div class="row addr-qr-actions">
        <button class="btn secondary" id="addr-qr-close" type="button"></button>
      </div>
    </div>`;
  document.body.append(overlay);
  const title = overlay.querySelector("#addr-qr-title"),
    image = overlay.querySelector("#addr-qr-image"),
    text = overlay.querySelector("#addr-qr-address"),
    closeButton = overlay.querySelector("#addr-qr-close");
  closeButton.textContent = t("Close");
  let button = null;

  const close = () => {
    overlay.hidden = true;
    image.replaceChildren(); // drop the rendered QR so a closed overlay holds no stale address
    button?.focus({ preventScroll: true });
    button = null;
  };
  const open = (target) => {
    const value = target.dataset.addressQr ?? "";
    if (!value) return;
    button = target;
    title.textContent = target.dataset.addressQrLabel || value;
    image.innerHTML = renderQr(value);
    text.textContent = value;
    overlay.hidden = false;
    closeButton.focus();
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest?.("[data-address-qr]");
    if (target) open(target);
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });
  closeButton.addEventListener("click", close);
};
