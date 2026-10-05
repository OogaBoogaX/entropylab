// Offline reference QR codes.
//
// EntropyLab is designed to run on an air-gapped computer, so clicking an
// external educational link does nothing useful — there is no network. This
// module intercepts clicks on every external link (any <a href="https://…">
// or http://…) when the page is in the offline state and shows a pop-up QR
// code that the user can scan with an online phone to open the reference.
//
// The full URL text is shown below the QR so it can be typed or copied too.
//
// When the page is online the links behave normally (open in a new tab), so
// the hosted site is unaffected. The online/offline state is read from the
// #network-status tag that network-check.js maintains, so this module adds
// no detection of its own and the two can never disagree.
//
// Link discovery is automatic: every external link in the document — present
// or future — is handled, so new educational references get QR popups with
// no extra wiring. The QR is rendered with the same uqr library the rest of
// the app uses for address and descriptor codes.
//
// initQrReferences is the only DOM entry point; isOfflineLink and
// referenceQrSvg are pure and unit-tested under Node.

import { renderSVG as uqrRenderSvg } from "uqr";
import { createModal } from "./modal.js";
import { copyText, showCopiedIcon } from "./clipboard.js";
import { tHtml as hodlT, t as hodlTText, tAttr as hodlTAttr } from "./i18n.js";

const NETWORK_TAG_ID = "network-status";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// True for anchor elements whose href targets an external http(s) resource.
// Relative links (entropylab.html, #fragments, mailto:) are left alone.
export const isOfflineLink = (anchor) => {
  if (!anchor || anchor.tagName !== "A") return false;
  const href = anchor.getAttribute("href") ?? "";
  return /^https?:\/\//i.test(href);
};

// Renders the QR SVG markup for a URL. Returns the same SVG string the rest
// of the app produces — white background, dark modules — so the overlay's QR
// matches the existing address and descriptor codes visually.
export const referenceQrSvg = (url) =>
  uqrRenderSvg(url, { ecc: "M", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" });

// Reads the network status tag. True only when the tag reports offline.
const pageIsOffline = () => {
  const tag = document.getElementById(NETWORK_TAG_ID);
  return !!tag && tag.dataset.state === "offline";
};

let modal = null, overlayEl = null, icons = { copy: () => "", copied: () => "" };

const closeOverlay = () => modal?.hide();

const openOverlay = (url, label, opener) => {
  if (!overlayEl) return;
  const qrSvg = referenceQrSvg(url);
  const card = overlayEl.querySelector(".qr-ref-card");
  // Built on every opening, long after the boot i18n sweep, so its words go
  // through the translators (under the names the catalog extractor reads).
  card.innerHTML = `
    <p class="modal-title qr-ref-title">${escapeHtml(label)}</p>
    <div class="qr-ref-qr" aria-label="${hodlTAttr("QR code for {url}", { url })}">${qrSvg}</div>
    <p class="qr-ref-url mono">${escapeHtml(url)}</p>
    <p class="qr-ref-hint muted">${hodlT("Scan with a phone camera to open this reference on an online device.")}</p>
    <div class="row modal-actions">
      <button type="button" class="copy-button boxed-copy-button" id="qr-ref-copy" aria-label="${hodlTAttr("Copy URL")}" title="${hodlTAttr("Copy URL")}">${icons.copy()}</button>
      <button class="btn red" id="qr-ref-close" type="button">${hodlT("Close")}</button>
    </div>`;
  const copyBtn = card.querySelector("#qr-ref-copy");
  copyBtn.addEventListener("click", () => {
    copyText(url, { host: overlayEl }).then((copied) => {
      if (copied && modal.isOpen()) showCopiedIcon(copyBtn, { copyIcon: icons.copy(), copiedIcon: icons.copied(), label: hodlTText("Copy URL") });
    });
  });
  card.querySelector("#qr-ref-close").addEventListener("click", closeOverlay);
  modal.show(card.querySelector("#qr-ref-close"), opener);
};

export const initQrReferences = (glyphs = {}) => {
  if (document.getElementById("qr-ref-overlay")) return;
  icons = { ...icons, ...glyphs };
  modal = createModal({
    id: "qr-ref-overlay",
    className: "qr-ref-overlay",
    card: `<div class="modal-card qr-ref-card"></div>`,
    focusables: () => [...overlayEl.querySelectorAll("button")],
    onDismiss: closeOverlay,
  });
  overlayEl = modal.overlay;
  overlayEl.setAttribute("role", "dialog");
  overlayEl.setAttribute("aria-modal", "true");

  // Event delegation: handles links present at boot and links created later
  // (e.g. by dynamic re-renders) without any per-link registration.
  document.addEventListener("click", (event) => {
    if (!pageIsOffline()) return;
    const anchor = event.target.closest?.("a");
    if (!isOfflineLink(anchor)) return;
    event.preventDefault();
    const url = anchor.getAttribute("href");
    const label = anchor.textContent?.trim() || url;
    openOverlay(url, label, anchor);
  });
};
