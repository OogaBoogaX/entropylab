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

let overlayEl = null;
let lastFocused = null;

const closeOverlay = () => {
  if (!overlayEl) return;
  overlayEl.hidden = true;
  lastFocused?.focus?.({ preventScroll: true });
  lastFocused = null;
};

const openOverlay = (url, label) => {
  if (!overlayEl) return;
  const qrSvg = referenceQrSvg(url);
  const card = overlayEl.querySelector(".qr-ref-card");
  card.innerHTML = `
    <p class="qr-ref-title">${escapeHtml(label)}</p>
    <div class="qr-ref-qr" aria-label="QR code for ${escapeHtml(url)}">${qrSvg}</div>
    <p class="qr-ref-url mono">${escapeHtml(url)}</p>
    <p class="qr-ref-hint muted">Scan with a phone camera to open this reference on an online device.</p>
    <div class="row qr-ref-actions">
      <button class="btn secondary" id="qr-ref-copy" type="button">Copy URL</button>
      <button class="btn primary" id="qr-ref-close" type="button">Close</button>
    </div>`;
  const copyBtn = card.querySelector("#qr-ref-copy");
  copyBtn.addEventListener("click", () => {
    navigator.clipboard?.writeText(url).then(() => {
      copyBtn.textContent = "Copied";
      setTimeout(() => { copyBtn.textContent = "Copy URL"; }, 1500);
    }).catch(() => {});
  });
  card.querySelector("#qr-ref-close").addEventListener("click", closeOverlay);
  overlayEl.hidden = false;
  card.querySelector("#qr-ref-close").focus();
};

export const initQrReferences = () => {
  if (document.getElementById("qr-ref-overlay")) return;
  overlayEl = document.createElement("div");
  overlayEl.className = "qr-ref-overlay no-print";
  overlayEl.id = "qr-ref-overlay";
  overlayEl.hidden = true;
  overlayEl.setAttribute("role", "dialog");
  overlayEl.setAttribute("aria-modal", "true");
  overlayEl.innerHTML = `<div class="qr-ref-card"></div>`;
  document.body.append(overlayEl);

  overlayEl.addEventListener("click", (event) => {
    if (event.target === overlayEl) closeOverlay();
  });
  overlayEl.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeOverlay();
  });

  // Event delegation: handles links present at boot and links created later
  // (e.g. by dynamic re-renders) without any per-link registration.
  document.addEventListener("click", (event) => {
    if (!pageIsOffline()) return;
    const anchor = event.target.closest?.("a");
    if (!isOfflineLink(anchor)) return;
    event.preventDefault();
    const url = anchor.getAttribute("href");
    const label = anchor.textContent?.trim() || url;
    lastFocused = anchor;
    openOverlay(url, label);
  });
};
