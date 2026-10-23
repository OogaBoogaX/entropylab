// Shared-fingerprint confirmation (GHSA-6rr2-5r82-grwc follow-up).
//
// A master fingerprint is 4 display bytes, so a newly derived wallet can show
// the same fingerprint as a different wallet already open in Key Station.
// Both tabs are then correct but look identical: same label, same LifeHash.
// Before such a wallet is committed as a tab, this modal says so; the user
// either proceeds ("I Understand") or cancels, which discards the derivation.
//
// The pattern mirrors low-entropy-confirm.js: a pure card-markup function,
// one shared overlay built by the init function, user-facing strings set
// through textContent (never a template attribute), and the shared focus
// trap. Escape and a backdrop click cancel.

import { t } from "./i18n.js";
import { createModal } from "./modal.js";

export const fingerprintCollisionCardHtml = () => `
  <div class="modal-card is-warning fingerprint-collision-card" id="fingerprint-collision-dialog" role="dialog" aria-modal="true" aria-labelledby="fingerprint-collision-title" aria-describedby="fingerprint-collision-message">
    <svg class="modal-warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4M12 17.5h.01"/></svg>
    <p class="modal-warning-title" id="fingerprint-collision-title"></p>
    <p class="fingerprint-collision-message" id="fingerprint-collision-message"></p>
    <p class="edge-note is-private" id="fingerprint-collision-advice"></p>
    <div class="row fingerprint-collision-actions tool-actions">
      <button class="btn primary" id="fingerprint-collision-proceed" type="button"></button>
      <button class="btn secondary" id="fingerprint-collision-cancel" type="button"></button>
    </div>
  </div>`;

// `open(fingerprint, onProceed?, onCancel?)` returns a boolean decision
// promise and retains the optional callbacks. Replacement, dismissal, and
// close cancel exactly once; only Proceed accepts the current request.
export const initFingerprintCollisionConfirm = () => {
  if (document.getElementById("fingerprint-collision-overlay")) return null;
  const modal = createModal({
    id: "fingerprint-collision-overlay",
    className: "fingerprint-collision-overlay",
    card: fingerprintCollisionCardHtml(),
    focusables: () => [proceedButton, cancelButton],
    onDismiss: () => settle(false),
  });
  const overlay = modal.overlay;
  const message = overlay.querySelector("#fingerprint-collision-message"),
    advice = overlay.querySelector("#fingerprint-collision-advice"),
    cancelButton = overlay.querySelector("#fingerprint-collision-cancel"),
    proceedButton = overlay.querySelector("#fingerprint-collision-proceed");
  overlay.querySelector("#fingerprint-collision-title").textContent = t("Shared fingerprint");
  advice.textContent = t("Rename one of the tabs to tell them apart by clicking on the tab label.");
  proceedButton.textContent = t("I Understand");
  cancelButton.textContent = t("Cancel");
  let pending = null;

  const complete = (request, accepted) => {
    request.resolve(accepted);
    (accepted ? request.onProceed : request.onCancel)?.();
  };
  const settle = (accepted, options) => {
    const request = pending;
    if (!request) return;
    pending = null;
    modal.hide(options);
    complete(request, accepted);
  };
  const close = (options) => settle(false, options);
  const open = (fingerprint, onProceed, onCancel) => {
    let resolve;
    const decision = new Promise((done) => { resolve = done; });
    const request = { onProceed, onCancel, resolve }, previous = pending;
    pending = request;
    if (previous) {
      modal.hide();
      complete(previous, false);
    }
    if (pending !== request) return decision;
    message.textContent = t("Another wallet open in this session also has fingerprint {fingerprint}. A fingerprint is only 4 bytes, so different wallets can share one: these are separate wallets.", { fingerprint });
    modal.show(proceedButton);
    return decision;
  };
  proceedButton.addEventListener("click", () => settle(true));
  cancelButton.addEventListener("click", () => settle(false));
  return { open, close, isOpen: modal.isOpen };
};
