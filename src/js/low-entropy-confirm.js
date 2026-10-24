// Low-entropy confirmation (issue #416).
//
// The Key Station's Derive Key button enables as soon as ANY entropy is
// supplied, while the per-source warnings about staying under the recommended
// amount are easy to miss. This module adds a second step for exactly those
// sources: when the user asks to derive from less entropy than recommended, a
// modal states the estimate, and the user either goes back to add more or
// explicitly proceeds.
//
// "Don't show again" is remembered in localStorage, the same site-settings
// store the beta gate's acceptance uses. When storage is unavailable
// (file:// origins, private modes) the acknowledgement simply does not stick
// the warning shows again, which is the safe direction. The store is
// injectable so it stays unit-testable under Node.
//
// The pattern mirrors address-qr.js: the card markup is a pure function
// unit-tested under Node, and initLowEntropyConfirm is the only DOM entry
// point, keeping one shared overlay for the whole page. Unlike the
// informational QR overlays, this dialog gates key creation, so it also
// contains keyboard focus: Tab and Shift+Tab cycle through the dialog's
// controls and the background is unreachable by keyboard while it is open
// (the backdrop click and Escape remain the pointer/keyboard dismissal of
// the dialog itself, which acknowledges nothing).

import { t } from "./i18n.js";
import { nextDialogFocus } from "./modal-focus.js";
import { createModal } from "./modal.js";

// Re-exported: the confirmation's own suite drives the step directly.
export { nextDialogFocus };

// The acknowledgement, remembered across sessions. Reads and writes are guarded:
// a browser that refuses storage simply keeps showing the warning, and only
// the exact stored marker counts as dismissed, so a corrupt or partial value
// fails towards showing it rather than towards silence.
export const LOW_ENTROPY_ACKNOWLEDGED_KEY = "entropylab-low-entropy-acknowledged";
export const createLowEntropyAcknowledgement = (store = globalThis.localStorage) => {
  let acknowledged = false;
  try {
    acknowledged = store?.getItem(LOW_ENTROPY_ACKNOWLEDGED_KEY) === "1";
  } catch (e) {}
  return {
    isAcknowledged: () => acknowledged,
    acknowledge: () => {
      acknowledged = true;
      try {
        store?.setItem(LOW_ENTROPY_ACKNOWLEDGED_KEY, "1");
      } catch (e) {}
    },
  };
};

// Static card skeleton. Every user-facing string is set through textContent
// at init/open time, so no translated text ever lands in a template attribute
// (see test/i18n-attribute-guard.test.mjs).
export const lowEntropyConfirmCardHtml = () => `
  <div class="modal-card is-warning low-entropy-card" id="low-entropy-dialog" role="dialog" aria-modal="true" aria-labelledby="low-entropy-title">
    <svg class="modal-warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4M12 17.5h.01"/></svg>
    <p class="modal-warning-title" id="low-entropy-title"></p>
    <p class="low-entropy-message" id="low-entropy-message"><span id="low-entropy-shortfall"></span><span class="low-entropy-recommended" id="low-entropy-recommended"></span></p>
    <p class="edge-note is-private" id="low-entropy-advice"></p>
    <div class="switch-row">
      <label class="switch-toggle"><input type="checkbox" id="low-entropy-ack" /><span class="label" id="low-entropy-ack-label"></span></label>
    </div>
    <div class="row low-entropy-actions tool-actions">
      <button class="btn primary" id="low-entropy-proceed" type="button"></button>
      <button class="btn secondary" id="low-entropy-more" type="button"></button>
    </div>
  </div>`;

// `open(warning, onProceed?, onCancel?)` returns a boolean decision promise
// and keeps the optional callback interface. Replacement and every dismissal
// resolve false; only Proceed resolves true and can remember acknowledgement.
export const initLowEntropyConfirm = () => {
  if (document.getElementById("low-entropy-overlay")) return null;
  const modal = createModal({
    id: "low-entropy-overlay",
    className: "low-entropy-overlay",
    card: lowEntropyConfirmCardHtml(),
    focusables: () => focusables,
    onDismiss: () => close(),
  });
  const overlay = modal.overlay;
  const title = overlay.querySelector("#low-entropy-title"),
    shortfall = overlay.querySelector("#low-entropy-shortfall"),
    recommended = overlay.querySelector("#low-entropy-recommended"),
    advice = overlay.querySelector("#low-entropy-advice"),
    ack = overlay.querySelector("#low-entropy-ack"),
    ackLabel = overlay.querySelector("#low-entropy-ack-label"),
    moreButton = overlay.querySelector("#low-entropy-more"),
    proceedButton = overlay.querySelector("#low-entropy-proceed");
  title.textContent = t("Low entropy");
  advice.textContent = t("A key derived from less entropy than recommended is not secure and can be guessed. Add more entropy unless you are only testing with this key.");
  ackLabel.textContent = t("Don't show again");
  moreButton.textContent = t("Add More Entropy");
  proceedButton.textContent = t("Derive Key Anyway");
  const acknowledgement = createLowEntropyAcknowledgement();
  const focusables = [ack, proceedButton, moreButton];
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
  const open = (warning, onProceed, onCancel) => {
    let resolve;
    const decision = new Promise((done) => { resolve = done; });
    const request = { onProceed, onCancel, resolve }, previous = pending;
    pending = request;
    if (previous) {
      modal.hide();
      complete(previous, false);
    }
    // A cancellation callback may open a newer request, which has already
    // canceled this one. Do not replace its message or focus afterward.
    if (pending !== request) return decision;
    shortfall.textContent = t("You have provided only about {bits} bits of entropy.", { bits: warning?.bits ?? "" });
    recommended.textContent = t("Recommended: {recommended} bits for a {words}-word seed", {
      recommended: warning?.recommended ?? "",
      words: warning?.words ?? "",
    });
    ack.checked = false;
    // The safe choice is the default focus: one more Enter adds entropy
    // instead of deriving.
    modal.show(moreButton);
    return decision;
  };
  moreButton.addEventListener("click", () => close());
  proceedButton.addEventListener("click", () => {
    if (!pending || !modal.isOpen()) return;
    if (ack.checked) acknowledgement.acknowledge();
    settle(true);
  });
  return { open, close, isOpen: modal.isOpen, isAcknowledged: acknowledgement.isAcknowledged };
};
