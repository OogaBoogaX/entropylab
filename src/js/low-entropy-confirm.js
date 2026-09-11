// Low-entropy confirmation (issue #416).
//
// The Key Station's Derive Key button enables as soon as ANY entropy is
// supplied, while the per-source warnings about staying under the recommended
// amount are easy to miss. This module adds a second step for exactly those
// sources: when the user asks to derive from less entropy than recommended, a
// modal states the estimate, and the user either goes back to add more or
// explicitly proceeds.
//
// "Don't show this again" is remembered in localStorage, the same
// site-settings store as the theme and the beta banner. When storage is
// unavailable (file:// origins, private modes) the persistence simply no-ops
// and the warning shows every time — the safe direction for a wallet tool.
//
// The pattern mirrors address-qr.js: the card markup is a pure function
// unit-tested under Node, the storage helpers take an injectable storage, and
// initLowEntropyConfirm is the only DOM entry point, keeping one shared
// overlay for the whole page.

import { t } from "./i18n.js";

export const LOW_ENTROPY_WARNING_KEY = "entropylab-low-entropy-warning-dismissed";

// Storage is injectable so the helpers are unit-testable under Node; the
// default reads the page's localStorage, and a throwing store (file://
// origins, private modes) reads as "not dismissed" so the warning still shows.
const defaultStorage = () => {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
};

export const lowEntropyWarningDismissed = (storage = defaultStorage()) => {
  try {
    return !!storage && storage.getItem(LOW_ENTROPY_WARNING_KEY) === "1";
  } catch {
    return false;
  }
};

// Returns whether the dismissal stuck; a failure must never break the flow,
// so the caller proceeds with the derivation either way.
export const dismissLowEntropyWarning = (storage = defaultStorage()) => {
  try {
    if (!storage) return false;
    storage.setItem(LOW_ENTROPY_WARNING_KEY, "1");
    return true;
  } catch {
    return false;
  }
};

// Static card skeleton. Every user-facing string is set through textContent
// at init/open time, so no translated text ever lands in a template attribute
// (see test/i18n-attribute-guard.test.mjs).
export const lowEntropyConfirmCardHtml = () => `
  <div class="low-entropy-card" role="dialog" aria-modal="true" aria-labelledby="low-entropy-title">
    <p class="low-entropy-title" id="low-entropy-title"></p>
    <p class="low-entropy-message" id="low-entropy-message"></p>
    <p class="low-entropy-detail muted" id="low-entropy-detail"></p>
    <p class="low-entropy-advice muted" id="low-entropy-advice"></p>
    <label class="choice low-entropy-dismiss-row"><input type="checkbox" id="low-entropy-dismiss" /><span id="low-entropy-dismiss-label"></span></label>
    <div class="row low-entropy-actions">
      <button class="btn secondary" id="low-entropy-more" type="button"></button>
      <button class="btn primary" id="low-entropy-proceed" type="button"></button>
    </div>
  </div>`;

// Builds the one shared overlay and returns its controls. `open(warning,
// onProceed)` shows the modal for a warning shaped { bits, recommended, words,
// detail }; "Add More Entropy" (or Escape / a backdrop click) cancels and
// returns focus to the Derive Key button, "I Understand, Proceed" optionally
// remembers the dismissal and then runs onProceed.
export const initLowEntropyConfirm = () => {
  if (document.getElementById("low-entropy-overlay")) return null;
  const overlay = document.createElement("div");
  overlay.className = "low-entropy-overlay no-print";
  overlay.id = "low-entropy-overlay";
  overlay.hidden = true;
  overlay.innerHTML = lowEntropyConfirmCardHtml();
  document.body.append(overlay);
  const title = overlay.querySelector("#low-entropy-title"),
    message = overlay.querySelector("#low-entropy-message"),
    detail = overlay.querySelector("#low-entropy-detail"),
    advice = overlay.querySelector("#low-entropy-advice"),
    dismiss = overlay.querySelector("#low-entropy-dismiss"),
    dismissLabel = overlay.querySelector("#low-entropy-dismiss-label"),
    moreButton = overlay.querySelector("#low-entropy-more"),
    proceedButton = overlay.querySelector("#low-entropy-proceed");
  title.textContent = t("Low entropy");
  advice.textContent = t("A key derived from less entropy than recommended can be guessed. Add more entropy unless you are only testing.");
  dismissLabel.textContent = t("Don't show this warning again");
  moreButton.textContent = t("Add More Entropy");
  proceedButton.textContent = t("I Understand, Proceed");
  let lastFocused = null;
  let proceed = null;

  const close = () => {
    overlay.hidden = true;
    proceed = null;
    lastFocused?.focus?.({ preventScroll: true });
    lastFocused = null;
  };
  const open = (warning, onProceed) => {
    if (typeof onProceed !== "function") return;
    message.textContent = t("You have provided only about {bits} bits of entropy (recommended: {recommended} bits for a {words}-word seed).", {
      bits: warning?.bits ?? "",
      recommended: warning?.recommended ?? "",
      words: warning?.words ?? "",
    });
    detail.textContent = warning?.detail ? t(warning.detail.key, warning.detail.vars) : "";
    detail.hidden = !warning?.detail;
    dismiss.checked = false;
    proceed = onProceed;
    lastFocused = document.activeElement;
    overlay.hidden = false;
    // The safe choice is the default focus: one more Enter adds entropy
    // instead of deriving.
    moreButton.focus();
  };
  moreButton.addEventListener("click", close);
  proceedButton.addEventListener("click", () => {
    if (dismiss.checked) dismissLowEntropyWarning();
    const run = proceed;
    close();
    run?.();
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });
  return { open, close, isOpen: () => !overlay.hidden };
};
