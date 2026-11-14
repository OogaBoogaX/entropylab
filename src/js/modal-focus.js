// Focus containment for modal dialogs.
//
// A modal gates the page behind it, so keyboard focus cycles within the
// dialog instead of escaping to a background the user cannot see or reach.
// The step is pure and unit-tested; trapModalFocus is the DOM binding, and
// every bundled modal shares both. The beta gate cannot import this: it is
// inlined through its own build token rather than the app bundle, so it
// repeats the same few lines inline.

// The next control to focus when Tab (or Shift+Tab) is pressed, cycling
// through the dialog's focusable elements.
export const nextDialogFocus = (focusables, active, shiftKey) => {
  if (!focusables.length) return null;
  const index = focusables.indexOf(active);
  if (index === -1) return focusables[0];
  return focusables[(index + (shiftKey ? -1 : 1) + focusables.length) % focusables.length];
};

// True for an element a keyboard user can reach: still in the document, not
// disabled, rendered, and not hidden by itself or an ancestor up to the
// overlay. An element outside the overlay is never reachable from it.
export const isUsableFocusable = (element, overlay) => {
  if (!element || element.isConnected === false || element.disabled) return false;
  if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) return false;
  for (let node = element; node; node = node.parentElement) {
    if (node.hidden) return false;
    if (node === overlay) return true;
  }
  return false;
};

// True for an element that can take focus back once a modal closes. The opener
// lives outside the overlay, so it only has to be connected, enabled, visible
// and not inside an inert subtree.
export const isUsableOpener = (element) => {
  if (!element || element.isConnected === false || element.disabled) return false;
  if (typeof element.focus !== "function") return false;
  for (let node = element; node; node = node.parentElement) {
    if (node.hidden) return false;
  }
  if (typeof element.closest === "function") return !element.closest("[inert]");
  for (let node = element; node; node = node.parentElement) if (node.inert) return false;
  return true;
};

// Focuses the card root (the overlay's first element child), giving it a
// tabindex of -1 when it has none so a plain div can take focus.
export const focusCardRoot = (overlay) => {
  const card = overlay?.firstElementChild;
  if (!card) return null;
  if (!card.hasAttribute?.("tabindex")) card.setAttribute?.("tabindex", "-1");
  card.focus?.();
  return card;
};

// Binds the cycle to an overlay. `getFocusables` is called per keypress so a
// card whose controls change between openings stays correct. Tab is always
// prevented: with no usable control focus goes to the card root, never to the
// inert page behind.
export const trapModalFocus = (overlay, getFocusables) => {
  overlay.addEventListener("keydown", (event) => {
    if (event.key !== "Tab") return;
    const focusables = getFocusables().filter((element) => isUsableFocusable(element, overlay));
    event.preventDefault();
    if (!focusables.length) {
      focusCardRoot(overlay);
      return;
    }
    nextDialogFocus(focusables, document.activeElement, event.shiftKey)?.focus();
  });
};
