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

// Binds the cycle to an overlay. `getFocusables` is called per keypress so a
// card whose controls change between openings stays correct.
export const trapModalFocus = (overlay, getFocusables) => {
  overlay.addEventListener("keydown", (event) => {
    if (event.key !== "Tab") return;
    const focusables = getFocusables().filter(Boolean);
    if (!focusables.length) return;
    event.preventDefault();
    nextDialogFocus(focusables, document.activeElement, event.shiftKey)?.focus();
  });
};
