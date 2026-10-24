// The app's one modal shell. A modal is a page-level overlay holding one card:
// it dims the page, keeps keyboard focus inside the card, closes from Escape or
// a click on the dimmed page, and hands focus back to whatever opened it. Each
// module supplies only what differs: the card markup, the controls focus
// cycles through, and what dismissing means (cancel a decision, or just close).
//
// createModal({ id, className, card, focusables, onDismiss }) appends the
// hidden overlay `<div class="modal-overlay {className} no-print" id="{id}">`
// with `card` inside, and returns:
//   show(focus, opener)  reveals it, focuses `focus`, and remembers `opener`
//                        (default: whatever had focus) to return focus to;
//   hide({ restoreFocus = true })  hides it, and returns focus unless asked not
//                        to (a page teardown has nowhere to return it);
//   isOpen()             whether it is showing.
// `focusables` is called per keypress, so a card whose controls change between
// openings stays correct. The beta gate cannot use this: it is inlined through
// its own build token rather than the app bundle (see modal-focus.js).
import { trapModalFocus } from "./modal-focus.js";

export const createModal = ({ id, className, card, focusables, onDismiss }) => {
  const overlay = document.createElement("div");
  overlay.className = `modal-overlay ${className} no-print`;
  overlay.id = id;
  overlay.hidden = true;
  overlay.innerHTML = card;
  document.body.append(overlay);
  let opener = null;
  const show = (focus, from = document.activeElement) => {
    opener = from;
    overlay.hidden = false;
    focus?.focus();
  };
  const hide = ({ restoreFocus = true } = {}) => {
    overlay.hidden = true;
    const target = opener;
    opener = null;
    if (restoreFocus) target?.focus?.({ preventScroll: true });
  };
  trapModalFocus(overlay, focusables);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) onDismiss();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") onDismiss();
  });
  return { overlay, show, hide, isOpen: () => !overlay.hidden };
};
