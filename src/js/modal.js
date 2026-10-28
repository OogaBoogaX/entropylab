// The app's one modal shell. A modal is a page-level overlay holding one card:
// it dims the page, keeps keyboard focus inside the card, closes from Escape or
// a click on the dimmed page, and hands focus back to whatever opened it. Each
// module supplies only what differs: the card markup, the controls focus
// cycles through, and what dismissing means (cancel a decision, or just close).
//
// createModal({ id, className, card, focusables, onDismiss }) appends the
// hidden overlay `<div class="modal-overlay {className} no-print" id="{id}">`
// with `card` inside, and returns:
//   show(focus, opener)  reveals it, makes the page behind it inert, focuses
//                        `focus` (or the first usable control, or the card),
//                        and remembers `opener` (default: whatever had focus)
//                        to return focus to;
//   hide({ restoreFocus = true })  hides it, restores the page, and returns
//                        focus unless asked not to (a page teardown has
//                        nowhere to return it);
//   isOpen()             whether it is showing.
// `focusables` is called per keypress, so a card whose controls change between
// openings stays correct. The beta gate cannot use this: it is inlined through
// its own build token rather than the app bundle (see modal-focus.js).
import { trapModalFocus, isUsableFocusable, isUsableOpener, focusCardRoot } from "./modal-focus.js";

// Every modal shares one stack of what is open (top last) and one record of
// what the shell changed on the page, so closing an outer modal while an inner
// one is still open leaves the page inert and the inner modal reachable.
const openStack = [];
const changed = new Map();

// Makes the page behind the top modal inert and everything else, including any
// modal below it, unreachable; with nothing open it puts every element back
// exactly as it was found.
const applyInert = () => {
  // An overlay removed from the page without hide() must not stay on top and
  // leave everything else inert.
  for (let i = openStack.length - 1; i >= 0; i--) {
    if (openStack[i].overlay.isConnected === false) openStack.splice(i, 1);
  }
  if (!openStack.length) {
    for (const [element, original] of changed) {
      element.inert = original.inert;
      if (original.ariaHidden === null) element.removeAttribute?.("aria-hidden");
      else element.setAttribute?.("aria-hidden", original.ariaHidden);
    }
    changed.clear();
    return;
  }
  const top = openStack.at(-1).overlay;
  for (const element of document.body.children ?? []) {
    if (element === top) {
      element.inert = false;
      const original = changed.get(element);
      if (original && original.ariaHidden !== null) element.setAttribute?.("aria-hidden", original.ariaHidden);
      else element.removeAttribute?.("aria-hidden");
      continue;
    }
    if (!changed.has(element)) {
      changed.set(element, {
        inert: element.inert === true,
        ariaHidden: element.hasAttribute?.("aria-hidden") ? element.getAttribute("aria-hidden") : null,
      });
    }
    element.inert = true;
    element.setAttribute?.("aria-hidden", "true");
  }
};

export const createModal = ({ id, className, card, focusables, onDismiss }) => {
  const overlay = document.createElement("div");
  overlay.className = `modal-overlay ${className} no-print`;
  overlay.id = id;
  overlay.hidden = true;
  overlay.innerHTML = card;
  document.body.append(overlay);
  // The card root carries the dialog semantics. A caller that already set a
  // role (alertdialog) or a name keeps it; the shell never invents a name.
  const cardRoot = overlay.firstElementChild;
  if (cardRoot) {
    if (!cardRoot.hasAttribute?.("role")) cardRoot.setAttribute?.("role", "dialog");
    if (!cardRoot.hasAttribute?.("aria-modal")) cardRoot.setAttribute?.("aria-modal", "true");
  }
  let opener = null;
  const canFocus = (element) => isUsableFocusable(element, overlay) && typeof element?.focus === "function";
  const show = (focus, from = document.activeElement) => {
    const index = openStack.findIndex((item) => item.overlay === overlay);
    if (index === -1) {
      opener = from;
      openStack.push({ overlay });
    } else {
      // Already open: it moves to the top but keeps the opener it remembered.
      openStack.push(openStack.splice(index, 1)[0]);
    }
    overlay.hidden = false;
    applyInert();
    const target = canFocus(focus) ? focus : focusables().find(canFocus);
    if (target) target.focus();
    else focusCardRoot(overlay);
  };
  const hide = ({ restoreFocus = true } = {}) => {
    const index = openStack.findIndex((item) => item.overlay === overlay);
    if (index === -1) return;
    // Only the modal that was on top hands focus back; hiding one underneath
    // leaves focus inside the modal the user is still looking at.
    const wasTop = index === openStack.length - 1;
    openStack.splice(index, 1);
    overlay.hidden = true;
    applyInert();
    const target = opener;
    opener = null;
    if (wasTop && restoreFocus && isUsableOpener(target)) target.focus({ preventScroll: true });
  };
  trapModalFocus(overlay, focusables);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) onDismiss();
  });
  overlay.addEventListener("keydown", (event) => {
    // Some IMEs report the keydown that ends a composition as keyCode 229
    // without isComposing; neither may cancel the dialog.
    if (event.key === "Escape" && !event.isComposing && event.keyCode !== 229) onDismiss();
  });
  return { overlay, show, hide, isOpen: () => !overlay.hidden };
};
