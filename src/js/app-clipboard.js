// EntropyLab's own clipboard for private values: one value, held as UTF-8
// bytes in memory, never written to the system clipboard (other apps can read
// it, clipboard history and cloud sync keep it, and no page can erase it).
// End Session dispatches pagehide first, which zeroes the bytes; leaving the
// page does the same.
let held = null, generation = 0;

const announce = () => {
  if (typeof document !== "undefined" && typeof document?.dispatchEvent === "function") document.dispatchEvent(new Event("hodl:app-clipboard"));
};

// A lone surrogate has no UTF-8 form (TextEncoder would swap in U+FFFD), so
// such text is refused rather than held as a different value. Checked by hand:
// older engines lack String.prototype.isWellFormed.
const wellFormed = (text) => {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xdc00 && unit <= 0xdfff) return false;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    }
  }
  return true;
};

export const appClipboardPut = (text) => {
  if (typeof text !== "string" || !text || !wellFormed(text)) return false;
  if (held) held.fill(0);
  held = new TextEncoder().encode(text);
  generation += 1;
  announce();
  return true;
};

export const appClipboardHas = () => held !== null;

// ignoreBOM keeps a leading U+FEFF that was copied (the default decoder drops it).
export const appClipboardText = () => (held ? new TextDecoder("utf-8", { ignoreBOM: true }).decode(held) : "");

// The live buffer. Callers must copy it, never keep it: the next put or clear
// zeroes it in place (a vault passphrase field's paste copies it).
export const appClipboardBytes = () => held;

export const appClipboardClear = () => {
  if (held) {
    held.fill(0);
    held = null;
  }
  generation += 1;
  announce();
};

// Changes on every put and clear, so a caller that awaited can tell whether
// what it saw held is still what is held.
export const appClipboardGeneration = () => generation;

// End Session (pagehide) clears it, and so does every time the page hides
// private values ("hodl:conceal": tab hidden, window blur, print, idle), so a
// paste control never brings back a value the page has just hidden (owner 10-31).
// So does any copy or cut to the system clipboard from the page (Ctrl+C on a
// selection, not only the app's own copy controls): "cleared when you copy
// something else" holds for every copy (Astra, K3.1).
const DOC_EVENTS = ["hodl:conceal", "copy", "cut"];
// The app's own fallback copy (execCommand) fires a copy event too; it runs
// through here so copyText's generation check decides, not the listener.
let ownCopies = 0;
export const appClipboardOwnCopy = (copy) => {
  ownCopies += 1;
  try { return copy(); } finally { ownCopies -= 1; }
};
export const initAppClipboard = (target = globalThis, doc = target.document) => {
  const clear = (event) => {
    if (ownCopies && event && event.type !== "hodl:conceal") return;
    appClipboardClear();
  };
  target.addEventListener("pagehide", clear);
  for (const type of DOC_EVENTS) doc?.addEventListener(type, clear);
  return () => {
    target.removeEventListener("pagehide", clear);
    for (const type of DOC_EVENTS) doc?.removeEventListener(type, clear);
  };
};
