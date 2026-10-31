// EntropyLab's own clipboard for private values: one value, held as UTF-8
// bytes in memory, never written to the system clipboard (other apps can read
// it, clipboard history and cloud sync keep it, and no page can erase it).
// End Session dispatches pagehide first, which zeroes the bytes; leaving the
// page does the same.
let held = null;

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
  announce();
};

export const initAppClipboard = (target = globalThis) => {
  const onPageHide = () => appClipboardClear();
  target.addEventListener("pagehide", onPageHide);
  return () => target.removeEventListener("pagehide", onPageHide);
};
