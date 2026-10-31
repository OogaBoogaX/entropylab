// EntropyLab's own clipboard for private values: one value, held as UTF-8
// bytes in memory, never written to the system clipboard (other apps can read
// it, clipboard history and cloud sync keep it, and no page can erase it).
// End Session dispatches pagehide first, which zeroes the bytes; leaving the
// page does the same.
let held = null;

const announce = () => {
  if (typeof document !== "undefined" && document) document.dispatchEvent(new Event("hodl:app-clipboard"));
};

export const appClipboardPut = (text) => {
  if (typeof text !== "string" || !text) return false;
  if (held) held.fill(0);
  held = new TextEncoder().encode(text);
  announce();
  return true;
};

export const appClipboardHas = () => held !== null;

export const appClipboardText = () => (held ? new TextDecoder().decode(held) : "");

// The live buffer. Callers must copy it, never keep it: the next put or clear
// zeroes it in place (a vault passphrase field will copy it in a later part).
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
