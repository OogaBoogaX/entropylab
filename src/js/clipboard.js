// The app's one clipboard writer. Every copy control hands its text here at
// the moment of the click (a secret is built for the copy and not kept on the
// control, #546 B3), and shows its own confirmation only when the promise
// says the clipboard really took the text.
//
// The Clipboard API is used when the page has it. Where it is missing or
// refuses (older browsers, some app views, file:// origins), a hidden
// read-only field carries the text just long enough for execCommand("copy"),
// then is emptied and removed, whether the copy worked or threw. A modal
// passes itself as `host` so the field, and the focus select() gives it,
// stay inside its focus trap. Removing the focused field drops focus to the
// body, outside a modal's trap and Escape handler, so focus then goes back
// to whatever held it before the copy.
import { t as hodlTText } from "./i18n.js";

const fallbackCopy = (text, host) => {
  const focused = document.activeElement;
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.left = "-9999px";
  host.append(field);
  field.select();
  try {
    return document.execCommand("copy") === true;
  } catch {
    return false;
  } finally {
    field.value = "";
    field.remove();
    if (focused && focused !== document.activeElement) focused.focus?.({ preventScroll: true });
  }
};

// Whether this page has put anything on the clipboard, as far as the page
// can know: a page cannot read the clipboard, so if the user copied
// something else in another app since, End session will replace that newer
// item with "" too. The direction is privacy-safe — it never skips a
// clipboard the page might have written.
let wroteClipboard = false;

export const copyText = async (text, { host = document.body } = {}) => {
  if (!text) return false;
  const writeText = navigator.clipboard?.writeText;
  if (typeof writeText === "function") {
    try {
      await writeText.call(navigator.clipboard, text);
      wroteClipboard = true;
      return true;
    } catch {}
  }
  const copied = fallbackCopy(text, host);
  if (copied) wroteClipboard = true;
  return copied;
};

// End session: replaces the clipboard's current item when this page wrote
// it. The Clipboard API takes an empty string; the fallback needs a
// selection, so it copies one space. Clipboard history and sync keep their
// own copies of earlier items, which no page can reach. Resolves true when
// the clipboard was cleared, false when there was nothing of ours on it or
// the browser refused.
export const clearClipboard = async ({ host = document.body } = {}) => {
  if (!wroteClipboard) return false;
  const writeText = navigator.clipboard?.writeText;
  let cleared = false;
  if (typeof writeText === "function") {
    try {
      await writeText.call(navigator.clipboard, "");
      cleared = true;
    } catch {}
  }
  if (!cleared) cleared = fallbackCopy(" ", host);
  if (cleared) wroteClipboard = false;
  return cleared;
};

// A boxed copy control at rest: the clipboard icon and its label, with any
// pending return from the check cancelled. A dialog calls this when it opens
// again, so a check cut short by closing it does not outlive its timer.
export const resetCopiedIcon = (button, { copyIcon = "", label = hodlTText("Copy") } = {}) => {
  clearTimeout(button.copiedTimer);
  button.classList.remove("is-copied");
  button.innerHTML = copyIcon;
  button.setAttribute("aria-label", label);
  button.title = label;
};

// The icon-button confirmation every boxed copy control shows: the clipboard
// icon turns to a green check for a moment, then back. The icons come from the
// caller (app.js owns the glyphs), and a new copy restarts the timer. The
// labels are set from script, after the boot i18n sweep has run, so they come
// from the translator in the page's language.
export const showCopiedIcon = (button, { copyIcon = "", copiedIcon = "", label = hodlTText("Copy"), copiedLabel = hodlTText("Copied"), ms = 1600 } = {}) => {
  const reset = () => resetCopiedIcon(button, { copyIcon, label });
  clearTimeout(button.copiedTimer);
  button.classList.add("is-copied");
  button.innerHTML = copiedIcon;
  button.setAttribute("aria-label", copiedLabel);
  button.title = copiedLabel;
  button.copiedTimer = setTimeout(() => {
    if (button.isConnected) reset();
  }, ms);
  return reset;
};
