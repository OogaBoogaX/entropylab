// End session: one control that ends everything this page holds and then
// asks the browser to close the tab.
//
// The residue audit (2026-10-03) found that closing the tab is the only step
// that removes every copy of a secret in Chrome and Edge: the page's process
// exits, and the operating system reclaims its memory. Wiping inside the
// page cannot reach strings, DOM text or the browser's own copies. So this
// does what the page can, in order, and then hands over to the browser:
//
//   1. every wipe the page runs when it is left (the `pagehide` listeners:
//      each station, the Journal, Vanity's workers, the two dialogs). A
//      Vanity grind in progress is terminated, not wiped: worker.terminate()
//      is a hard kill, so the worker's message loop never runs wipeSecrets()
//      and its linear memory is freed unzeroed — only closing the tab covers
//      it;
//   2. the WebAssembly modules' whole linear memory, overwritten with the
//      patterns 0x55, 0xAA and 0xFF and then zeroed, and the modules retired
//      so nothing can run on them again;
//   3. the clipboard, emptied if this page wrote it;
//   4. the page replaced by a short screen, which drops the old DOM;
//   5. window.close(). A browser closes a tab by script only when it allows
//      it (typically a tab opened straight to this file, with no history to
//      go back to), so the screen says to close the tab when it is still
//      showing.
//
// Steps 2 and 3 come from the caller, so the suite can drive the sequence.
//
// Edge is the exception to "closing the tab is enough". Measured on
// 2026-10-06 (Windows 11, Edge 154): after Copy seed phrase, Edge's browser
// process still held 2 or 3 copies of the phrase once the tab closed, until
// Edge itself was quit. So in Edge the dialog, which everyone sees before
// the tab closes, also says to quit Edge. Other browsers see no change.

import { t } from "./i18n.js";
import { createModal } from "./modal.js";

// Microsoft Edge, from its brand in navigator.userAgentData where the browser
// has one, else the token Edge puts in its user agent: "Edg/" on desktop,
// "EdgA/" on Android, "EdgiOS/" on iOS. Read on this device only.
export const isEdge = (nav) => {
  const brands = nav?.userAgentData?.brands;
  if (Array.isArray(brands) && brands.some((entry) => entry?.brand === "Microsoft Edge")) return true;
  return /\bEdg(?:A|iOS)?\//.test(String(nav?.userAgent ?? ""));
};

// The dialog's extra warning in Edge; null in every other browser.
export const endSessionEdgeWarning = (nav) => isEdge(nav)
  ? t("You are using Microsoft Edge. In our tests, Edge kept copies of a copied seed phrase after the tab closed, until Edge itself was quit. Assume it does the same with any secret you copy, such as a private key. Quit Edge completely, and turn off Startup boost and background apps in its System settings.")
  : null;

// Static card skeleton; its words are set through textContent at init, so no
// translated text lands in a template attribute.
export const endSessionCardHtml = () => `
  <div class="modal-card is-warning end-session-card" id="end-session-dialog" role="dialog" aria-modal="true" aria-labelledby="end-session-title" aria-describedby="end-session-message">
    <svg class="modal-warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v9"/><path d="M6.3 6.3a8 8 0 1 0 11.4 0"/></svg>
    <p class="modal-warning-title" id="end-session-title"></p>
    <div class="end-session-text"><p id="end-session-message"></p></div>
    <div class="row tool-actions">
      <button class="btn red" id="end-session-confirm" type="button"></button>
      <button class="btn secondary" id="end-session-cancel" type="button"></button>
    </div>
  </div>`;

// The screen left behind. Built from elements and textContent: nothing of the
// session, and no catalog markup, reaches it.
export const renderSessionEnded = (doc, { clipboardCleared = false } = {}) => {
  const main = doc.createElement("main");
  main.className = "sanity-failure";
  main.dataset.sessionEnded = "";
  // The same card as the disclaimer gate: the power mark, the title in the
  // warning red, then the sentences in one centred column.
  const card = doc.createElement("div");
  card.className = "modal-card is-warning end-session-card";
  card.setAttribute("role", "status");
  const svg = "http://www.w3.org/2000/svg";
  const icon = doc.createElementNS(svg, "svg");
  for (const [name, value] of [["class", "modal-warning-icon"], ["viewBox", "0 0 24 24"], ["fill", "none"], ["stroke", "currentColor"], ["stroke-width", "2"], ["stroke-linecap", "round"], ["stroke-linejoin", "round"], ["aria-hidden", "true"]]) icon.setAttribute(name, value);
  for (const d of ["M12 3v9", "M6.3 6.3a8 8 0 1 0 11.4 0"]) {
    const path = doc.createElementNS(svg, "path");
    path.setAttribute("d", d);
    icon.append(path);
  }
  const title = doc.createElement("h1");
  title.className = "modal-warning-title";
  title.textContent = t("Session ended");
  const text = doc.createElement("div");
  text.className = "end-session-text";
  const line = (value) => {
    const element = doc.createElement("p");
    element.textContent = value;
    text.append(element);
  };
  line(t("EntropyLab wiped every key, seed and field this page held. A Vanity grind cut short mid-run is the one exception: its workers are stopped, not wiped — closing the tab covers them."));
  line(t("Close this tab now, or quit the browser: that is what erases the copies the browser keeps for itself. Reloading starts a new session but does not erase them."));
  if (clipboardCleared) line(t("The clipboard was emptied. Clipboard history and cloud clipboard sync keep their own copies of what was copied."));
  line(t("Chrome and Edge keep running after the last window closes unless “Continue running background apps” is off in their System settings."));
  card.append(icon, title, text);
  main.append(card);
  doc.body.replaceChildren(main);
};

export const endSession = async ({ win = window, doc = document, retireModules = [], clearClipboard = async () => false } = {}) => {
  win.dispatchEvent(new win.PageTransitionEvent("pagehide", { persisted: false }));
  // The retires cannot throw today; if one ever does, the screen and
  // window.close() below must still run, so keep this sequence flat.
  for (const retire of retireModules) retire();
  // Started inside the confirm click, while the browser still counts it as
  // the user's action; some browsers refuse a clipboard write without one.
  const clipboardCleared = await clearClipboard().catch(() => false);
  renderSessionEnded(doc, { clipboardCleared });
  win.close();
};

// The confirm dialog. `open()` shows it with Cancel focused (the safe
// choice); Cancel, Escape or a click on the dimmed page closes it and
// nothing happens; End Session runs `onEnd`.
export const initEndSessionConfirm = (onEnd) => {
  if (document.getElementById("end-session-overlay")) return null;
  const modal = createModal({
    id: "end-session-overlay",
    className: "end-session-overlay",
    card: endSessionCardHtml(),
    focusables: () => focusables,
    onDismiss: () => modal.hide(),
  });
  const overlay = modal.overlay;
  const confirmButton = overlay.querySelector("#end-session-confirm"),
    cancelButton = overlay.querySelector("#end-session-cancel");
  overlay.querySelector("#end-session-title").textContent = t("End this session?");
  overlay.querySelector("#end-session-message").textContent = t("EntropyLab wipes every key, seed and field on this page, empties the clipboard if it copied something, and asks the browser to close this tab. Anything you have not written down or saved is lost.");
  const edgeWarning = endSessionEdgeWarning(globalThis.navigator);
  if (edgeWarning) {
    const paragraph = document.createElement("p");
    paragraph.id = "end-session-edge";
    paragraph.textContent = edgeWarning;
    overlay.querySelector(".end-session-text").append(paragraph);
    overlay.querySelector("#end-session-dialog").setAttribute("aria-describedby", "end-session-message end-session-edge");
  }
  confirmButton.textContent = t("End Session");
  cancelButton.textContent = t("Cancel");
  const focusables = [confirmButton, cancelButton];
  cancelButton.addEventListener("click", () => modal.hide());
  confirmButton.addEventListener("click", () => {
    modal.hide({ restoreFocus: false });
    onEnd();
  });
  return { open: (opener) => modal.show(cancelButton, opener), isOpen: modal.isOpen };
};
