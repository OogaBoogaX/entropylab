import { t } from "./i18n.js";
import { createModal } from "./modal.js";

// Asks how to switch Secure entry on or off when words already exist: keep or
// clear them on the way in, convert or clear them on the way out. Only an
// explicit Keep, Clear or Convert resolves a choice; every dismissal resolves
// null, and the text, key names included, is discarded on close.
export const initSecureEntryConfirm = () => {
  const modal = createModal({
    id: "secure-entry-modal",
    className: "",
    card: `
      <div class="modal-card" id="secure-entry-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="secure-entry-confirm-title" aria-describedby="secure-entry-confirm-message">
        <h2 class="modal-title" id="secure-entry-confirm-title"></h2>
        <p id="secure-entry-confirm-message"></p>
        <ul id="secure-entry-confirm-names" data-i18n-skip translate="no" hidden></ul>
        <p class="edge-note is-private" id="secure-entry-confirm-cannot-keep" hidden></p>
        <div class="row tool-actions">
          <button class="btn primary" id="secure-entry-confirm-primary" type="button"></button>
          <button class="btn red" id="secure-entry-confirm-secondary" type="button"></button>
          <button class="btn secondary" id="secure-entry-confirm-cancel" type="button"></button>
        </div>
      </div>`,
    focusables: () => [primary, secondary, cancel].filter((button) => !button.hidden && !button.disabled),
    onDismiss: () => settle(null),
  });
  const find = (id) => modal.overlay.querySelector(`#secure-entry-confirm-${id}`);
  const title = find("title"), message = find("message"), names = find("names"), cannotKeep = find("cannot-keep");
  const primary = find("primary"), secondary = find("secondary"), cancel = find("cancel");
  let pending = null, primaryChoice = null, secondaryChoice = null, opener = null;

  const clearText = () => {
    for (const field of [title, message, cannotKeep, primary, secondary, cancel]) field.textContent = "";
    names.replaceChildren();
  };
  const settle = (choice, options) => {
    const resolve = pending;
    pending = null;
    primaryChoice = secondaryChoice = null;
    clearText();
    modal.hide(options);
    opener = null;
    resolve?.(choice);
  };
  const close = (options) => settle(null, options);
  const open = (options = {}) => {
    const from = options.opener || (modal.isOpen() ? opener : document.activeElement);
    close({ restoreFocus: false });
    if (options.mode !== "on" && options.mode !== "off") return Promise.resolve(null);
    const on = options.mode === "on";
    const list = on && Array.isArray(options.names) ? options.names : [];
    // Turning on asks only about keys that hold words; with none there is
    // nothing to keep, so it never claims there is.
    if (on && list.length === 0) return Promise.resolve(null);
    opener = from;
    names.hidden = !on;
    cannotKeep.hidden = !on || options.canKeep !== false;
    primary.hidden = on && options.canKeep === false;
    cancel.textContent = t("Cancel");
    if (on) {
      title.textContent = t("Turn on secure entry?");
      if (list.length === 1) {
        message.textContent = t("{name} already has words in the text field. Turning this on cannot remove copies already created.", { name: String(list[0]) });
        names.hidden = true;
      } else {
        message.textContent = t("These keys already have words in the text field. Turning this on cannot remove copies already created.");
        names.hidden = false;
        for (const name of list) {
          const item = document.createElement("li");
          item.textContent = String(name);
          names.append(item);
        }
      }
      primary.textContent = t("Keep current entry");
      secondary.textContent = t("Clear and start again");
      cannotKeep.textContent = t("Some of these words are not on the BIP39 English list, so they cannot be kept.");
      primaryChoice = "keep";
      secondaryChoice = "clear";
    } else {
      title.textContent = t("Turn off secure entry?");
      message.textContent = t("Converting puts the words back into standard text fields, which creates text copies. Either choice applies to every key in this session.");
      primary.textContent = t("Convert entries to standard text");
      secondary.textContent = t("Clear entries and turn off");
      primaryChoice = "convert";
      secondaryChoice = "clear";
    }
    const decision = new Promise((resolve) => { pending = resolve; });
    modal.show(cancel, opener);
    return decision;
  };
  primary.addEventListener("click", () => { if (modal.isOpen() && !primary.hidden && !primary.disabled && primaryChoice) settle(primaryChoice); });
  secondary.addEventListener("click", () => { if (modal.isOpen() && !secondary.hidden && !secondary.disabled && secondaryChoice) settle(secondaryChoice); });
  cancel.addEventListener("click", () => { if (modal.isOpen()) close(); });
  return { open, close, isOpen: () => modal.isOpen() };
};
