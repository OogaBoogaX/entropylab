import { t } from "./i18n.js";
import { createModal } from "./modal.js";

// Asks for the passphrase that encrypts or opens a nonce history file. The
// file's key comes from the passphrase alone (no random-number generator), so
// the same passphrase gives the same key in every file and for every user: an
// attacker can grind common passphrases once for all files. Use a long, unique
// passphrase. Only an explicit Encrypt and download or Open resolves a
// passphrase; every dismissal resolves null, and both fields are emptied on
// close.
export const initNonceHistoryConfirm = () => {
  const modal = createModal({
    id: "nonce-history-confirm-modal",
    className: "",
    card: `
      <div class="modal-card" id="nonce-history-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="nonce-history-confirm-title" aria-describedby="nonce-history-confirm-message">
        <h2 class="modal-title" id="nonce-history-confirm-title"></h2>
        <p class="edge-note is-private" id="nonce-history-confirm-message"></p>
        <label for="nonce-history-confirm-passphrase" id="nonce-history-confirm-passphrase-label"></label>
        <input type="password" id="nonce-history-confirm-passphrase" autocomplete="new-password" spellcheck="false">
        <label for="nonce-history-confirm-repeat" id="nonce-history-confirm-repeat-label"></label>
        <input type="password" id="nonce-history-confirm-repeat" autocomplete="new-password" spellcheck="false">
        <div class="row tool-actions">
          <button class="btn primary" id="nonce-history-confirm-primary" type="button" disabled></button>
          <button class="btn secondary" id="nonce-history-confirm-cancel" type="button"></button>
        </div>
      </div>`,
    focusables: () => [passphrase, repeat, primary, cancel].filter((field) => !field.hidden && !field.disabled),
    onDismiss: () => settle(null),
  });
  const find = (id) => modal.overlay.querySelector(`#nonce-history-confirm-${id}`);
  const title = find("title"), message = find("message");
  const passphraseLabel = find("passphrase-label"), repeatLabel = find("repeat-label");
  const passphrase = find("passphrase"), repeat = find("repeat");
  const primary = find("primary"), cancel = find("cancel");
  let pending = null, opener = null, mode = null;

  const clearText = () => {
    for (const field of [title, message, passphraseLabel, repeatLabel, primary, cancel]) field.textContent = "";
    passphrase.value = "";
    repeat.value = "";
  };
  const settle = (value, options) => {
    const resolve = pending;
    pending = null;
    mode = null;
    clearText();
    modal.hide(options);
    opener = null;
    resolve?.(value);
  };
  const close = (options) => settle(null, options);
  const updatePrimary = () => {
    if (mode === "download") primary.disabled = !(passphrase.value && repeat.value && passphrase.value === repeat.value);
    else if (mode === "import") primary.disabled = !passphrase.value;
    else primary.disabled = true;
  };
  const open = (options = {}) => {
    const from = options.opener || (modal.isOpen() ? opener : document.activeElement);
    close({ restoreFocus: false });
    if (options.mode !== "download" && options.mode !== "import") return Promise.resolve(null);
    opener = from;
    mode = options.mode;
    repeat.hidden = mode !== "download";
    repeatLabel.hidden = mode !== "download";
    cancel.textContent = t("Cancel");
    if (mode === "download") {
      title.textContent = t("Download an encrypted nonce history?");
      message.textContent = t("This file links your signatures to your key's fingerprint. Keep it offline, and use a long, unique passphrase (at least 4–5 random words): the file is only as strong as the passphrase.");
      passphraseLabel.textContent = t("Passphrase");
      repeatLabel.textContent = t("Repeat the passphrase");
      primary.textContent = t("Encrypt and download");
    } else {
      title.textContent = t("Open an encrypted nonce history");
      message.textContent = "";
      passphraseLabel.textContent = t("Passphrase");
      repeatLabel.textContent = "";
      primary.textContent = t("Open");
    }
    passphrase.value = "";
    repeat.value = "";
    updatePrimary();
    const decision = new Promise((resolve) => { pending = resolve; });
    modal.show(cancel, opener);
    return decision;
  };
  passphrase.addEventListener("input", updatePrimary);
  repeat.addEventListener("input", updatePrimary);
  primary.addEventListener("click", () => {
    if (!modal.isOpen() || primary.disabled) return;
    if (mode === "download") {
      if (!passphrase.value || passphrase.value !== repeat.value) return;
      settle(passphrase.value);
    } else if (mode === "import") {
      if (!passphrase.value) return;
      settle(passphrase.value);
    }
  });
  cancel.addEventListener("click", () => { if (modal.isOpen()) close(); });
  return { open, close, isOpen: () => modal.isOpen() };
};
