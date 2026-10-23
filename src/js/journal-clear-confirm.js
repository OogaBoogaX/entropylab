import { t } from "./i18n.js";
import { createModal } from "./modal.js";

// Downloading starts a browser operation; it cannot prove that the file was
// saved. Only a separate, explicit confirmation clears the selected scope.
export const initJournalClearConfirm = ({ onDownload, onDiscard }) => {
  const modal = createModal({
    id: "journal-clear-modal",
    className: "",
    card: `
      <div class="modal-card is-warning" id="journal-clear-dialog" role="dialog" aria-modal="true" aria-labelledby="journal-clear-title" aria-describedby="journal-clear-message">
        <p class="modal-warning-title" id="journal-clear-title"></p>
        <p id="journal-clear-message"></p>
        <p class="edge-note is-info" id="journal-clear-status" role="status" aria-live="polite"></p>
        <div class="row tool-actions">
          <button class="btn primary" id="journal-clear-download" type="button"></button>
          <button class="btn red" id="journal-clear-discard" type="button"></button>
          <button class="btn secondary" id="journal-clear-cancel" type="button"></button>
        </div>
      </div>`,
    focusables: () => [download, discard, cancel].filter((button) => !button.disabled),
    onDismiss: () => hide(),
  });
  const find = (id) => modal.overlay.querySelector(`#journal-clear-${id}`);
  const download = find("download"), discard = find("discard"), cancel = find("cancel"), status = find("status");
  cancel.textContent = t("Cancel");
  let request = 0, busy = false, pending = null;
  const setBusy = (value) => {
    busy = value;
    download.disabled = value;
    discard.disabled = value;
  };
  const hide = (options) => {
    request++;
    pending = null;
    setBusy(false);
    status.textContent = "";
    modal.hide(options);
  };
  const show = (opener, options = {}) => {
    if (modal.isOpen()) return;
    request++;
    pending = {
      onDownload, onDiscard, isCurrent: () => true,
      preparingMessage: t("Preparing your backup…"),
      successMessage: t("Backup download started. Check that the file was saved before choosing Discard. Your Journal is still open."),
      errorMessage: t("The backup was not downloaded. Your Journal is still open. Choose Cancel to resolve the error and try again."),
      ...options,
    };
    find("title").textContent = options.title ?? t("Clear journal?");
    find("message").textContent = options.message ?? t("Discard removes Journal notes, saved records, detached and archived key inputs, snapshots, and activity. Anything you have not backed up will be lost. Keys still open in Key Station remain there; use End Session to clear the whole page.");
    download.textContent = options.downloadLabel ?? t("Download backup first");
    discard.textContent = options.discardLabel ?? t("Discard");
    status.textContent = "";
    setBusy(false);
    modal.show(cancel, opener);
  };
  cancel.addEventListener("click", () => hide());
  discard.addEventListener("click", () => {
    if (!modal.isOpen() || busy) return;
    const action = pending?.isCurrent() ? pending.onDiscard : null;
    hide();
    action?.();
  });
  download.addEventListener("click", async () => {
    if (!modal.isOpen() || busy) return;
    if (!pending?.isCurrent()) { hide(); return; }
    const scope = pending;
    const current = ++request;
    const isCurrent = () => current === request && modal.isOpen() && scope.isCurrent();
    setBusy(true);
    cancel.focus();
    status.textContent = scope.preparingMessage;
    let saved = false;
    try {
      saved = await scope.onDownload(isCurrent);
    } catch {}
    if (!isCurrent()) {
      if (current === request && modal.isOpen()) hide();
      return;
    }
    setBusy(false);
    status.textContent = saved ? scope.successMessage : scope.errorMessage;
  });
  return { show, hide };
};
