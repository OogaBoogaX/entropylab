import { t } from "./i18n.js";
import { createModal } from "./modal.js";

export const initJournalPageDeleteConfirm = () => {
  const modal = createModal({
    id: "journal-page-delete-modal",
    className: "",
    card: `
      <div class="modal-card is-warning" id="journal-page-delete-dialog" role="dialog" aria-modal="true" aria-labelledby="journal-page-delete-title" aria-describedby="journal-page-delete-message">
        <p class="modal-warning-title" id="journal-page-delete-title"></p>
        <p id="journal-page-delete-message"></p>
        <div class="row tool-actions">
          <button class="btn red" id="journal-page-delete-confirm" type="button"></button>
          <button class="btn secondary" id="journal-page-delete-cancel" type="button"></button>
        </div>
      </div>`,
    focusables: () => [confirm, cancel],
    onDismiss: () => hide(),
  });
  const find = (id) => modal.overlay.querySelector(`#journal-page-delete-${id}`);
  const confirm = find("confirm"), cancel = find("cancel");
  cancel.textContent = t("Cancel");
  let pending = null;
  const hide = (options) => {
    pending = null;
    modal.hide(options);
  };
  const show = ({ opener, onConfirm, title, message, confirmLabel }) => {
    if (modal.isOpen()) return;
    pending = onConfirm;
    find("title").textContent = title ?? t("Delete this note page?");
    find("message").textContent = message ?? t("This removes the page and its contents from this Journal. Downloaded backups are unchanged.");
    confirm.textContent = confirmLabel ?? t("Delete page");
    modal.show(cancel, opener);
  };
  cancel.addEventListener("click", () => hide());
  confirm.addEventListener("click", () => {
    if (!modal.isOpen() || !pending) return;
    const action = pending;
    hide();
    action();
  });
  return { show, hide };
};
