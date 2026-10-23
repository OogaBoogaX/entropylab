import { t } from "./i18n.js";
import { createModal } from "./modal.js";

// These decisions authorize only the current request. Replacement and every
// dismissal cancel it; labels and public setup details are discarded on close.
export const initJournalKeyImportConfirm = () => {
  const modal = createModal({
    id: "journal-key-import-modal",
    className: "",
    card: `
      <div class="modal-card end-session-card" id="journal-key-import-dialog" role="dialog" aria-modal="true" aria-labelledby="journal-key-import-title" aria-describedby="journal-key-import-message">
        <h2 class="modal-title" id="journal-key-import-title"></h2>
        <div class="end-session-text" id="journal-key-import-body">
          <p id="journal-key-import-message"></p>
          <p id="journal-key-import-summary"></p>
          <ul id="journal-key-import-names" data-i18n-skip translate="no"></ul>
          <p id="journal-key-import-name" data-i18n-skip translate="no"></p>
          <table id="journal-key-import-details" hidden>
            <thead><tr><th id="journal-key-import-setting-label" scope="col"></th><th id="journal-key-import-existing-label" scope="col"></th><th id="journal-key-import-imported-label" scope="col"></th></tr></thead>
            <tbody>
              <tr><th id="journal-key-import-name-label" scope="row"></th><td id="journal-key-import-existing-name" data-i18n-skip translate="no"></td><td id="journal-key-import-imported-name" data-i18n-skip translate="no"></td></tr>
              <tr><th id="journal-key-import-network-label" scope="row"></th><td id="journal-key-import-existing-network" data-i18n-skip translate="no"></td><td id="journal-key-import-imported-network" data-i18n-skip translate="no"></td></tr>
              <tr><th id="journal-key-import-path-label" scope="row"></th><td class="key-summary-path" id="journal-key-import-existing-path" data-i18n-skip translate="no"></td><td class="key-summary-path" id="journal-key-import-imported-path" data-i18n-skip translate="no"></td></tr>
              <tr><th id="journal-key-import-script-label" scope="row"></th><td id="journal-key-import-existing-script" data-i18n-skip translate="no"></td><td id="journal-key-import-imported-script" data-i18n-skip translate="no"></td></tr>
              <tr id="journal-key-import-encoding-row" hidden><th id="journal-key-import-encoding-label" scope="row"></th><td id="journal-key-import-existing-encoding" data-i18n-skip translate="no"></td><td id="journal-key-import-imported-encoding" data-i18n-skip translate="no"></td></tr>
              <tr><th id="journal-key-import-recovery-label" scope="row"></th><td id="journal-key-import-existing-recovery" data-i18n-skip translate="no"></td><td id="journal-key-import-imported-recovery" data-i18n-skip translate="no"></td></tr>
            </tbody>
          </table>
        </div>
        <div class="row tool-actions">
          <button class="btn primary" id="journal-key-import-primary" type="button"></button>
          <button class="btn secondary" id="journal-key-import-secondary" type="button" hidden></button>
          <button class="btn secondary" id="journal-key-import-cancel" type="button"></button>
        </div>
      </div>`,
    focusables: () => [primary, secondary, cancel].filter((button) => !button.hidden && !button.disabled),
    onDismiss: () => close(),
  });
  const find = (id) => modal.overlay.querySelector(`#journal-key-import-${id}`);
  const primary = find("primary"), secondary = find("secondary"), cancel = find("cancel");
  const title = find("title"), message = find("message"), summary = find("summary"), names = find("names"), name = find("name"), details = find("details");
  const values = ["existing-name", "imported-name", "existing-network", "imported-network", "existing-path", "imported-path", "existing-script", "imported-script", "existing-recovery", "imported-recovery", "existing-encoding", "imported-encoding"].map(find);
  let pending = null, primaryChoice = null, secondaryChoice = null, opener = null;

  const settle = (choice, options) => {
    const resolve = pending;
    pending = null;
    primaryChoice = secondaryChoice = null;
    for (const field of [title, message, summary, names, name, primary, secondary, cancel, ...values]) field.textContent = "";
    modal.hide(options);
    opener = null;
    resolve?.(choice);
  };
  const close = (options) => settle(null, options);
  const open = (options = {}) => {
    const from = options.opener || (modal.isOpen() ? opener : document.activeElement);
    close({ restoreFocus: false });
    if (!["preview", "conflict", "draft"].includes(options.mode)) return Promise.resolve(null);
    opener = from;
    const preview = options.mode === "preview", conflict = options.mode === "conflict";
    summary.hidden = names.hidden = !preview;
    name.hidden = options.mode !== "draft";
    details.hidden = !conflict;
    find("encoding-row").hidden = !conflict || !(options.existingEncoding || options.importedEncoding);
    secondary.hidden = !conflict;
    cancel.textContent = t(conflict ? "Stop deriving" : "Cancel");
    if (preview) {
      title.textContent = t("Import key inputs");
      const derive = options.names.length > 0;
      names.hidden = !derive;
      message.textContent = t(derive ? "Derive the imported inputs and add the resulting keys to Key Station. Existing keys stay available. Archived inputs stay archived." : "Import the archived inputs into Journal. They stay archived until you restore them.");
      summary.textContent = derive ? t("{n} input set(s) to derive. {archived} archived input set(s).", { n: options.names.length, archived: options.archivedCount }) : t("{archived} archived input set(s).", { archived: options.archivedCount });
      for (const label of options.names) {
        const item = document.createElement("li");
        item.textContent = String(label);
        names.append(item);
      }
      primary.textContent = t(derive ? "Import and derive" : "Import archived inputs");
      primaryChoice = derive ? "derive" : "import";
    } else if (conflict) {
      title.textContent = t("Choose a key setup");
      message.textContent = t("Fresh derivation found the same wallet with different settings. Keep existing leaves these inputs available for later. Add separate setup adds another Key Station tab. The existing setup stays unchanged. Stop deriving keeps these inputs and any keys already added.");
      for (const [id, label] of [["setting-label", t("Setting")], ["existing-label", t("Existing setup")], ["imported-label", t("Imported setup")], ["name-label", t("Name")], ["network-label", t("Network")], ["path-label", t("Derivation path")], ["script-label", t("Script type")], ["recovery-label", t("Recovery material")], ["encoding-label", t("Public-key encoding")]]) find(id).textContent = label;
      [options.existingName, options.name, options.existingNetwork, options.importedNetwork, options.existingPath, options.importedPath, options.existingScript, options.importedScript, options.existingRecovery, options.importedRecovery, options.existingEncoding, options.importedEncoding].forEach((value, index) => { values[index].textContent = String(value ?? ""); });
      primary.textContent = t("Keep existing");
      secondary.textContent = t("Add separate setup");
      primaryChoice = "keep";
      secondaryChoice = "append";
    } else {
      title.textContent = t("Replace unfinished key inputs?");
      message.textContent = t("Loading these inputs replaces the unfinished inputs currently in Key Station. Your imported inputs remain in Journal.");
      name.textContent = String(options.name ?? "");
      primary.textContent = t("Load inputs");
      primaryChoice = "load";
    }
    const decision = new Promise((resolve) => { pending = resolve; });
    modal.show(cancel, opener);
    return decision;
  };
  primary.addEventListener("click", () => { if (modal.isOpen() && primaryChoice) settle(primaryChoice); });
  secondary.addEventListener("click", () => { if (modal.isOpen() && !secondary.hidden && secondaryChoice) settle(secondaryChoice); });
  cancel.addEventListener("click", () => close());
  return { open, close };
};
