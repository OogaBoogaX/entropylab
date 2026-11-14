import { t } from "./i18n.js";
import { createModal } from "./modal.js";
import { privateCopyButtonHtml, renderAnnotatedPrivateText } from "./private-data.js";
import { snapshotPrivateSpans } from "./journal.js";
import { resetCopiedIcon } from "./clipboard.js";

export const initJournalReportViewer = ({ privacyMarkup, copyIcon = () => "" }) => {
  const modal = createModal({
    id: "journal-report-modal",
    className: "",
    card: `
      <div class="modal-card is-scrollable" id="journal-report-dialog" role="dialog" aria-modal="true" aria-labelledby="journal-report-title" aria-describedby="journal-report-description">
        <p class="modal-title" id="journal-report-title"></p>
        <p class="field-note" id="journal-report-description"></p>
        <div class="tool-section" id="journal-report-privacy"></div>
        <div class="tool-section private-field" id="journal-report-field" data-private-field>
          <p class="label copy-field-label" id="journal-report-heading"><span id="journal-report-label"></span>${privateCopyButtonHtml(copyIcon, { id: "journal-report-copy", label: "Copy report", disabled: true })}</p>
          <p class="muted" id="journal-report-concealed"></p>
          <pre class="journal-log" id="journal-report-readout" tabindex="0" aria-labelledby="journal-report-label" data-private-value data-i18n-skip translate="no" hidden></pre>
        </div>
        <div class="row modal-actions"><span class="modal-actions-end"><button class="btn secondary" id="journal-report-close" type="button"></button></span></div>
      </div>`,
    focusables: () => [reveal, copy, readout, close].filter((control) => control && !control.hidden && !control.disabled),
    onDismiss: () => clear(),
  });
  const find = (name) => modal.overlay.querySelector(`#journal-report-${name}`);
  const copy = find("copy"), close = find("close"), readout = find("readout"), privacy = find("privacy");
  let content = null, reportKind = "", reveal = null;
  find("description").textContent = t("This is a read-only report. Its contents may include private material. Opening it does not restore tools or add anything to this Journal.");
  find("label").textContent = t("Private report");
  find("concealed").textContent = t("Private report hidden");
  close.textContent = t("Close");
  const render = (shown) => {
    shown = Boolean(shown && content !== null && modal.isOpen());
    const refocus = reveal && document.activeElement === reveal;
    privacy.innerHTML = privacyMarkup({ id: "journal-report-reveal", revealed: shown, describedBy: "journal-report-description" });
    reveal = find("reveal");
    reveal.checked = shown;
    reveal.addEventListener("change", () => render(reveal.checked));
    renderAnnotatedPrivateText(readout, shown ? content : "", shown && reportKind === "session-state" ? snapshotPrivateSpans(content) : []);
    readout.hidden = !shown;
    find("concealed").hidden = shown;
    find("field").classList.toggle("is-revealed", shown);
    copy.hidden = !shown;
    copy.disabled = !shown || !content;
    if (refocus) reveal.focus();
  };
  const clear = (options) => {
    content = null;
    reportKind = "";
    modal.hide(options);
    render(false);
    find("title").textContent = "";
    resetCopiedIcon(copy, { copyIcon: copyIcon(), label: t("Copy report") });
  };
  const show = ({ kind, content: text, opener }) => {
    clear({ restoreFocus: false });
    if (!["session-state", "session-log"].includes(kind) || typeof text !== "string") return false;
    content = text;
    reportKind = kind;
    find("title").textContent = t(kind === "session-state" ? "Opened session snapshot" : "Opened debug log");
    render(false);
    modal.show(reveal, opener);
    return true;
  };
  close.addEventListener("click", () => clear());
  render(false);
  return { show, clear };
};
