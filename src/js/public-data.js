// Public readouts share their payload between direct value clicks and the
// label clipboard. A QR action takes the label clipboard's place.
import { privateCopyButtonHtml } from "./private-data.js";
import { hodlEscapeAttribute, hodlEscapeHtmlText } from "./i18n-sanitize.js";
import { tAttr } from "./i18n.js";

const hasValue = (value) => value != null && String(value) !== "" && String(value) !== "—";
const publicControl = (value, copyIcon, qrHtml = "") => hasValue(value)
  ? qrHtml || privateCopyButtonHtml(copyIcon, { attribute: "data-public-copy" })
  : "";
const publicReadout = (value, { preview = value, id = "", className = "mono" } = {}) => {
  const content = hodlEscapeAttribute(preview ?? "—");
  const attrs = `${id ? ` id="${hodlEscapeAttribute(id)}"` : ""} class="${hodlEscapeAttribute(className)}" data-i18n-skip translate="no"`;
  if (!hasValue(value)) return `<span${attrs}>${content}</span>`;
  return `<button type="button"${attrs} data-public-value data-copy-field${String(preview) !== String(value) ? ` data-copy-value="${hodlEscapeAttribute(value)}"` : ""} title="${String(preview) !== String(value) ? hodlEscapeAttribute(value) : tAttr("Copy")}">${content}</button>`;
};

// labelHtml / qrHtml / afterLabel are trusted markup supplied by the caller.
export const publicFieldHtml = (labelHtml, value, { copyIcon = () => "", qrHtml = "", labelClass = "label", id = "", afterLabel = "" } = {}) =>
  `<div data-copy-group><p class="${hodlEscapeAttribute(labelClass)} copy-field-label">${labelHtml}${publicControl(value, copyIcon, qrHtml)}${qrHtml && hasValue(value) ? '<span data-copy-status class="copy-status copy-field-status" aria-live="polite"></span>' : ""}</p>${afterLabel}${publicReadout(value, { id, className: "mono copy-field-value" })}</div>`;

export const publicValueHtml = (value, { label = "", copyIcon = () => "", preview = value, id = "", className = "mono", clipboard = true } = {}) =>
  `<span data-copy-group data-public-inline>${label || clipboard ? `<span class="copy-field-label">${hodlEscapeHtmlText(label)}${clipboard ? publicControl(value, copyIcon) : ""}</span>` : ""}${publicReadout(value, { preview, id, className: `addr-text ${className}` })}${!clipboard && hasValue(value) ? '<span data-copy-status class="copy-status copy-field-status" aria-live="polite"></span>' : ""}</span>`;
