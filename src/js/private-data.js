// Private readouts share one deliberate copy action. The shown value is the
// source of truth at click time; controls never retain the secret themselves.
import { copyText, showCopiedIcon } from "./clipboard.js";
import { t as hodlTText, tAttr as hodlTAttr } from "./i18n.js";
import { hodlEscapeAttribute } from "./i18n-sanitize.js";

export const privateCopyButtonHtml = (copyIcon, { id = "", label = "Copy", disabled = false, attribute = "data-private-copy" } = {}) =>
  `<button type="button" class="copy-button boxed-copy-button"${id ? ` id="${hodlEscapeAttribute(id)}"` : ""} ${attribute} data-copy-label="${hodlEscapeAttribute(label)}" aria-label="${hodlTAttr(label)}" title="${hodlTAttr(label)}"${disabled ? " disabled" : ""}>${copyIcon()}</button>`;

export const isReadoutShown = (node) => {
  if (!node?.isConnected || node.closest('[hidden], [aria-hidden="true"], [inert]')) return false;
  // Chrome can report layout boxes for the hidden contents of a closed
  // disclosure. Only its first summary remains visible in that state.
  for (let child = node, parent = node.parentElement; parent; child = parent, parent = parent.parentElement) {
    if (parent.tagName === "DETAILS" && !parent.hasAttribute("open")
        && child !== Array.from(parent.children).find((element) => element.tagName === "SUMMARY")) return false;
  }
  const view = node.ownerDocument.defaultView;
  return !view || (node.getClientRects().length > 0 && view.getComputedStyle(node).visibility === "visible");
};

export function initPrivateCopy({ copyIcon = () => "", copiedIcon = () => "" } = {}) {
  const onClick = async (event) => {
    const button = event.target.closest?.("button[data-private-copy]");
    if (!button || button.disabled || !isReadoutShown(button)) return;
    const field = button.closest("[data-private-field]");
    const value = field?.querySelector("[data-private-value]");
    if (!isReadoutShown(value) || value.closest("[data-private-field]") !== field || !value.textContent) return;
    if (!await copyText(value.textContent, { host: field })) return;
    if (!isReadoutShown(button) || !isReadoutShown(value)) return;
    showCopiedIcon(button, { copyIcon: copyIcon(), copiedIcon: copiedIcon(), label: hodlTText(button.dataset.copyLabel || "Copy") });
  };
  document.addEventListener("click", onClick);
  return () => document.removeEventListener("click", onClick);
}
