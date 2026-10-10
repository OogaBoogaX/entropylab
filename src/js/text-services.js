// Text services: browser features and extensions that read what a field
// holds and keep it, or send it off the machine. The CSP's connect-src
// 'none' binds only the page, so it stops none of them: the browser or the
// extension makes the request. Each honours an opt-out attribute, and this
// module stamps them, so a field added anywhere gets them without its markup
// having to remember.
//
// - Edge's text prediction sends what is typed to a Microsoft service.
//   writingsuggestions="false" turns it off and is inherited, so it is set
//   once, on the root.
// - Grammarly sends field text to its servers whatever spellcheck says. It
//   honours data-gramm, data-gramm_editor and data-enable-grammarly.
// - Password managers offer to save a field into a vault that syncs to the
//   cloud: data-1p-ignore (1Password), data-lpignore (LastPass),
//   data-bwignore (Bitwarden) and data-form-type="other" (Dashlane) stop
//   them. A field marked data-password-manager keeps them: the Journal's file
//   password is the one field a manager has a job on.
// - Chrome writes form contents into its session-restore files on disk and
//   skips fields marked autocomplete="off". A field that names its own
//   autocomplete token keeps it.
const NON_TEXT_TYPES = new Set(["button", "checkbox", "color", "file", "hidden", "image", "radio", "range", "reset", "submit"]);
const GRAMMARLY_OPT_OUTS = [["data-gramm", "false"], ["data-gramm_editor", "false"], ["data-enable-grammarly", "false"]];
const PASSWORD_MANAGER_OPT_OUTS = [["data-1p-ignore", ""], ["data-lpignore", "true"], ["data-bwignore", ""], ["data-form-type", "other"]];

const isTextField = (element) => element.tagName === "TEXTAREA"
  || (element.tagName === "INPUT" && !NON_TEXT_TYPES.has(String(element.getAttribute("type") || "text").toLowerCase()));

export function optOutTextField(field) {
  if (!field.hasAttribute("autocomplete")) field.setAttribute("autocomplete", "off");
  for (const [name, value] of GRAMMARLY_OPT_OUTS) field.setAttribute(name, value);
  if (field.hasAttribute("data-password-manager")) return;
  for (const [name, value] of PASSWORD_MANAGER_OPT_OUTS) field.setAttribute(name, value);
}

// Every text field in `root`, and `root` itself when it is one.
export function optOutTextFields(root) {
  if (isTextField(root)) optOutTextField(root);
  for (const field of root.querySelectorAll("input, textarea")) {
    if (isTextField(field)) optOutTextField(field);
  }
}

// Stamps the fields already in the document and every one added later. The
// observer runs before the browser dispatches another event, so a new field
// is stamped before the user can reach it; a field the page focuses in the
// same task it inserts it is stamped by the focus listener, which runs ahead
// of any an extension registers later.
export function initTextServiceOptOuts(doc = document) {
  const root = doc.documentElement;
  root.setAttribute("writingsuggestions", "false");
  optOutTextFields(root);
  new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) if (node.nodeType === 1) optOutTextFields(node);
    }
  }).observe(root, { childList: true, subtree: true });
  doc.addEventListener("focusin", (event) => {
    if (event.target?.nodeType === 1 && isTextField(event.target)) optOutTextField(event.target);
  }, true);
}

// Browser translation is the one service the page can see after the fact.
// Chrome's and Edge's built-in translators send the page's text to an online
// service; translate="no" withholds what is inside it, and the page marks
// every element that shows a secret. Chrome/Google marks the root with a
// translated-ltr or translated-rtl class; Edge/Microsoft adds _msthash,
// _msttexthash or _mstmutation attributes to elements. These are best-effort
// browser markers, not a security boundary or a guaranteed future API.
// Detection is after the fact, not prevention: the warning cannot undo a
// transmission and does not prove which text was sent. It stays up. It is
// a bullet in the Important section, so showing it opens that section too:
// a warning inside a closed disclosure would go unseen. The callback records
// the detection in the security log.
const EDGE_TRANSLATION_ATTRIBUTES = ["_msthash", "_msttexthash", "_mstmutation"];
const EDGE_TRANSLATION_SELECTOR = EDGE_TRANSLATION_ATTRIBUTES.map((name) => `[${name}]`).join(", ");
const hasEdgeTranslationMarker = (node) => node.nodeType === 1
  && (node.matches(EDGE_TRANSLATION_SELECTOR) || node.querySelector(EDGE_TRANSLATION_SELECTOR));

export function initTranslationWarning(doc = document, onDetected = () => {}) {
  const warning = doc.getElementById("translated-warning");
  if (!warning) return;
  const root = doc.documentElement;
  let detected = false;
  const observer = new MutationObserver((records) => check(records.some((record) => {
    if (record.type === "attributes") {
      return EDGE_TRANSLATION_ATTRIBUTES.includes(record.attributeName) && record.target.hasAttribute(record.attributeName);
    }
    return record.type === "childList" && Array.from(record.addedNodes).some(hasEdgeTranslationMarker);
  })));
  const check = (edgeDetected) => {
    if (detected || (!edgeDetected && !/(^|\s)translated-(ltr|rtl)(\s|$)/.test(root.getAttribute("class") || ""))) return;
    detected = true;
    warning.removeAttribute("hidden");
    warning.closest("details")?.setAttribute("open", "");
    observer.disconnect();
    onDetected();
  };
  observer.observe(root, {
    attributes: true, attributeFilter: ["class", ...EDGE_TRANSLATION_ATTRIBUTES],
    childList: true, subtree: true,
  });
  check(hasEdgeTranslationMarker(root));
}
