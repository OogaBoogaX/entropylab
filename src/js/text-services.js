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
// every element that shows a secret. Chrome then marks the root with a
// translated-ltr or translated-rtl class. By then the text has been sent, so
// the warning cannot undo anything: it says what happened and stays up.
export function initTranslationWarning(doc = document) {
  const warning = doc.getElementById("translated-warning");
  if (!warning) return;
  const root = doc.documentElement;
  const observer = new MutationObserver(() => check());
  const check = () => {
    if (!/(^|\s)translated-(ltr|rtl)(\s|$)/.test(root.getAttribute("class") || "")) return;
    warning.removeAttribute("hidden");
    observer.disconnect();
  };
  observer.observe(root, { attributes: true, attributeFilter: ["class"] });
  check();
}
