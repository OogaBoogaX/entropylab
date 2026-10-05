// Third-party text services must not receive what a field holds. Grammarly
// sends field text to its servers whatever spellcheck says, a password
// manager offers to save a field into a cloud-synced vault, Edge's text
// prediction sends typing to a Microsoft service, and Chrome writes form
// contents into its session-restore files on disk unless a field says
// autocomplete="off". The CSP cannot stop any of them, because the browser
// or the extension sends the text, not the page (CONTRIBUTING §3).
//
// Contract: every text field gets the Grammarly and password-manager
// opt-outs and autocomplete="off"; a field that names its own autocomplete
// token keeps it; only the Journal's file-password fields may keep the
// password managers; controls that hold no text get nothing.
//
// Expected values are the vendors' documented opt-outs: Grammarly's
// data-gramm, data-gramm_editor and data-enable-grammarly set to "false";
// 1Password's data-1p-ignore, LastPass's data-lpignore="true", Bitwarden's
// data-bwignore and Dashlane's data-form-type="other"; and the HTML
// standard's writingsuggestions="false", inherited from the root.
//
// Browser translation sends the page's text to an online service too, and
// the page can only see it afterwards: Chrome marks a translated page with a
// translated-ltr or translated-rtl class on the root. Contract: either class
// shows the warning, any other class does not, and it stays up. The warning
// is a bullet in the Important section, so showing it also opens that
// section: a warning inside a closed disclosure is not seen.
// The live page, with its observers, is covered in the browser suite.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MiniDocument, MiniElement } from "./mini-dom.mjs";
import { initTextServiceOptOuts, initTranslationWarning, optOutTextFields } from "../src/js/text-services.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

const GRAMMARLY = { "data-gramm": "false", "data-gramm_editor": "false", "data-enable-grammarly": "false" };
const PASSWORD_MANAGERS = { "data-1p-ignore": "", "data-lpignore": "true", "data-bwignore": "", "data-form-type": "other" };
const JOURNAL_PASSWORDS = ["journal-create-password", "journal-create-confirm", "journal-open-password"];
const NON_TEXT = new Set(["button", "checkbox", "color", "file", "hidden", "image", "radio", "range", "reset", "submit"]);

const isText = (field) => field.tagName === "TEXTAREA" || !NON_TEXT.has(field.getAttribute("type") ?? "text");
const assertAttrs = (field, expected, label) => {
  for (const [name, value] of Object.entries(expected)) {
    assert.equal(field.getAttribute(name), value, `${label} must set ${name}="${value}"`);
  }
};
const stampedShell = () => {
  const doc = new MiniDocument();
  doc.body.innerHTML = shell;
  const before = new Map(doc.body.querySelectorAll("input, textarea").map((field) => [field, field.getAttribute("autocomplete")]));
  optOutTextFields(doc.body);
  return { doc, before };
};

test("every text field in the shell opts out of Grammarly and of form restore", () => {
  const { doc, before } = stampedShell();
  const fields = doc.body.querySelectorAll("input, textarea").filter(isText);
  assert.ok(fields.length > 40, `found only ${fields.length} text fields; the shell parse is broken`);
  for (const field of fields) {
    const label = `#${field.id || field.tagName}`;
    assertAttrs(field, GRAMMARLY, label);
    assert.equal(field.getAttribute("autocomplete"), before.get(field) ?? "off", `${label} must keep its own autocomplete token or get "off"`);
  }
});

test("the fields that lacked autocomplete now have it off", () => {
  // These had no autocomplete attribute, so Chrome's session restore saved
  // what they held; journal-entry-notes can hold a secret.
  const { doc } = stampedShell();
  for (const id of ["purpose", "network", "account", "branch-start", "address-start", "msig-account", "sp-verify-labels", "journal-entry-notes"]) {
    assert.equal(doc.getElementById(id).getAttribute("autocomplete"), "off", `#${id}`);
  }
});

test("only the Journal's file-password fields keep the password managers", () => {
  const { doc } = stampedShell();
  const kept = doc.body.querySelectorAll("[data-password-manager]").map((field) => field.id).sort();
  assert.deepEqual(kept, [...JOURNAL_PASSWORDS].sort(), "a new password-manager exemption needs review");
  for (const field of doc.body.querySelectorAll("input, textarea").filter(isText)) {
    const label = `#${field.id || field.tagName}`;
    if (JOURNAL_PASSWORDS.includes(field.id)) {
      for (const name of Object.keys(PASSWORD_MANAGERS)) assert.equal(field.hasAttribute(name), false, `${label} must not set ${name}`);
    } else {
      assertAttrs(field, PASSWORD_MANAGERS, label);
    }
  }
  // The BIP39 and aezeed passphrases are what a vault must never hold.
  for (const id of ["pass", "sp-pass", "psbt-pass", "nonce-pass", "ln-pass"]) assertAttrs(doc.getElementById(id), PASSWORD_MANAGERS, `#${id}`);
  // The Journal's own tokens survive: they are what invites the manager.
  assert.equal(doc.getElementById("journal-create-password").getAttribute("autocomplete"), "new-password");
});

test("controls that hold no text are left alone", () => {
  const { doc } = stampedShell();
  const controls = doc.body.querySelectorAll("input").filter((field) => !isText(field));
  assert.ok(controls.some((field) => field.getAttribute("type") === "checkbox") && controls.some((field) => field.getAttribute("type") === "file"));
  for (const field of controls) {
    for (const name of [...Object.keys(GRAMMARLY), ...Object.keys(PASSWORD_MANAGERS)]) {
      assert.equal(field.hasAttribute(name), false, `#${field.id} (${field.getAttribute("type")}) must not get ${name}`);
    }
  }
});

test("the page root turns off writing suggestions and every field added later is stamped", () => {
  const doc = new MiniDocument();
  const html = new MiniElement("html", doc);
  html.append(doc.body);
  doc.documentElement = html;
  const observers = [], focusListeners = [];
  doc.addEventListener = (type, listener, capture) => { if (type === "focusin") focusListeners.push({ listener, capture }); };
  const original = globalThis.MutationObserver;
  globalThis.MutationObserver = class {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe(target, options) { this.target = target; this.options = options; }
  };
  const all = { ...GRAMMARLY, ...PASSWORD_MANAGERS, autocomplete: "off" };
  try {
    doc.body.innerHTML = '<textarea id="early"></textarea>';
    initTextServiceOptOuts(doc);
  } finally {
    globalThis.MutationObserver = original;
  }
  assert.equal(html.getAttribute("writingsuggestions"), "false");
  assertAttrs(doc.getElementById("early"), all, "a field present at boot");

  assert.equal(observers.length, 1);
  const [observer] = observers;
  assert.equal(observer.target, html, "the observer must watch the whole document, overlays included");
  assert.equal(observer.options.childList && observer.options.subtree, true);
  const added = doc.createElement("div");
  added.innerHTML = '<input id="later"><input id="later-box" type="checkbox">';
  doc.body.append(added);
  observer.callback([{ addedNodes: [added] }]);
  assertAttrs(doc.getElementById("later"), all, "a field added later");
  assert.equal(doc.getElementById("later-box").hasAttribute("data-gramm"), false);

  // A field the page inserts and focuses in one task is stamped on focus.
  assert.equal(focusListeners.length, 1);
  assert.equal(focusListeners[0].capture, true, "the focus listener must capture, to run before the field's own");
  const focused = doc.createElement("textarea");
  focusListeners[0].listener({ target: focused });
  assertAttrs(focused, all, "a field stamped on focus");
});

test("a machine-translated page shows the translation warning and keeps it up", () => {
  const observers = [];
  const original = globalThis.MutationObserver;
  globalThis.MutationObserver = class {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe(target, options) { this.target = target; this.options = options; }
    disconnect() { this.disconnected = true; }
  };
  const page = (rootClass) => {
    const doc = new MiniDocument();
    const html = new MiniElement("html", doc);
    html.append(doc.body);
    doc.documentElement = html;
    doc.body.innerHTML = shell;
    if (rootClass) html.setAttribute("class", rootClass);
    return { doc, html, warning: doc.getElementById("translated-warning") };
  };
  try {
    const { doc, html, warning } = page("");
    let detections = 0;
    assert.ok(warning?.hidden, "the warning must start hidden");
    const important = doc.getElementById("important");
    assert.ok(important && warning.closest("#important") === important, "the warning must sit in the Important section");
    important.removeAttribute("open");
    initTranslationWarning(warning.ownerDocument, () => detections++);
    const observer = observers.at(-1);
    assert.equal(observer.target, html);
    assert.deepEqual(observer.options, { attributes: true, attributeFilter: ["class"] });
    html.setAttribute("class", "translated-pending some-theme");
    observer.callback([]);
    assert.ok(warning.hidden, "a class other than Chrome's marker must not show the warning");
    assert.equal(detections, 0);
    html.setAttribute("class", "some-theme translated-ltr");
    observer.callback([]);
    assert.equal(warning.hidden, false, "translated-ltr must show the warning");
    assert.ok(important.hasAttribute("open"), "showing the warning must open the Important section");
    assert.equal(detections, 1, "the security log must be notified of translation");
    assert.ok(observer.disconnected);
    html.setAttribute("class", "");
    assert.equal(warning.hidden, false, "showing the original again must not hide it: the text was already sent");

    // A page already translated when the app boots warns at once.
    const late = page("translated-rtl");
    initTranslationWarning(late.warning.ownerDocument, () => detections++);
    assert.equal(late.warning.hidden, false, "translated-rtl must show the warning");
    assert.equal(detections, 2, "translation already present at boot must be logged too");
  } finally {
    globalThis.MutationObserver = original;
  }
});
