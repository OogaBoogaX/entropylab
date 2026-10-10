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
// the page can only see it afterwards: Chrome/Google marks the root with
// translated-ltr or translated-rtl; Edge/Microsoft adds _msthash,
// _msttexthash or _mstmutation attributes. Contract: these exact signals,
// present at boot or added later, show the warning and notify once; unrelated
// attributes, classes and DOM changes do not. The warning stays up and
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
    assert.deepEqual(observer.options, {
      attributes: true, attributeFilter: ["class", "_msthash", "_msttexthash", "_mstmutation"],
      childList: true, subtree: true,
    });
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

function translationFixture(t, beforeInit = () => {}) {
  const doc = new MiniDocument();
  const html = doc.createElement("html");
  const head = doc.createElement("head");
  html.append(head, doc.body);
  doc.documentElement = html;
  doc.body.innerHTML = '<details id="important"><p id="translated-warning" hidden></p></details><div id="content"></div>';
  const warning = doc.getElementById("translated-warning");
  const important = doc.getElementById("important");
  const content = doc.getElementById("content");
  const observers = [];
  const original = globalThis.MutationObserver;
  t.after(() => { globalThis.MutationObserver = original; });
  globalThis.MutationObserver = class {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe(target, options) { this.target = target; this.options = options; }
    disconnect() { this.disconnected = true; }
  };
  let detections = 0;
  beforeInit({ doc, html, head, content });
  initTranslationWarning(doc, () => detections++);
  assert.equal(observers.length, 1);
  const [observer] = observers;
  return {
    doc, html, content, warning, observer,
    assertDetected() {
      assert.equal(warning.hidden, false, "translation must show the warning");
      assert.ok(important.hasAttribute("open"), "translation must open Important");
      assert.equal(detections, 1, "translation must notify exactly once");
      assert.equal(observer.disconnected, true, "the detector must stop observing after detection");
    },
    assertNotDetected() {
      assert.equal(warning.hidden, true);
      assert.equal(important.hasAttribute("open"), false);
      assert.equal(detections, 0);
      assert.ok(!observer.disconnected, "the detector must keep watching");
    },
  };
}

for (const marker of ["_msthash", "_msttexthash", "_mstmutation"]) {
  for (const location of ["html", "head", "content"]) {
    test(`Edge ${marker} present at initialization on ${location} warns immediately`, (t) => {
      // Attribute presence counts, even when the value is empty.
      translationFixture(t, (page) => page[location].setAttribute(marker, "")).assertDetected();
    });
  }

  test(`Edge ${marker} added to an existing element warns`, (t) => {
    const page = translationFixture(t);
    page.assertNotDetected();
    page.content.setAttribute(marker, "123");
    page.observer.callback([{ type: "attributes", target: page.content, attributeName: marker }]);
    page.assertDetected();
  });
}

test("translation observer watches subtree additions and only relevant attributes", (t) => {
  const { html, observer } = translationFixture(t);
  assert.equal(observer.target, html);
  assert.equal(observer.options.subtree, true);
  assert.equal(observer.options.childList, true);
  assert.equal(observer.options.attributes, true);
  assert.deepEqual(new Set(observer.options.attributeFilter), new Set(["class", "_msthash", "_msttexthash", "_mstmutation"]));
});

for (const [label, markup] of [
  ["new element with _msttexthash", '<span _msttexthash="123"></span>'],
  ["inserted wrapper with a nested _msthash", '<div><section><span _msthash="123"></span></section></div>'],
]) {
  test(`Edge ${label} warns`, (t) => {
    const page = translationFixture(t);
    const holder = page.doc.createElement("div");
    holder.innerHTML = markup;
    const inserted = holder.firstChild;
    page.content.append(inserted);
    page.observer.callback([{ type: "childList", target: page.content, addedNodes: [inserted] }]);
    page.assertDetected();
  });
}

for (const [attribute, value] of [
  ["_mstfoo", "123"], ["_msthash-extra", "123"], ["data-ms-editor", "false"],
  ["writingsuggestions", "false"], ["data-1p-ignore", ""], ["data-lpignore", "true"],
  ["class", "translated-pending some-theme"],
]) {
  test(`${attribute} is not a translation signal at boot or on mutation`, (t) => {
    const page = translationFixture(t, ({ content }) => content.setAttribute(attribute, value));
    page.assertNotDetected();
    page.content.setAttribute(attribute, value);
    page.observer.callback([{ type: "attributes", target: page.content, attributeName: attribute }]);
    page.assertNotDetected();
    const wrapper = page.doc.createElement("div");
    const child = page.doc.createElement("span");
    child.setAttribute(attribute, value);
    wrapper.append(child);
    page.content.append(wrapper);
    page.observer.callback([{ type: "childList", target: page.content, addedNodes: [wrapper] }]);
    page.assertNotDetected();
  });
}

test("ordinary subtree and text insertion do not warn; Chrome classes only count on the root", (t) => {
  const page = translationFixture(t);
  const wrapper = page.doc.createElement("div");
  wrapper.innerHTML = '<span class="translated-ltr">ordinary text</span>';
  const text = page.doc.createTextNode("more text");
  page.content.append(wrapper, text);
  page.observer.callback([{ type: "childList", target: page.content, addedNodes: [wrapper, text] }]);
  page.assertNotDetected();
  wrapper.setAttribute("class", "translated-rtl");
  page.observer.callback([{ type: "attributes", target: wrapper, attributeName: "class" }]);
  page.assertNotDetected();
});

test("multiple Edge and Chrome signals notify once and stay latched after markers disappear", (t) => {
  const page = translationFixture(t);
  const markers = ["_msthash", "_msttexthash", "_mstmutation"];
  const records = markers.map((attributeName) => {
    page.content.setAttribute(attributeName, "123");
    return { type: "attributes", target: page.content, attributeName };
  });
  page.observer.callback(records);
  page.assertDetected();
  page.html.setAttribute("class", "translated-ltr translated-rtl");
  // Explicitly exercise the one-shot guard even if a callback is repeated.
  page.observer.callback([...records, { type: "attributes", target: page.html, attributeName: "class" }]);
  page.assertDetected();
  for (const marker of markers) page.content.removeAttribute(marker);
  page.html.removeAttribute("class");
  page.observer.callback(records);
  page.assertDetected();
});
