// One clipboard writer for the whole app (src/js/clipboard.js).
//
// Security contract: the text handed in is written to the clipboard and kept
// nowhere else. The Clipboard API is used when the page has it; when it is
// missing or refuses, a hidden field carries the text only for the copy and is
// emptied and removed afterwards, whether the copy worked or threw. The
// promise reports whether the clipboard really took the text, so a caller
// never shows "Copied" for a copy that failed. And no other module writes the
// clipboard itself, so every copy goes through this one path.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const { copyText, resetCopiedIcon, showCopiedIcon } = await import("../src/js/clipboard.js");
const { hodlSetLocale } = await import("../src/js/i18n.js");
const ES = JSON.parse(readFileSync(join(root, "src/locales/es.json"), "utf8"));

// A page with just enough DOM for the fallback: the fields it appends, what
// execCommand saw selected, and whether each field was emptied and removed.
// Focus behaves as in a browser: select() moves it into the field, and
// removing the focused field drops it to the body.
const fakePage = ({ clipboard, execResult = true, execThrows = false } = {}) => {
  const fields = [];
  const host = { appended: [], append(field) { this.appended.push(field); field.parent = this; } };
  let selected = null;
  const document = {
    body: host,
    activeElement: null,
    createElement: (tag) => {
      const field = {
        tag, value: "", attributes: {}, style: {}, removed: false,
        setAttribute(name, value) { this.attributes[name] = value; },
        select() { selected = this.value; document.activeElement = this; },
        remove() {
          this.removed = true;
          this.valueAtRemoval = this.value;
          if (document.activeElement === this) document.activeElement = host;
        },
      };
      fields.push(field);
      return field;
    },
    execCommand: (command) => {
      assert.equal(command, "copy");
      if (execThrows) throw new Error("denied");
      return execResult;
    },
  };
  const navigator = clipboard === undefined ? {} : { clipboard };
  return { document, navigator, fields, host, selected: () => selected };
};
const run = async (page, text, options) => {
  const saved = { document: globalThis.document, navigator: globalThis.navigator };
  Object.defineProperty(globalThis, "document", { value: page.document, configurable: true, writable: true });
  Object.defineProperty(globalThis, "navigator", { value: page.navigator, configurable: true, writable: true });
  try {
    return await copyText(text, options);
  } finally {
    Object.defineProperty(globalThis, "document", { value: saved.document, configurable: true, writable: true });
    Object.defineProperty(globalThis, "navigator", { value: saved.navigator, configurable: true, writable: true });
  }
};
const PHRASE = "abandon arm moon abandon abandon abandon abandon abandon abandon abandon abandon ability";

test("the Clipboard API writes the text and nothing else is created", async () => {
  const written = [];
  const page = fakePage({ clipboard: { writeText: async (text) => { written.push(text); } } });
  assert.equal(await run(page, PHRASE), true);
  assert.deepEqual(written, [PHRASE]);
  assert.equal(page.fields.length, 0, "a fallback field was created although the API worked");
});

test("a refused Clipboard API falls back to a hidden field that is emptied and removed", async () => {
  const page = fakePage({ clipboard: { writeText: async () => { throw new Error("NotAllowedError"); } } });
  assert.equal(await run(page, PHRASE), true);
  assert.equal(page.fields.length, 1);
  const [field] = page.fields;
  assert.equal(page.selected(), PHRASE, "the fallback did not select the text it copies");
  assert.equal(field.attributes.readonly, "", "the fallback field is editable");
  assert.ok(field.removed, "the fallback field stayed in the page");
  assert.equal(field.valueAtRemoval, "", "the fallback field kept the text after the copy");
});

test("without the Clipboard API the fallback runs and reports a failed copy as failed", async () => {
  const page = fakePage({ execResult: false });
  assert.equal(await run(page, PHRASE), false, "a refused execCommand was reported as copied");
  assert.ok(page.fields[0].removed);
  assert.equal(page.fields[0].valueAtRemoval, "");
});

test("a throwing copy still empties and removes the field, and reports failure", async () => {
  const page = fakePage({ execThrows: true });
  assert.equal(await run(page, PHRASE), false);
  assert.ok(page.fields[0].removed, "the field survived a throwing copy");
  assert.equal(page.fields[0].valueAtRemoval, "", "the field kept the text after a throwing copy");
});

test("the fallback field goes where the caller asks, so a modal keeps it inside its focus trap", async () => {
  const page = fakePage();
  const overlay = { appended: [], append(field) { this.appended.push(field); } };
  assert.equal(await run(page, PHRASE, { host: overlay }), true);
  assert.equal(overlay.appended.length, 1, "the field was not placed in the given host");
  assert.equal(page.host.appended.length, 0, "the field went to the body instead of the host");
});

// The copy control the reader clicked, holding focus when the copy starts.
const focusedControl = (page) => {
  const control = {
    focusCalls: [],
    focus(options) {
      this.focusCalls.push(options);
      page.document.activeElement = this;
    },
  };
  page.document.activeElement = control;
  return control;
};

// Inside a modal, focus left on the body would sit outside the overlay's
// focus trap and Escape handler: Tab would walk the page behind the dialog
// and Escape would stop closing it. So a fallback copy hands focus back to
// the control that had it, whether the copy worked, failed or threw.
test("a fallback copy hands focus back to the control that had it", async () => {
  for (const [name, options] of [
    ["a refused Clipboard API", { clipboard: { writeText: async () => { throw new Error("NotAllowedError"); } } }],
    ["a refused execCommand", { execResult: false }],
    ["a throwing execCommand", { execThrows: true }],
  ]) {
    const page = fakePage(options);
    const control = focusedControl(page);
    await run(page, PHRASE, { host: { append() {} } });
    assert.equal(page.document.activeElement, control, `focus stayed off the copy control after ${name}`);
    assert.deepEqual(control.focusCalls, [{ preventScroll: true }], `focus came back with a scroll after ${name}`);
  }
});

test("a Clipboard API copy leaves focus alone", async () => {
  const page = fakePage({ clipboard: { writeText: async () => {} } });
  const control = focusedControl(page);
  assert.equal(await run(page, PHRASE), true);
  assert.equal(page.document.activeElement, control);
  assert.deepEqual(control.focusCalls, [], "the copy control was refocused although nothing took focus");
});

test("empty text is not copied", async () => {
  const written = [];
  const page = fakePage({ clipboard: { writeText: async (text) => { written.push(text); } } });
  assert.equal(await run(page, ""), false);
  assert.deepEqual(written, []);
  assert.equal(page.fields.length, 0);
});

test("no module but clipboard.js writes the clipboard", () => {
  const dir = join(root, "src/js");
  const offenders = [];
  for (const name of readdirSync(dir).filter((file) => file.endsWith(".js") && file !== "clipboard.js")) {
    const source = readFileSync(join(dir, name), "utf8");
    if (/clipboard\??\.writeText|execCommand\(\s*["']copy["']\s*\)/.test(source)) offenders.push(name);
  }
  assert.deepEqual(offenders, [], `clipboard writes outside clipboard.js: ${offenders.join(", ")}`);
});

// A boxed copy control, as the confirmation sees it.
const iconButton = () => {
  const attributes = {};
  return {
    innerHTML: "", title: "", isConnected: true,
    classList: { add() {}, remove() {} },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return name in attributes ? attributes[name] : null; },
  };
};

// The labels are set from script, after the boot i18n sweep has run, so they
// have to come from the translator: in a translated page the check and the
// label it returns to are both in that language.
test("the copy check and the label it returns to read in the page's language", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  hodlSetLocale("es", false);
  try {
    const button = iconButton();
    showCopiedIcon(button, { copyIcon: "<copy>", copiedIcon: "<check>" });
    assert.equal(button.getAttribute("aria-label"), ES.Copied, "the check's label is not in the page's language");
    assert.equal(button.title, ES.Copied);
    t.mock.timers.tick(1600);
    assert.equal(button.innerHTML, "<copy>");
    assert.equal(button.getAttribute("aria-label"), ES.Copy, "the label the check returns to is not in the page's language");
    assert.equal(button.title, ES.Copy);
  } finally {
    hodlSetLocale("en", false);
  }
});

// A dialog that opens again resets its copy control; the check's pending
// return must not fire afterwards and overwrite the label it was given.
test("a reset restores the icon and label and cancels the check's pending return", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const button = iconButton();
  showCopiedIcon(button, { copyIcon: "<copy>", copiedIcon: "<check>", label: "Copy URL" });
  resetCopiedIcon(button, { copyIcon: "<copy>", label: "Copy URL" });
  assert.equal(button.innerHTML, "<copy>");
  assert.equal(button.getAttribute("aria-label"), "Copy URL");
  assert.equal(button.title, "Copy URL");
  button.setAttribute("aria-label", "relabelled after the reset");
  t.mock.timers.tick(1600);
  assert.equal(button.getAttribute("aria-label"), "relabelled after the reset", "the cancelled return still fired");
});
