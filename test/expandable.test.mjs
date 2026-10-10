// Tests for the pure half of src/js/expandable.js — the standard truncation
// rule and the cell markup. initExpandable is DOM-bound and covered by the
// Firefox browser suite (test/browser-suite.html); reopening it after a copy
// is checked here through a minimal fake page.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { truncateText, expandSizeLabel, expandableHtml, initExpandable, EXPAND_LIMIT } from "../src/js/expandable.js";
import { hodlSetLocale, t as translate } from "../src/js/i18n.js";
import { MiniDocument, MiniNodeFilter } from "./mini-dom.mjs";

test("at or under the limit the text passes through untouched", () => {
  assert.deepEqual(truncateText(""), { truncated: false, preview: "" });
  assert.deepEqual(truncateText("ab".repeat(EXPAND_LIMIT / 2)), { truncated: false, preview: "ab".repeat(EXPAND_LIMIT / 2) });
});

test("over the limit the preview is head, ellipsis, tail", () => {
  const text = "a".repeat(EXPAND_LIMIT + 1);
  const { truncated, preview } = truncateText(text);
  assert.equal(truncated, true);
  assert.equal(preview, `${"a".repeat(32)}…${"a".repeat(16)}`);
  const hex = `0123456789abcdef`.repeat(8); // 128 chars
  const cut = truncateText(hex);
  assert.equal(cut.preview, `${hex.slice(0, 32)}…${hex.slice(-16)}`);
  assert.ok(cut.preview.length < hex.length);
});

test("the size label counts bytes for even hex and characters otherwise", () => {
  assert.equal(expandSizeLabel("ab".repeat(150)), "300 hex chars (150 bytes)");
  assert.equal(expandSizeLabel("ab".repeat(75)), "150 hex chars (75 bytes)");
  assert.equal(expandSizeLabel("OP_DUP OP_HASH160 …"), "19 characters");
  assert.equal(expandSizeLabel(""), "0 characters");
  assert.equal(expandSizeLabel("abc"), "3 characters"); // odd-length hex is not byte-counted
});

test("short values are protected readouts and hostile text stays inert", () => {
  assert.match(expandableHtml("00ff"), /data-private-value/);
  const html = expandableHtml('<script>"x"</script>');
  assert.ok(html.includes("&lt;script&gt;&quot;x&quot;&lt;/script&gt;"));
  assert.ok(!html.includes("<script>"));
});

test("long text renders a truncated cell carrying the full value", () => {
  const value = "cd".repeat(150); // 300 hex chars
  const html = expandableHtml(value, { label: "Value bytes for PSBT_IN_WITNESS_UTXO (hex)" });
  assert.match(html, /data-private-value/);
  assert.ok(html.includes(`data-exp="${value}"`), "full value missing from the cell");
  assert.ok(html.includes(`data-exp-label="Value bytes for PSBT_IN_WITNESS_UTXO (hex)"`));
  assert.ok(html.includes(`${"cd".repeat(16)}…${"cd".repeat(8)}`), "preview is not head…tail");
  assert.ok(html.includes("300 hex chars (150 bytes)"), "size label missing");
  assert.ok(!html.includes("data-exp-edit"), "cell without edit attributes must not be editable");
});

test("edit attributes mark the cell editable and pass through", () => {
  const html = expandableHtml("ef".repeat(100), { label: "Value (hex)", editAttrs: `data-kind="input" data-map="2" data-pair="3"` });
  assert.ok(html.includes("data-exp-edit"), "editable marker missing");
  assert.ok(html.includes(`data-kind="input" data-map="2" data-pair="3"`));
});

test("markup from a hostile value stays inert", () => {
  const hostile = `"><img src=x onerror=alert(1)>${"aa".repeat(100)}`;
  const html = expandableHtml(hostile, { label: 'key "quoted"' });
  assert.ok(!html.includes("<img"), "unescaped markup in cell");
  assert.ok(html.includes("&lt;img"), "value was not escaped");
  assert.ok(html.includes("key &quot;quoted&quot;"), "label was not escaped");
});

test("private readout values remain exact when the page language changes", () => {
  const saved = { document: globalThis.document, NodeFilter: globalThis.NodeFilter };
  const document = new MiniDocument(), values = ["account", "coin", "online"];
  globalThis.document = document;
  globalThis.NodeFilter = MiniNodeFilter;
  try {
    document.body.innerHTML = `<p id="label">Close</p>${values.map((value) => expandableHtml(value)).join("")}`;
    for (const locale of ["es", "pt", "fr", "de"]) {
      hodlSetLocale(locale, false);
      assert.deepEqual(document.querySelectorAll("[data-private-value]").map((node) => node.textContent), values);
      assert.equal(document.getElementById("label").textContent, translate("Close"));
    }
  } finally {
    hodlSetLocale("en", false);
    if (saved.document === undefined) delete globalThis.document;
    else globalThis.document = saved.document;
    if (saved.NodeFilter === undefined) delete globalThis.NodeFilter;
    else globalThis.NodeFilter = saved.NodeFilter;
  }
});

// The overlay is a body-level sibling that outlives the editor views whose
// cells opened it, and a pasted PSBT can carry xprvs in proprietary fields:
// once the dialog goes out of scope it must not keep the full value.
// (Behavioral checks live in test/browser-suite.html; these pin the wiring.)
test("closing the overlay releases the full value, the title and the size meta", () => {
  const module = readFileSync(new URL("../src/js/expandable.js", import.meta.url), "utf8");
  const release = module.slice(module.indexOf("const release = () => {"), module.indexOf("const close = () => {"));
  assert.match(release, /text\.value = ""/, "release must clear #exp-text");
  assert.match(release, /querySelector\("#exp-title"\)\.textContent = ""/, "release must clear #exp-title");
  assert.match(release, /querySelector\("#exp-meta"\)\.textContent = ""/, "release must clear #exp-meta");
  const close = module.slice(module.indexOf("const close = () => {"), module.indexOf("const open = (target) => {"));
  assert.match(close, /release\(\)/, "close() must release the overlay contents");
});

test("pagehide and persisted pageshow release the overlay contents", () => {
  const module = readFileSync(new URL("../src/js/expandable.js", import.meta.url), "utf8");
  assert.match(module, /addEventListener\("pagehide"/, "the overlay must release on pagehide");
  assert.match(module, /event\.persisted/, "a bfcache restore must release too");
  const teardown = module.slice(module.indexOf("const teardown = () => {") >= 0 ? module.indexOf("const teardown = () => {") : Infinity, module.indexOf("const open = (target) => {"));
  assert.match(teardown, /release\(\)/, "the teardown must run the same release as close()");
});

// A minimal fake page drives the real dialog: every element it asks for by id
// is a stub, a click lands on an expandable cell, and the clipboard takes the
// text.
const fakeElement = (props = {}) => {
  const listeners = {}, attributes = {};
  return {
    hidden: false, innerHTML: "", textContent: "", title: "", value: "", dataset: {}, isConnected: true,
    classList: { add() {}, remove() {}, contains: () => false },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return name in attributes ? attributes[name] : null; },
    addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
    fire(type, event = {}) { for (const fn of listeners[type] ?? []) fn(event); },
    focus() {},
    ...props,
  };
};
const withExpandDialog = async (run) => {
  const parts = {}, documentListeners = {}, windowListeners = {}, clipboard = [];
  const overlay = fakeElement({ querySelector: (selector) => (parts[selector] ??= fakeElement()), querySelectorAll: () => [] });
  const page = {
    body: { append() {} },
    activeElement: null,
    getElementById: () => null,
    createElement: () => overlay,
    addEventListener: (type, fn) => { (documentListeners[type] ??= []).push(fn); },
  };
  const saved = { document: globalThis.document, navigator: globalThis.navigator, addEventListener: globalThis.addEventListener };
  Object.defineProperty(globalThis, "document", { value: page, configurable: true, writable: true });
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (value) => { clipboard.push(value); } } }, configurable: true, writable: true });
  globalThis.addEventListener = (type, fn) => { (windowListeners[type] ??= []).push(fn); };
  try {
    initExpandable({ copy: () => "<copy>", copied: () => "<check>" });
    const cell = fakeElement({ dataset: { exp: "00ff" } });
    await run({
      copyButton: parts["#exp-copy"],
      parts, clipboard, overlay,
      open: ({ value = "00ff", editable = false } = {}) => {
        cell.dataset = { exp: value, ...(editable ? { expEdit: "" } : {}) };
        documentListeners.click.forEach((fn) => fn({ target: { closest: () => cell } }));
      },
      close: () => parts["#exp-close"].fire("click"),
      pageEvent: (type, event = {}) => (windowListeners[type] ?? []).forEach((fn) => fn(event)),
      copy: async () => {
        parts["#exp-copy"].fire("click");
        await new Promise((resolve) => setImmediate(resolve));
      },
    });
  } finally {
    Object.defineProperty(globalThis, "document", { value: saved.document, configurable: true, writable: true });
    Object.defineProperty(globalThis, "navigator", { value: saved.navigator, configurable: true, writable: true });
    if (saved.addEventListener === undefined) delete globalThis.addEventListener;
    else globalThis.addEventListener = saved.addEventListener;
  }
};

test("readonly values use a protected readout and copy without populating the editor", async () => {
  await withExpandDialog(async ({ parts, open, close, copy, clipboard }) => {
    const value = "  " + "abcd".repeat(40) + "\n";
    open({ value });
    assert.equal(parts["#exp-text"].value, "", "readonly secrets must not reach a native selection control");
    assert.equal(parts["#exp-text"].hidden, true);
    assert.equal(parts["#exp-readout"].textContent, value);
    assert.equal(parts["#exp-readout"].hidden, false);
    assert.equal(parts["#exp-apply"].hidden, true);
    await copy();
    assert.deepEqual(clipboard, [value], "copy must preserve every character of the displayed value");
    close();
    assert.equal(parts["#exp-text"].value, "");
    assert.equal(parts["#exp-readout"].textContent, "");
  });
});

test("editable values keep their editor and copy the current edit without a second readout copy", async () => {
  await withExpandDialog(async ({ parts, open, copy, clipboard }) => {
    open({ value: "ab".repeat(100), editable: true });
    assert.equal(parts["#exp-text"].hidden, false);
    assert.equal(parts["#exp-readout"].hidden, true);
    assert.equal(parts["#exp-readout"].textContent, "");
    assert.equal(parts["#exp-apply"].hidden, false);
    parts["#exp-text"].value = "cafe";
    await copy();
    assert.deepEqual(clipboard, ["cafe"]);
    open({ value: "ff".repeat(100) });
    assert.equal(parts["#exp-text"].value, "", "switching to a readonly value must release the previous edit");
  });
});

test("both viewer modes release contents on pagehide and restored pageshow", async () => {
  await withExpandDialog(async ({ parts, open, pageEvent, overlay }) => {
    for (const editable of [false, true]) {
      for (const [type, event] of [["pagehide", {}], ["pageshow", { persisted: true }]]) {
        open({ value: "secret ".repeat(20), editable });
        pageEvent(type, event);
        assert.equal(parts["#exp-text"].value, "");
        assert.equal(parts["#exp-readout"].textContent, "");
        assert.equal(overlay.hidden, true);
      }
    }
  });
});

// Closing within the check's 1.6 s and opening again must not keep the check:
// opening cancels its timer, so opening has to restore the label as well.
test("reopening the expand dialog clears a copy check cut short", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  await withExpandDialog(async ({ copyButton, open, close, copy }) => {
    open();
    await copy();
    assert.equal(copyButton.getAttribute("aria-label"), "Copied", "fixture: the copy did not confirm");
    close();
    open();
    assert.equal(copyButton.innerHTML, "<copy>", "the reopened dialog kept the check");
    assert.equal(copyButton.getAttribute("aria-label"), "Copy", "the reopened dialog kept the copied label");
    assert.equal(copyButton.title, "Copy");
  });
});
