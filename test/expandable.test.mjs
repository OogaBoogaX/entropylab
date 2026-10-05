// Tests for the pure half of src/js/expandable.js — the standard truncation
// rule and the cell markup. initExpandable is DOM-bound and covered by the
// Firefox browser suite (test/browser-suite.html); reopening it after a copy
// is checked here through a minimal fake page.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { truncateText, expandSizeLabel, expandableHtml, initExpandable, EXPAND_LIMIT } from "../src/js/expandable.js";

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

test("short text renders as escaped plain text, not a button", () => {
  assert.equal(expandableHtml("00ff"), "00ff");
  assert.equal(expandableHtml('<script>"x"</script>'), "&lt;script&gt;&quot;x&quot;&lt;/script&gt;");
  assert.ok(!expandableHtml("00ff").includes("exp-cell"));
});

test("long text renders a truncated cell carrying the full value", () => {
  const value = "cd".repeat(150); // 300 hex chars
  const html = expandableHtml(value, { label: "Value bytes for PSBT_IN_WITNESS_UTXO (hex)" });
  assert.match(html, /^<button type="button" class="exp-cell" /);
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

// Minimal fake page drives the real dialog.
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
  const parts = {}, documentListeners = {};
  const overlay = fakeElement({ querySelector: (selector) => (parts[selector] ??= fakeElement()), querySelectorAll: () => [] });
  const page = { body: { append() {} }, activeElement: null, getElementById: () => null, createElement: () => overlay, addEventListener: (type, fn) => { (documentListeners[type] ??= []).push(fn); } };
  const saved = { document: globalThis.document, navigator: globalThis.navigator, addEventListener: globalThis.addEventListener };
  Object.defineProperty(globalThis, "document", { value: page, configurable: true, writable: true });
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => {} } }, configurable: true, writable: true });
  globalThis.addEventListener = () => {};
  try {
    initExpandable({ copy: () => "<copy>", copied: () => "<check>" });
    const cell = fakeElement({ dataset: { exp: "00ff" } });
    await run({ copyButton: parts["#exp-copy"], open: () => documentListeners.click.forEach((fn) => fn({ target: { closest: () => cell } })), close: () => parts["#exp-close"].fire("click"), copy: async () => { parts["#exp-copy"].fire("click"); await new Promise((resolve) => setImmediate(resolve)); } });
  } finally {
    Object.defineProperty(globalThis, "document", { value: saved.document, configurable: true, writable: true });
    Object.defineProperty(globalThis, "navigator", { value: saved.navigator, configurable: true, writable: true });
    if (saved.addEventListener === undefined) delete globalThis.addEventListener; else globalThis.addEventListener = saved.addEventListener;
  }
};

test("reopening the expand dialog clears a copy check cut short", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  await withExpandDialog(async ({ copyButton, open, close, copy }) => {
    open(); await copy();
    assert.equal(copyButton.getAttribute("aria-label"), "Copied", "fixture: the copy did not confirm");
    close(); open();
    assert.equal(copyButton.innerHTML, "<copy>", "the reopened dialog kept the check");
    assert.equal(copyButton.getAttribute("aria-label"), "Copy", "the reopened dialog kept the copied label");
    assert.equal(copyButton.title, "Copy");
  });
});
