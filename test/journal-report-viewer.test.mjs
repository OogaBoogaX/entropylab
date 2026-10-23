// Reports may contain arbitrary private text. They stay concealed until an
// explicit reveal and must leave neither DOM text nor reusable state on close.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { MiniDocument } from "./mini-dom.mjs";
import { initPrivateCopy } from "../src/js/private-data.js";
import { initJournalReportViewer } from "../src/js/journal-report-viewer.js";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const builder = source.match(/^function hodlPrivacyBarMarkup\([^]*?^}/m)[0];
const privacyMarkup = vm.runInNewContext(`${builder}; hodlPrivacyBarMarkup`, { hodlT: (text) => text });
const PRIVATE_TEXT = "  imported recovery text <img src=x onerror=alert(1)>\nsecond line\t  ";

async function withViewer(run) {
  const saved = Object.fromEntries(["document", "navigator"].map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const document = new MiniDocument(), writes = [];
  Object.defineProperty(globalThis, "document", { configurable: true, value: document });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (value) => writes.push(value) } } });
  const opener = document.createElement("button");
  opener.focus = () => { document.activeElement = opener; };
  document.body.append(opener);
  const viewer = initJournalReportViewer({ privacyMarkup, copyIcon: () => "<svg></svg>" });
  const stopCopy = initPrivateCopy();
  const el = (name) => document.getElementById(`journal-report-${name}`);
  const reveal = (value) => {
    const toggle = el("reveal");
    toggle.checked = value;
    toggle.dispatchEvent({ type: "change", target: toggle });
  };
  const copy = async () => {
    document.dispatchEvent({ type: "click", target: el("copy") });
    await new Promise((resolve) => setImmediate(resolve));
  };
  try { await run({ viewer, document, opener, el, reveal, copy, writes }); }
  finally {
    viewer.clear({ restoreFocus: false });
    clearTimeout(el("copy").copiedTimer);
    stopCopy();
    for (const [name, descriptor] of Object.entries(saved)) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
}

for (const kind of ["session-state", "session-log"]) test(`${kind} report is concealed, then copies exact revealed text through the private readout`, () => withViewer(async ({ viewer, el, reveal, copy, writes, opener }) => {
  assert.equal(viewer.show({ kind, content: PRIVATE_TEXT, opener }), true);
  assert.equal(el("modal").hidden, false);
  assert.equal(el("reveal").checked, false);
  assert.ok(el("reveal").hasAttribute("data-private-reveal"));
  assert.ok(!el("modal").textContent.includes(PRIVATE_TEXT));
  assert.equal(el("readout").textContent, "");
  assert.equal(el("copy").hidden, true);
  await copy();
  assert.deepEqual(writes, []);
  reveal(true);
  assert.equal(el("readout").textContent, PRIVATE_TEXT);
  assert.equal(el("readout").children.length, 0, "report contents became markup");
  assert.ok(el("readout").hasAttribute("data-private-value"));
  assert.ok(el("readout").hasAttribute("data-i18n-skip"));
  assert.equal(el("readout").getAttribute("translate"), "no");
  await copy();
  assert.deepEqual(writes, [PRIVATE_TEXT]);
  for (const value of el("copy").getAttributeNames().map((name) => el("copy").getAttribute(name))) assert.ok(!value.includes(PRIVATE_TEXT));
  reveal(false);
  assert.equal(el("readout").textContent, "");
  await copy();
  assert.equal(writes.length, 1);
}));

test("report close, Escape, backdrop and explicit teardown erase text and prevent stale reveal/copy", () => withViewer(async ({ viewer, document, opener, el, reveal, copy, writes }) => {
  for (const dismiss of [
    () => el("close").dispatchEvent({ type: "click" }),
    () => el("modal").dispatchEvent({ type: "keydown", key: "Escape" }),
    () => el("modal").dispatchEvent({ type: "click", target: el("modal") }),
    () => viewer.clear(),
  ]) {
    viewer.show({ kind: "session-log", content: PRIVATE_TEXT, opener });
    reveal(true);
    dismiss();
    assert.equal(el("modal").hidden, true);
    assert.equal(el("readout").textContent, "");
    assert.equal(document.activeElement, opener);
    reveal(true);
    await copy();
    assert.equal(el("readout").textContent, "");
  }
  assert.deepEqual(writes, []);
  viewer.show({ kind: "session-log", content: PRIVATE_TEXT, opener });
  document.activeElement = null;
  viewer.clear({ restoreFocus: false });
  assert.equal(document.activeElement, null);
}));

test("replacing a report starts concealed and invalid kinds or content cannot be displayed", () => withViewer(async ({ viewer, el, reveal, opener }) => {
  viewer.show({ kind: "session-state", content: PRIVATE_TEXT, opener });
  reveal(true);
  viewer.show({ kind: "session-log", content: "another private report", opener });
  assert.equal(el("readout").textContent, "");
  reveal(true);
  assert.equal(el("readout").textContent, "another private report");
  for (const report of [{ kind: "notebook", content: PRIVATE_TEXT }, { kind: "key-manager", content: PRIVATE_TEXT }, { kind: "session-log", content: {} }]) {
    assert.equal(viewer.show({ ...report, opener }), false);
    assert.equal(el("modal").hidden, true);
    reveal(true);
    assert.equal(el("readout").textContent, "");
  }
}));

test("the revealed report readout participates in keyboard focus order for scrolling", () => withViewer(async ({ viewer, document, el, reveal, opener }) => {
  viewer.show({ kind: "session-log", content: PRIVATE_TEXT, opener });
  reveal(true);
  for (const name of ["reveal", "copy", "readout", "close"]) el(name).focus = () => { document.activeElement = el(name); };
  el("copy").focus();
  el("modal").dispatchEvent({ type: "keydown", key: "Tab", preventDefault() {} });
  assert.equal(document.activeElement, el("readout"), "Tab skipped the scrollable report");
  assert.equal(el("readout").getAttribute("tabindex"), "0");
  assert.ok(document.getElementById(el("readout").getAttribute("aria-labelledby")));
  el("modal").dispatchEvent({ type: "keydown", key: "Tab", preventDefault() {} });
  assert.equal(document.activeElement, el("close"));
  reveal(false);
  el("reveal").focus = () => { document.activeElement = el("reveal"); };
  el("close").focus();
  el("modal").dispatchEvent({ type: "keydown", key: "Tab", shiftKey: true, preventDefault() {} });
  assert.equal(document.activeElement, el("reveal"), "A concealed readout stayed in the focus trap");
}));

test("opened snapshots annotate known private fields without interpreting text or changing copies", () => withViewer(async ({ viewer, el, reveal, copy, writes, opener }) => {
  const secret = "<img src=x onerror=alert(1)> & literal text";
  const snapshot = `ENTROPYLAB SESSION STATE\r\nPrivate material: INCLUDED\r\n\r\nKEYS\r\n- Saved key\r\nENTROPYLAB — RECOVERY SHEET\r\n\r\nPRIVATE RECOVERY MATERIAL\r\nHex private key:  ${secret}\r\nPUBLIC KEYS AND ADDRESSES\r\nPublic tail  `;
  for (const kind of ["session-state", "session-log"]) {
    viewer.show({ kind, content: snapshot, opener });
    assert.equal(el("readout").textContent, "");
    assert.equal(el("readout").children.length, 0);
    reveal(true);
    assert.equal(el("readout").textContent, snapshot);
    assert.equal(el("readout").querySelector("img"), null);
    if (kind === "session-state") {
      assert.ok(el("readout").querySelector("[data-report-private-label]"));
      assert.equal(el("readout").querySelector("[data-report-private-value]")?.textContent, secret);
    } else assert.equal(el("readout").querySelector("[data-report-private-label], [data-report-private-value]"), null);
    await copy();
    assert.equal(writes.at(-1), snapshot);
    reveal(false);
    assert.equal(el("readout").textContent, "");
    assert.equal(el("readout").children.length, 0);
    reveal(true);
    viewer.clear();
    assert.equal(el("readout").textContent, "");
    assert.equal(el("readout").children.length, 0);
  }
}));
