// End session (src/js/end-session.js). The residue audit found that closing
// the tab is the only step that removes every copy of a secret, so End session
// wipes what the page can and then asks the browser to close the tab.
//
// Contract: End session runs, in this order, every wipe the page runs when it
// is left (a pagehide that is not a bfcache entry), the modules' retirement
// (their whole linear memory overwritten with patterns, then zeroed), the
// saved preferences cleared from both storages (every `entropylab-` key
// except the language), the clipboard clear, the page's replacement by the
// ended screen (nothing of the old DOM left), and window.close(). A clipboard
// the browser refuses to clear does not stop the rest, and neither does a
// storage that throws. The live page (the header control, the dialog, a real
// tab) is covered in the browser suite; the modules' retirement in
// wasm-retire.test.mjs.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import * as endSessionModule from "../src/js/end-session.js";
import { endSession, renderSessionEnded } from "../src/js/end-session.js";
import { hodlLocaleStorageKey } from "../src/js/i18n.js";

const SECRET = "legal winner thank year wave sausage worth useful legal winner thank yellow";

const fakePage = () => {
  const log = [];
  const doc = new MiniDocument();
  doc.body.innerHTML = `<div id="btc-calc"><textarea id="seed"></textarea><p id="out">${SECRET}</p></div>`;
  doc.getElementById("seed").value = SECRET;
  const win = {
    PageTransitionEvent: class {
      constructor(type, init) { this.type = type; this.persisted = init?.persisted; }
    },
    dispatchEvent: (event) => { log.push(`${event.type}:${event.persisted === false ? "left" : "restored"}`); return true; },
    close: () => { log.push(`close:${doc.querySelector("[data-session-ended]") ? "after the ended screen" : "before it"}`); },
  };
  return { log, doc, win };
};

// A Storage stand-in: key(index) reflects the current order, so a loop that
// removes while indexing skips the next key.
const fakeStorage = (entries) => {
  const map = new Map(Object.entries(entries));
  return {
    get length() { return map.size; },
    key: (index) => [...map.keys()][index] ?? null,
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(String(key), String(value)); },
    removeItem: (key) => { map.delete(key); },
    get keys() { return [...map.keys()]; },
  };
};

test("End session wipes, retires, clears, replaces the page and closes, in that order", async () => {
  const { log, doc, win } = fakePage();
  await endSession({
    win,
    doc,
    retireModules: [() => log.push("retire crypto"), () => log.push("retire psbt")],
    clearClipboard: async () => { log.push("clear clipboard"); return true; },
  });
  assert.deepEqual(log, ["pagehide:left", "retire crypto", "retire psbt", "clear clipboard", "close:after the ended screen"]);
  assert.equal(doc.getElementById("btc-calc"), null, "the app's DOM must be gone");
  assert.equal(doc.getElementById("seed"), null);
  assert.ok(!doc.body.textContent.includes("legal winner"), "the ended screen must hold nothing of the session");
  assert.ok(doc.querySelector("[data-session-ended]"), "the ended screen is missing");
});

test("a clipboard the browser refuses to clear does not stop the session ending", async () => {
  const { log, doc, win } = fakePage();
  await endSession({
    win,
    doc,
    retireModules: [() => log.push("retire")],
    clearClipboard: async () => { throw new Error("NotAllowedError"); },
  });
  assert.deepEqual(log, ["pagehide:left", "retire", "close:after the ended screen"]);
  assert.ok(doc.querySelector("[data-session-ended]"));
});

test("the ended screen mentions the clipboard only when it was cleared", () => {
  const paragraphs = (cleared) => {
    const doc = new MiniDocument();
    renderSessionEnded(doc, { clipboardCleared: cleared });
    return doc.querySelectorAll("[data-session-ended] p").length;
  };
  assert.equal(paragraphs(true), paragraphs(false) + 1);
});

// Contract: the ended screen says the clipboard was emptied only when the
// clear reported success. A clear that reports false, or that the browser
// refuses (a rejection), must not leave that claim on the screen. The test
// above pins the screen; this pins what endSession hands it (found by the
// mutation-testing pilot: `.catch(() => true)` and dropping
// `{ clipboardCleared }` both passed every test).
test("End session claims an emptied clipboard only when the clear succeeded", async () => {
  const screenParagraphs = (cleared) => {
    const doc = new MiniDocument();
    renderSessionEnded(doc, { clipboardCleared: cleared });
    return doc.querySelectorAll("[data-session-ended] p").length;
  };
  for (const [label, clearClipboard, cleared] of [
    ["cleared", async () => true, true],
    ["not cleared", async () => false, false],
    ["refused", async () => { throw new Error("NotAllowedError"); }, false],
  ]) {
    const { doc, win } = fakePage();
    await endSession({ win, doc, clearClipboard });
    assert.equal(doc.querySelectorAll("[data-session-ended] p").length, screenParagraphs(cleared), label);
  }
});

// Microsoft Edge. Measured on 2026-10-06 (Windows 11, Chrome 154.0.8037.98
// and Edge 154.0.4258.53): after Copy seed phrase, Edge's browser process
// still held 2 or 3 copies of the phrase once the tab closed, until Edge
// itself was quit; Chrome held none (#816).
//
// Contract: when the browser is Edge, the End session dialog, which everyone
// sees before the tab closes, adds a warning to quit Edge completely. Every
// other browser gets the dialog unchanged. Detection reads only this
// device's navigator.
//
// User-agent shapes follow Microsoft's documented formats: "Edg/" on
// desktop, "EdgA/" on Android, "EdgiOS/" on iOS, and the "Microsoft Edge"
// brand in navigator.userAgentData.
const EDGE_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.4258.53";
const EDGE_ANDROID = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36 EdgA/154.0.4258.53";
const EDGE_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/154.0.4258.53 Mobile/15E148 Safari/605.1.15";
const CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const OPERA_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 OPR/139.0.0.0";
const FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0";
const SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

test("Edge is recognised from its brand or its user-agent token, and nothing else is", () => {
  const { isEdge } = endSessionModule;
  assert.equal(typeof isEdge, "function");
  for (const userAgent of [EDGE_WINDOWS, EDGE_ANDROID, EDGE_IOS]) assert.equal(isEdge({ userAgent }), true, userAgent);
  assert.equal(isEdge({ userAgent: "", userAgentData: { brands: [{ brand: "Not=A?Brand", version: "99" }, { brand: "Microsoft Edge", version: "154" }, { brand: "Chromium", version: "154" }] } }), true);
  for (const userAgent of [CHROME_WINDOWS, OPERA_WINDOWS, FIREFOX_WINDOWS, SAFARI_MAC, "", "Mozilla/5.0 SomeEdg/1.0"]) assert.equal(isEdge({ userAgent }), false, userAgent);
  assert.equal(isEdge({ userAgent: CHROME_WINDOWS, userAgentData: { brands: [{ brand: "Google Chrome", version: "154" }, { brand: "Chromium", version: "154" }] } }), false);
  assert.equal(isEdge(undefined), false);
  assert.equal(isEdge({}), false);
});

test("only Edge gets the End session dialog's quit-Edge warning", () => {
  const { endSessionEdgeWarning } = endSessionModule;
  assert.equal(typeof endSessionEdgeWarning, "function");
  assert.equal(endSessionEdgeWarning({ userAgent: CHROME_WINDOWS }), null, "other browsers keep the dialog unchanged");
  assert.equal(endSessionEdgeWarning({ userAgent: FIREFOX_WINDOWS }), null);
  assert.equal(endSessionEdgeWarning(undefined), null);
  const warning = endSessionEdgeWarning({ userAgent: EDGE_WINDOWS });
  assert.match(warning, /Microsoft Edge/);
  assert.match(warning, /Quit Edge completely/);
  assert.match(warning, /Startup boost/);
});

test("the ended screen is unchanged by the Edge warning", async () => {
  const ended = async (navigator) => {
    const { doc, win } = fakePage();
    win.navigator = navigator;
    await endSession({ win, doc });
    return doc.body.textContent;
  };
  assert.equal(await ended({ userAgent: EDGE_WINDOWS }), await ended({ userAgent: CHROME_WINDOWS }), "the ended screen differs between Edge and other browsers");
});

// Contract: End session clears EntropyLab's saved preferences from both
// storages, keeping the language (owner decision 2026-10-26). The keys are
// not secrets, but on a shared machine they show the page was used.
test("End session clears every saved preference except the language, in both storages", async () => {
  const { doc, win } = fakePage();
  const saved = {
    "entropylab-theme": "dark",
    "entropylab-intro-dismissed": "1",
    "entropylab-disclaimer-banner-dismissed": "1",
    "entropylab-sources-open": "1",
    "entropylab-important-open": "1",
    "entropylab-disclaimer-accepted": "1.0.0",
    "entropylab-locale": "fr",
    "other-site-key": "keep me",
  };
  win.localStorage = fakeStorage(saved);
  win.sessionStorage = fakeStorage(saved);
  await endSession({ win, doc });
  for (const storage of [win.localStorage, win.sessionStorage]) {
    assert.deepEqual(storage.keys.sort(), ["entropylab-locale", "other-site-key"]);
    assert.equal(storage.getItem("entropylab-locale"), "fr");
    assert.equal(storage.getItem("other-site-key"), "keep me");
  }
});

test("a storage that throws does not stop the session ending", async () => {
  const blocked = fakePage();
  Object.defineProperty(blocked.win, "localStorage", { get() { throw new Error("SecurityError"); } });
  blocked.win.sessionStorage = fakeStorage({ "entropylab-theme": "dark", "entropylab-locale": "fr" });
  await endSession({ win: blocked.win, doc: blocked.doc });
  assert.ok(blocked.doc.querySelector("[data-session-ended]"), "the ended screen must still render");
  assert.ok(blocked.log.includes("close:after the ended screen"), "close() must still run");
  assert.deepEqual(blocked.win.sessionStorage.keys.sort(), ["entropylab-locale"], "the other storage must still be cleared");

  const refusing = fakePage();
  const storage = fakeStorage({ "entropylab-theme": "dark" });
  storage.removeItem = () => { throw new Error("QuotaExceededError"); };
  refusing.win.localStorage = storage;
  refusing.win.sessionStorage = fakeStorage({ "entropylab-theme": "dark", "entropylab-locale": "fr" });
  await endSession({ win: refusing.win, doc: refusing.doc });
  assert.ok(refusing.doc.querySelector("[data-session-ended]"), "the ended screen must still render");
  assert.ok(refusing.log.includes("close:after the ended screen"), "close() must still run");
  assert.deepEqual(refusing.win.sessionStorage.keys.sort(), ["entropylab-locale"], "the other storage must still be cleared");
});

test("clearSavedPreferences removes adjacent matching keys without skipping one", () => {
  const { clearSavedPreferences } = endSessionModule;
  assert.equal(typeof clearSavedPreferences, "function");
  const storage = fakeStorage({
    "entropylab-a": "1",
    "entropylab-b": "1",
    "entropylab-c": "1",
    "entropylab-locale": "de",
    "other-site-key": "keep",
  });
  clearSavedPreferences({ localStorage: storage, sessionStorage: fakeStorage({}) });
  assert.deepEqual(storage.keys.sort(), ["entropylab-locale", "other-site-key"]);
});

test("the kept preference key is the locale key i18n.js writes", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/js/end-session.js", import.meta.url), "utf8");
  const match = source.match(/const KEPT_PREFERENCE_KEY = "([^"]+)";/);
  assert.ok(match, "end-session.js must define KEPT_PREFERENCE_KEY as a string literal");
  assert.equal(match[1], hodlLocaleStorageKey);
});
