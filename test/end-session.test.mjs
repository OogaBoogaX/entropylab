// End session (src/js/end-session.js). The residue audit found that closing
// the tab is the only step that removes every copy of a secret, so End session
// wipes what the page can and then asks the browser to close the tab.
//
// Contract: End session runs, in this order, every wipe the page runs when it
// is left (a pagehide that is not a bfcache entry), the modules' retirement
// (their whole linear memory overwritten with patterns, then zeroed), the clipboard clear, the page's
// replacement by the ended screen (nothing of the old DOM left), and
// window.close(). A clipboard the browser refuses to clear does not stop the
// rest. The live page (the header control, the dialog, a real tab) is covered
// in the browser suite; the modules' retirement in wasm-retire.test.mjs.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import * as endSessionModule from "../src/js/end-session.js";
import { endSession, renderSessionEnded } from "../src/js/end-session.js";

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
