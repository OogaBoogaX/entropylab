// Preview build warning: a fail-closed first-load notice, a fixed note, one
// line on each preview-only station, and build checks that keep all of it out
// of the release artifact. The notice must cover the page with no script at
// all; the gate only lifts it after the acknowledgement, and the release
// build must carry none of it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";
import { checkPreviewWarning } from "../scripts/preview-warning-check.mjs";
import { initPreviewGate, PREVIEW_ACK_KEY } from "../src/js/preview-gate.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const NOTICE_TITLE = "This is a preview build";
const NOTICE_BODY = "This build is still being tested and is not approved for real use. Use test seeds only: never enter a real seed or key, and never send funds to anything made here.";
const NOTICE_BUTTON = "I understand: test seeds only";
const FIXED_NOTE = "Preview build: test seeds only. Never enter a real seed or key, or fund anything made here.";
const STATION_LINE = "Preview only: not approved for real use. Use a test seed, and do not fund anything made here.";
const PREVIEW_STRINGS = [NOTICE_TITLE, NOTICE_BODY, NOTICE_BUTTON, FIXED_NOTE, STATION_LINE];

const stationBlock = (html, id) => {
  const at = html.indexOf(`id="${id}"`);
  if (at === -1) return "";
  const start = html.lastIndexOf("<", at);
  const end = html.indexOf("</section>", at);
  return end === -1 ? "" : html.slice(start, end + "</section>".length);
};

// Synthetic pages for checkPreviewWarning: no build run, so a failure names
// the check, not a missing artifact.
const stationSection = (id, lines) =>
  `<section id="${id}">\n${`<p>${STATION_LINE}</p>\n`.repeat(lines)}</section>`;

const previewPage = ({ slip39 = 1, seedqr = 1, seedxor = 1 } = {}) => [
  `<div id="preview-notice"><p id="preview-notice-title">${NOTICE_TITLE}</p><p id="preview-notice-text">${NOTICE_BODY}</p><button id="preview-notice-accept" type="button">${NOTICE_BUTTON}</button></div>`,
  `<p id="preview-banner" role="note">${FIXED_NOTE}</p>`,
  stationSection("slip39-check", slip39),
  stationSection("seedqr-check", seedqr),
  stationSection("seedxor-card", seedxor),
].join("\n");

test("the preview build carries the notice, the fixed note and one line per station", () => {
  const index = applyPreviewBlocks(read("src/index.html"), true);
  const shell = applyPreviewBlocks(read("src/shell.html"), true);
  const notice = index.match(/<div[^>]*id="preview-notice"[^>]*>/)?.[0] ?? "";
  assert.ok(notice, "the notice is missing");
  assert.doesNotMatch(notice, /\bhidden\b/, "the notice must not start hidden");
  assert.match(notice, /\bis-visible\b/, "the notice must be visible without a script");
  assert.ok(index.includes(`id="preview-notice-title">${NOTICE_TITLE}</p>`), "the notice title is missing or reworded");
  assert.ok(index.includes(`id="preview-notice-text"><p>${NOTICE_BODY}</p></div>`), "the notice body is missing or reworded");
  assert.ok(index.includes(`id="preview-notice-accept" type="button">${NOTICE_BUTTON}</button>`), "the notice button is missing or reworded");
  assert.ok(shell.includes(`id="preview-banner" role="note">${FIXED_NOTE}</p>`), "the fixed note is missing or reworded");
  for (const id of ["slip39-check", "seedqr-check", "seedxor-card"]) {
    const block = stationBlock(shell, id);
    assert.ok(block, `the ${id} station is missing`);
    assert.equal(block.split(STATION_LINE).length - 1, 1, `the ${id} station must carry the station line once`);
  }
});

test("the release build carries none of the preview warning", () => {
  for (const path of ["src/index.html", "src/shell.html"]) {
    const release = applyPreviewBlocks(read(path), false);
    for (const text of PREVIEW_STRINGS) assert.ok(!release.includes(text), `${path} leaked: ${text}`);
    assert.ok(!release.includes('id="preview-notice"'), `${path} leaked the notice`);
    assert.ok(!release.includes('id="preview-banner"'), `${path} leaked the fixed note`);
  }
});

test("checkPreviewWarning accepts a preview build with one station line inside each station", () => {
  assert.doesNotThrow(() => checkPreviewWarning(previewPage(), true));
});

// CodeRabbit on 3f1736a3: a page-wide count of 3 lines for 3 stations passed
// while one station carried two lines and another carried none.
test("checkPreviewWarning refuses a station without its line (CodeRabbit's 2/1/0 case)", () => {
  assert.throws(() => checkPreviewWarning(previewPage({ slip39: 2, seedqr: 1, seedxor: 0 }), true), /seedxor-card/);
});

test("checkPreviewWarning refuses a station with no line while another carries two", () => {
  assert.throws(() => checkPreviewWarning(previewPage({ slip39: 0, seedqr: 1, seedxor: 2 }), true), /slip39-check/);
});

test("checkPreviewWarning refuses release HTML that leaks any preview text or markup", () => {
  for (const text of PREVIEW_STRINGS) {
    assert.throws(() => checkPreviewWarning(`<p>${text}</p>`, false), /Release build leaked/, text);
  }
  for (const id of ['id="preview-notice"', 'id="preview-banner"', 'id="slip39-check"', 'id="seedqr-check"', 'id="seedxor-card"']) {
    assert.throws(() => checkPreviewWarning(`<div ${id}></div>`, false), /Release build leaked/, id);
  }
  assert.doesNotThrow(() => checkPreviewWarning("<p>a release page</p>", false));
});

test("the stylesheet hides the page behind the notice without a script", () => {
  const css = read("src/css/styles.css");
  assert.ok(css.includes("body:has(#preview-notice) #btc-calc"), "the fail-closed hide rule is missing");
});

class FakeElement {
  constructor(id) {
    this.id = id;
    this.attributes = new Map();
    this.listeners = new Map();
    this.removed = false;
    this.focused = false;
  }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  removeAttribute(name) { this.attributes.delete(name); }
  hasAttribute(name) { return this.attributes.has(name); }
  addEventListener(type, fn) { this.listeners.set(type, fn); }
  remove() { this.removed = true; }
  focus() { this.focused = true; }
  click() { this.listeners.get("click")?.({ type: "click" }); }
  dispatch(type, event = {}) { this.listeners.get(type)?.(event); }
}

const fakeDoc = ({ notice = true, btcCalc = true } = {}) => {
  const elements = new Map();
  if (btcCalc) elements.set("btc-calc", new FakeElement("btc-calc"));
  if (notice) {
    elements.set("preview-notice", new FakeElement("preview-notice"));
    elements.set("preview-notice-accept", new FakeElement("preview-notice-accept"));
  }
  return { getElementById: (id) => elements.get(id) ?? null, elements };
};

const fakeStorage = (initial = {}) => {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)); },
    get keys() { return [...map.keys()]; },
  };
};

test("the gate keeps the notice up until the button is clicked, then writes the acknowledgement", () => {
  const doc = fakeDoc();
  const store = fakeStorage();
  initPreviewGate({ doc, storage: () => store });
  const notice = doc.getElementById("preview-notice");
  const btcCalc = doc.getElementById("btc-calc");
  const button = doc.getElementById("preview-notice-accept");
  assert.equal(notice.removed, false, "the notice must stay up without an acknowledgement");
  assert.equal(btcCalc.hasAttribute("inert"), true, "the page behind the notice must be inert");
  assert.equal(button.focused, true, "the button must take focus");
  button.click();
  assert.equal(notice.removed, true, "the notice must be removed after the acknowledgement");
  assert.equal(btcCalc.hasAttribute("inert"), false, "the page must be usable after the acknowledgement");
  assert.equal(store.getItem(PREVIEW_ACK_KEY), "1", "the acknowledgement must be written");
});

test("an acknowledgement already in sessionStorage lifts the gate at once", () => {
  const doc = fakeDoc();
  const store = fakeStorage({ [PREVIEW_ACK_KEY]: "1" });
  initPreviewGate({ doc, storage: () => store });
  assert.equal(doc.getElementById("preview-notice").removed, true);
  assert.equal(doc.getElementById("btc-calc").hasAttribute("inert"), false);
});

test("a storage getter that throws counts as not acknowledged, and a click still lifts the gate", () => {
  const doc = fakeDoc();
  initPreviewGate({ doc, storage: () => { throw new Error("SecurityError"); } });
  const notice = doc.getElementById("preview-notice");
  const btcCalc = doc.getElementById("btc-calc");
  assert.equal(notice.removed, false);
  assert.equal(btcCalc.hasAttribute("inert"), true);
  doc.getElementById("preview-notice-accept").click();
  assert.equal(notice.removed, true);
  assert.equal(btcCalc.hasAttribute("inert"), false);
});

test("a storage write that throws does not keep the notice up", () => {
  const doc = fakeDoc();
  const store = fakeStorage();
  store.setItem = () => { throw new Error("QuotaExceededError"); };
  initPreviewGate({ doc, storage: () => store });
  doc.getElementById("preview-notice-accept").click();
  assert.equal(doc.getElementById("preview-notice").removed, true);
  assert.equal(doc.getElementById("btc-calc").hasAttribute("inert"), false);
});

test("a document without the notice is left alone", () => {
  const doc = fakeDoc({ notice: false });
  const btcCalc = doc.getElementById("btc-calc");
  initPreviewGate({ doc, storage: () => fakeStorage() });
  assert.equal(btcCalc.hasAttribute("inert"), false);
});

test("Tab is trapped on the button while the notice is up", () => {
  const doc = fakeDoc();
  initPreviewGate({ doc, storage: () => fakeStorage() });
  const notice = doc.getElementById("preview-notice");
  const button = doc.getElementById("preview-notice-accept");
  let prevented = false;
  notice.dispatch("keydown", { key: "Tab", preventDefault: () => { prevented = true; } });
  assert.equal(prevented, true, "Tab must not leave the notice");
  assert.equal(button.focused, true, "focus must stay on the button");
});

test("the acknowledgement key is cleared by End session", () => {
  assert.ok(PREVIEW_ACK_KEY.startsWith("entropylab-"));
  assert.notEqual(PREVIEW_ACK_KEY, "entropylab-locale");
});

test("the build checks name both preview markers for both builds", () => {
  const check = read("scripts/preview-warning-check.mjs");
  assert.match(check, /preview-notice/);
  assert.match(check, /preview-banner/);
  assert.match(check, /Preview build is missing/);
  assert.match(check, /Release build leaked/);
  assert.match(read("scripts/build.mjs"), /checkPreviewWarning\(html, preview\)/);
});

test("the notice is not a descendant of the beta disclaimer overlay", () => {
  const index = applyPreviewBlocks(read("src/index.html"), true);
  const betaAt = index.indexOf('id="beta-disclaimer"');
  assert.notEqual(betaAt, -1, "the beta disclaimer overlay is missing");
  const betaStart = index.lastIndexOf("<", betaAt);
  const noticeAt = index.indexOf('id="preview-notice"');
  assert.notEqual(noticeAt, -1, "the preview notice is missing");
  const noticeStart = index.lastIndexOf("<", noticeAt);
  const between = index.slice(betaStart, noticeStart);
  const opens = (between.match(/<div\b/g) || []).length;
  const closes = (between.match(/<\/div>/g) || []).length;
  assert.equal(opens, closes, `the preview notice is inside #beta-disclaimer (${opens} <div openings, ${closes} </div> closings)`);
});

test("the notice is in the HTML before the browser-check script", () => {
  const index = applyPreviewBlocks(read("src/index.html"), true);
  const noticeAt = index.indexOf('id="preview-notice"');
  const scriptAt = index.indexOf("/*@@JS_BROWSER_CHECK@@*/");
  assert.notEqual(noticeAt, -1, "the preview notice is missing");
  assert.notEqual(scriptAt, -1, "the browser-check script marker is missing");
  assert.ok(noticeAt < scriptAt, "the preview notice must appear before the browser-check script");
});
