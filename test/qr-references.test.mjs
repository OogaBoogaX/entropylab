// Tests for the pure half of src/js/qr-references.js — the link classifier
// and the QR SVG renderer. initQrReferences is DOM-bound and covered by the
// Firefox browser suite (test/browser-suite.html); that every word the popup
// shows is translatable is checked here through a minimal fake page.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { initQrReferences, isOfflineLink, referenceQrSvg } from "../src/js/qr-references.js";
import { collectSources, normalize } from "../scripts/i18n-sources.mjs";

test("isOfflineLink accepts http and https anchors", () => {
  const make = (href) => ({ tagName: "A", getAttribute: () => href });
  assert.equal(isOfflineLink(make("https://example.com/page")), true);
  assert.equal(isOfflineLink(make("http://example.com/page")), true);
  assert.equal(isOfflineLink(make("HTTPS://example.com")), true);
});

test("isOfflineLink rejects relative, fragment, and non-http links", () => {
  const make = (href) => ({ tagName: "A", getAttribute: () => href });
  assert.equal(isOfflineLink(make("entropylab.html")), false);
  assert.equal(isOfflineLink(make("#section")), false);
  assert.equal(isOfflineLink(make("mailto:a@b.com")), false);
  assert.equal(isOfflineLink(make("tel:+15551234")), false);
  assert.equal(isOfflineLink(make("")), false);
  assert.equal(isOfflineLink(make(null)), false);
});

test("isOfflineLink rejects non-anchor elements and null", () => {
  assert.equal(isOfflineLink(null), false);
  assert.equal(isOfflineLink({ tagName: "DIV", getAttribute: () => "https://x.com" }), false);
  assert.equal(isOfflineLink({ tagName: "BUTTON", getAttribute: () => "https://x.com" }), false);
});

test("referenceQrSvg produces SVG markup for a URL", () => {
  const svg = referenceQrSvg("https://example.com");
  assert.match(svg, /^<svg/);
  assert.ok(svg.includes("</svg>"));
  // The QR uses the same dark/white palette as the rest of the app's codes.
  assert.ok(svg.includes("#111111"));
  assert.ok(svg.includes("#ffffff"));
});

test("referenceQrSvg output differs for different URLs", () => {
  const a = referenceQrSvg("https://example.com/foo");
  const b = referenceQrSvg("https://example.com/bar");
  assert.notEqual(a, b);
});

test("referenceQrSvg handles a long URL without throwing", () => {
  const longUrl = "https://example.com/" + "a".repeat(200);
  const svg = referenceQrSvg(longUrl);
  assert.match(svg, /^<svg/);
});

const URL_SHOWN = "https://example.com/reference", LINK_TEXT = "Example reference";
const fakeElement = (props = {}) => {
  const listeners = {}, attributes = {};
  return {
    hidden: false, innerHTML: "", title: "", isConnected: true,
    classList: { add() {}, remove() {}, contains: () => false },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return name in attributes ? attributes[name] : null; },
    addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
    fire(type, event = {}) { for (const fn of listeners[type] ?? []) fn(event); },
    focus() {},
    ...props,
  };
};
const withReferencePopup = async (run) => {
  const buttons = {}, documentListeners = {};
  const card = fakeElement({ querySelector: (selector) => (buttons[selector] ??= fakeElement()) });
  const overlay = fakeElement({ querySelector: (selector) => (selector === ".qr-ref-card" ? card : null), querySelectorAll: () => [] });
  const page = { body: { append() {} }, activeElement: null, getElementById: (id) => (id === "network-status" ? { dataset: { state: "offline" } } : null), createElement: () => overlay, addEventListener: (type, fn) => { (documentListeners[type] ??= []).push(fn); } };
  const saved = globalThis.document;
  Object.defineProperty(globalThis, "document", { value: page, configurable: true, writable: true });
  try {
    initQrReferences({ copy: () => '<svg data-icon="copy"></svg>', copied: () => '<svg data-icon="check"></svg>' });
    const link = { tagName: "A", textContent: LINK_TEXT, getAttribute: () => URL_SHOWN, focus() {} };
    documentListeners.click.forEach((fn) => fn({ target: { closest: () => link }, preventDefault() {} }));
    await run({ card, copyButton: buttons["#qr-ref-copy"] });
  } finally {
    Object.defineProperty(globalThis, "document", { value: saved, configurable: true, writable: true });
  }
};
const decodeEntities = (text) => text.replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16))).replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec))).replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const shownStrings = (html) => {
  const markup = html.replace(/<svg[\s\S]*?<\/svg>/g, "");
  return [...[...markup.matchAll(/>([^<]*)</g)].map((match) => match[1]), ...[...markup.matchAll(/\s(?:aria-label|title)="([^"]*)"/g)].map((match) => match[1])].map((text) => normalize(decodeEntities(text))).filter(Boolean);
};

test("every word the reference QR popup shows is a translation source", async () => {
  const sources = await collectSources(fileURLToPath(new URL("..", import.meta.url)));
  await withReferencePopup(async ({ card }) => {
    const shown = shownStrings(card.innerHTML);
    assert.ok(shown.length > 3, "fixture: the popup rendered no card");
    const own = shown.filter((text) => text !== LINK_TEXT && text !== URL_SHOWN).map((text) => text.replace(URL_SHOWN, "{url}"));
    assert.deepEqual(own.filter((text) => !sources.has(text)), [], "the popup shows text that is never translated");
  });
});
