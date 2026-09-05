// Tests for the pure half of src/js/qr-references.js — the link classifier
// and the QR SVG renderer. initQrReferences is DOM-bound and covered by the
// Firefox browser suite (test/browser-suite.html).
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { isOfflineLink, referenceQrSvg } from "../src/js/qr-references.js";

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
