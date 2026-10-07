// Tests for the pure half of src/js/address-qr.js — the per-row QR button
// markup. initAddressQr is DOM-bound and covered by the browser suite
// (test/browser-suite.html), which drives a row button through the overlay.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { addressQrButtonHtml, privateQrButtonHtml } from "../src/js/address-qr.js";

const ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

test("a private QR button identifies a row without carrying its WIF", () => {
  const html = privateQrButtonHtml({ address: ADDRESS, path: "m/84'/0'/0'/0/0", index: 0, branch: 0, privateKey: WIF }, "Receive address #0");
  assert.ok(html.includes('data-private-qr-branch="0"'));
  assert.ok(html.includes('data-private-qr-index="0"'));
  assert.ok(html.includes('data-private-qr-path="m/84&#39;/0&#39;/0&#39;/0/0"'));
  assert.ok(html.includes(`data-private-qr-address="${ADDRESS}"`));
  assert.ok(!html.includes(WIF), "a private QR button retained the key");
  assert.equal(privateQrButtonHtml({ address: ADDRESS, path: "", index: 0, branch: 0 }, "Receive address #0"), "", "a row without a path must not offer QR");
});

test("an empty address renders no button", () => {
  assert.equal(addressQrButtonHtml(""), "");
  assert.equal(addressQrButtonHtml(null), "");
  assert.equal(addressQrButtonHtml(undefined), "");
});

test("the button carries the address and label in data attributes", () => {
  const html = addressQrButtonHtml(ADDRESS, "Address #3");
  assert.match(html, /^<button type="button" class="addr-qr no-print" /);
  assert.ok(html.includes(`data-address-qr="${ADDRESS}"`), "address missing from the button");
  assert.ok(html.includes(`data-address-qr-label="Address #3"`), "label missing from the button");
  assert.ok(html.includes('aria-label="Show QR code for Address #3"'), "aria-label missing");
  assert.ok(html.endsWith(">QR</button>"), "button text missing");
});

test("a missing label falls back to the address itself", () => {
  const html = addressQrButtonHtml(ADDRESS);
  assert.ok(html.includes(`data-address-qr-label="${ADDRESS}"`));
});

test("markup from a hostile value stays inert", () => {
  const hostile = `"><img src=x onerror=alert(1)>`;
  const html = addressQrButtonHtml(hostile, 'key "quoted"');
  assert.ok(!html.includes("<img"), "unescaped markup in button");
  assert.ok(html.includes("&lt;img"), "value was not escaped");
  assert.ok(html.includes("key &quot;quoted&quot;"), "label was not escaped");
});

test("a payload can ask the overlay for an animated sequence", () => {
  // A PSBT is larger than one code can hold, so its button opts in; an
  // address does not, and must not gain the attribute by default.
  assert.ok(!addressQrButtonHtml(ADDRESS, "Address #3").includes("data-address-qr-animate"), "an address asked to animate");
  const psbt = addressQrButtonHtml("cHNidP8BAHE", "Edited PSBT (base64)", { animate: "psbt" });
  assert.ok(psbt.includes('data-address-qr-animate="psbt"'), "the PSBT button does not ask for a sequence");
  // The kind is attribute data like any other: it escapes.
  assert.ok(addressQrButtonHtml("x", "y", { animate: '"><img src=x>' }).includes("&quot;&gt;&lt;img"), "animate kind was not escaped");
});

// The overlay is a body-level sibling of every wiped view, and the payloads
// it carries can be an edited PSBT (base64) — key material if the PSBT holds
// an xprv. Once the dialog goes out of scope it must keep none of it.
// (Behavioral checks live in test/browser-suite.html; these pin the wiring.)
test("closing the overlay releases the address text and title", () => {
  const module = readFileSync(new URL("../src/js/address-qr.js", import.meta.url), "utf8");
  const close = module.slice(module.indexOf("const close = ("), module.indexOf("const open = (target) => {"));
  assert.match(close, /text\.textContent = ""/, "close() must clear #addr-qr-address");
  assert.match(close, /title\.textContent = ""/, "close() must clear #addr-qr-title");
  assert.match(close, /note\.textContent = ""/, "close() must clear #addr-qr-note");
  assert.match(close, /image\.replaceChildren\(\)/, "close() must drop the rendered QR");
});

test("pagehide and persisted pageshow release the overlay contents", () => {
  const module = readFileSync(new URL("../src/js/address-qr.js", import.meta.url), "utf8");
  assert.match(module, /addEventListener\("pagehide"/, "the overlay must release on pagehide");
  assert.match(module, /event\.persisted/, "a bfcache restore must release too");
  const teardown = module.slice(module.indexOf("const teardown = () => {") >= 0 ? module.indexOf("const teardown = () => {") : -1, module.indexOf("addEventListener(\"pagehide\""));
  assert.match(teardown, /text\.textContent = ""/, "the teardown must clear the address text");
  assert.match(teardown, /title\.textContent = ""/, "the teardown must clear the title");
  assert.match(teardown, /payload = ""/, "the teardown must drop the payload");
});
