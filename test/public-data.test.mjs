// Public readouts preserve the exact key material for the shared copy
// handler; empty values and unrelated PSBT data must not become copy targets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { publicFieldHtml, publicValueHtml } from "../src/js/public-data.js";

const copyIcon = () => '<svg data-test-copy-icon></svg>';
const PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const parse = (html) => {
  const document = new MiniDocument();
  document.body.innerHTML = html;
  return document.body;
};

test("public field connects its label clipboard with the exact shown value", () => {
  const body = parse(publicFieldHtml("Node key", PUBKEY, { copyIcon, id: "node-key" }));
  const value = body.querySelector("[data-public-value]");
  const copy = body.querySelector("[data-public-copy]");
  assert.equal(value.id, "node-key");
  assert.equal(value.textContent, PUBKEY);
  assert.ok(value.hasAttribute("data-copy-field"));
  assert.equal(copy.closest("[data-copy-group]"), value.closest("[data-copy-group]"));
  assert.ok(copy.getAttribute("aria-label"));
  assert.equal(copy.querySelector("[data-test-copy-icon]").tagName, "SVG");
  assert.equal(copy.getAttribute("data-copy-value"), null);
});

test("public field with a QR has one QR action and no duplicate label clipboard", () => {
  const body = parse(publicFieldHtml("Address", PUBKEY, { copyIcon, qrHtml: '<button data-address-qr="known-public-payload"></button>' }));
  assert.ok(body.querySelector("[data-address-qr]"));
  assert.equal(body.querySelector("[data-public-copy]"), null);
  assert.equal(body.querySelector("[data-public-value]").textContent, PUBKEY);
});

test("inline public preview keeps the full payload for copying and has no nested actions", () => {
  const body = parse(publicValueHtml(PUBKEY, { label: "Public key", copyIcon, preview: "0279…1798" }));
  const value = body.querySelector("[data-public-value]");
  assert.equal(value.textContent, "0279…1798");
  assert.equal(value.dataset.copyValue, PUBKEY);
  assert.ok(value.hasAttribute("data-i18n-skip"));
  assert.equal(body.querySelectorAll("button button").length, 0);
  assert.ok(body.querySelector("[data-public-copy]"));
});

test("public readout escapes supplied values and identifiers", () => {
  const body = parse(publicValueHtml('<script>&" &amp;', { id: 'key" data-injected="yes', copyIcon }));
  assert.equal(body.querySelector("script"), null);
  assert.equal(body.querySelector("[data-injected]"), null);
  assert.equal(body.querySelector("[data-public-value]").textContent, '<script>&" &amp;');
});

test("inline outputs can keep direct copy without a duplicate clipboard control", () => {
  const body = parse(publicValueHtml("m/84'/0'/0'/0/0", { clipboard: false, copyIcon }));
  const value = body.querySelector("[data-public-value]"), status = body.querySelector("[data-copy-status]");
  assert.equal(value.textContent, "m/84'/0'/0'/0/0");
  assert.ok(value.hasAttribute("data-copy-field"));
  assert.equal(body.querySelector("[data-public-copy]"), null);
  assert.ok(status, "the direct action has its own confirmation slot");
  assert.equal(status.closest("[data-copy-group]"), value.closest("[data-copy-group]"));
  assert.ok(status.getAttribute("aria-live"));
  assert.equal(status.textContent, "");
});

for (const empty of [null, undefined, "", "—"]) {
  test(`missing public value ${String(empty)} has no copy action`, () => {
    for (const html of [publicFieldHtml("Key", empty, { copyIcon }), publicValueHtml(empty, { copyIcon })]) {
      const body = parse(html);
      assert.equal(body.querySelector("[data-copy-field]"), null);
      assert.equal(body.querySelector("[data-public-copy]"), null);
    }
  });
}
