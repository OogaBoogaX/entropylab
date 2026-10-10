// Public value clicks and label clipboards must copy the current readout;
// missing, concealed and detached readouts must never reach the clipboard.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument, MiniElement } from "./mini-dom.mjs";

const app = await loadAppFunctions(["hodlPublicFieldHtml", "hodlPublicInlineHtml", "hodlCopyFieldHtml", "hodlInitDescriptorCopy"]);
// SEC2's secp256k1 generator, compressed. This is public test data.
const PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
async function withPage(body) {
  const saved = Object.fromEntries(["document", "navigator"].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const document = new MiniDocument(), writes = [];
  let listener;
  document.addEventListener = (type, callback) => { if (type === "click") listener = callback; };
  document.defaultView = { getComputedStyle: () => ({ visibility: "visible" }) };
  Object.defineProperty(MiniElement.prototype, "getClientRects", { configurable: true, value() { return [{}]; } });
  Object.defineProperty(globalThis, "document", { configurable: true, value: document });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (value) => { writes.push(value); } } } });
  mock.timers.enable({ apis: ["setTimeout"] });
  app.hodlInitDescriptorCopy();
  const click = async (target) => { assert.ok(target, "copy target exists"); await listener({ target }); await new Promise((resolve) => setImmediate(resolve)); };
  try { await body({ document, writes, click }); }
  finally {
    mock.timers.reset();
    delete MiniElement.prototype.getClientRects;
    for (const [key, descriptor] of Object.entries(saved)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
}

test("public values without QR controls copy through the value and label clipboard", () => withPage(async ({ document, writes, click }) => {
  document.body.innerHTML = app.hodlPublicFieldHtml("Compressed public key", PUBLIC_KEY);
  const value = document.querySelector("[data-public-value]"), copy = document.querySelector("[data-public-copy]");
  assert.ok(value && copy, "the public value and its label clipboard are wired");
  assert.equal(document.querySelector("[data-address-qr]"), null);
  await click(value);
  await click(copy);
  assert.deepEqual(writes, [PUBLIC_KEY, PUBLIC_KEY]);
  value.textContent = "73c5da0a";
  await click(copy);
  assert.equal(writes.at(-1), "73c5da0a", "the control reads the updated field, not a cached value");
}));

test("QR-backed public fields copy on their value and omit a second clipboard control", () => withPage(async ({ document, writes, click }) => {
  document.body.innerHTML = app.hodlCopyFieldHtml("Public key", PUBLIC_KEY);
  assert.ok(document.querySelector("[data-address-qr]"));
  assert.equal(document.querySelector("[data-public-copy]"), null);
  await click(document.querySelector("[data-public-value]"));
  assert.deepEqual(writes, [PUBLIC_KEY]);
}));

test("inline public values without clipboard icons copy directly and clear their temporary confirmation", () => withPage(async ({ document, writes, click }) => {
  document.body.innerHTML = app.hodlPublicInlineHtml(PUBLIC_KEY, { clipboard: false });
  const value = document.querySelector("[data-public-value]");
  const status = value.closest("[data-copy-group]").querySelector("[data-copy-status]");
  assert.equal(document.querySelector("[data-public-copy]"), null);
  assert.ok(status, "direct copying has a feedback slot in the same value group");
  assert.ok(status.getAttribute("aria-live"));
  assert.equal(status.childNodes.length, 0);
  await click(value);
  assert.deepEqual(writes, [PUBLIC_KEY]);
  assert.equal(value.textContent, PUBLIC_KEY, "confirmation must not replace the public value");
  assert.ok(status.childNodes.length > 0, "the successful copy produced no confirmation");
  mock.timers.tick(2000);
  assert.equal(status.childNodes.length, 0, "copy confirmation did not clear");
  value.textContent = "73c5da0a";
  await click(value);
  assert.deepEqual(writes, [PUBLIC_KEY, "73c5da0a"]);
  assert.ok(status.childNodes.length > 0, "a subsequent copy produced no confirmation");
  mock.timers.tick(2000);
  assert.equal(status.childNodes.length, 0);
}));

test("a public payload beyond QR capacity uses the label clipboard and copies the full text", () => withPage(async ({ document, writes, click }) => {
  const payload = PUBLIC_KEY.repeat(16);
  document.body.innerHTML = app.hodlCopyFieldHtml("Public export", payload);
  assert.equal(document.querySelector("[data-address-qr]"), null);
  await click(document.querySelector("[data-public-copy]"));
  assert.deepEqual(writes, [payload]);
}));

for (const state of ["missing", "concealed", "detached"]) {
  test(`${state} public fields cannot copy`, () => withPage(async ({ document, writes, click }) => {
    document.body.innerHTML = app.hodlPublicFieldHtml("Public key", state === "missing" ? null : PUBLIC_KEY);
    const value = document.querySelector("[data-public-value]"), copy = document.querySelector("[data-public-copy]");
    if (state === "missing") {
      assert.equal(copy, null, "an absent value has no clipboard action");
      if (value) await click(value);
    } else {
      assert.ok(value && copy);
      if (state === "concealed") value.closest("[data-copy-group]").hidden = true;
      else value.closest("[data-copy-group]").remove();
      await click(value);
      await click(copy);
    }
    assert.deepEqual(writes, []);
  }));
}
