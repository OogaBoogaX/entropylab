// Tests for the pure half of src/js/address-qr.js — the per-row QR button
// markup. initAddressQr is DOM-bound and covered by the browser suite
// (test/browser-suite.html), which drives a row button through the overlay.
// Run with `npm test` (part of the default and CI suites).
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { addressQrButtonHtml, initAddressQr, watchOnlyQrButtonHtml } from "../src/js/address-qr.js";
import { WATCH_ONLY_QR_STATIC_MAX_CHARS, hodlUrDecodeWatchOnly, watchOnlyQrFrames } from "../src/js/psbt-ur.js";
import { MiniDocument, MiniElement } from "./mini-dom.mjs";

const ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

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
  const close = module.slice(module.indexOf("const close = () => {"), module.indexOf("const open = (target) => {"));
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

// Security contract: a PSBT (whose proprietary fields may carry private
// keys) copies only through the copy button; text/image clicks must be
// inert. Public address previews retain their existing copy interactions.
const PSBT = readFileSync(new URL("fixtures/psbt/p2wpkh-1in-2out.b64", import.meta.url), "utf8").trim();
const settle = () => new Promise((resolve) => setImmediate(resolve));

async function withOverlay(run, { fallback = false, frames = null, renderQr = () => "<svg></svg>" } = {}) {
  const saved = Object.fromEntries(["document", "navigator", "addEventListener"].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const document = new MiniDocument(), writes = [], listeners = new WeakMap();
  const listen = function (type, callback) {
    if (!listeners.has(this)) listeners.set(this, new Map());
    const own = listeners.get(this);
    if (!own.has(type)) own.set(type, []);
    own.get(type).push(callback);
  };
  mock.method(MiniElement.prototype, "addEventListener", listen);
  mock.method(MiniElement.prototype, "focus", function () { document.activeElement = this; });
  Object.defineProperty(MiniElement.prototype, "contains", { configurable: true, value(node) {
    for (; node; node = node.parentElement) if (node === this) return true;
    return false;
  } });
  document.addEventListener = listen;
  document.execCommand = () => { writes.push(document.querySelector("textarea")?.value); return true; };
  Object.defineProperty(globalThis, "document", { configurable: true, value: document });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: fallback ? {} : { clipboard: { writeText: async (text) => { writes.push(text); } } } });
  Object.defineProperty(globalThis, "addEventListener", { configurable: true, value: (type, callback) => listen.call(globalThis, type, callback) });
  mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const fire = (node, type, event) => { for (const listener of listeners.get(node)?.get(type) || []) listener(event); };
  const click = async (node) => {
    // Dispatch even on a disabled readout: the handler must reject a direct
    // synthetic click as well as the browser's normal user interaction.
    fire(node, "click", { target: node });
    fire(document, "click", { target: node });
    await settle();
  };
  initAddressQr(renderQr, { copy: () => "<svg></svg>", copied: () => "<svg></svg>" }, { frames });
  const open = async (value, animate = "") => {
    const host = document.createElement("div");
    host.innerHTML = addressQrButtonHtml(value, "Fixture", { animate });
    document.body.append(host);
    await click(host.querySelector("button"));
  };
  try { await run({ document, writes, click, open }); }
  finally {
    fire(globalThis, "pagehide", {});
    mock.timers.reset();
    mock.restoreAll();
    delete MiniElement.prototype.contains;
    for (const [key, descriptor] of Object.entries(saved)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
}

test("PSBT QR readouts and images do not copy when clicked", () => withOverlay(async ({ document, writes, click, open }) => {
  await open(PSBT, "psbt");
  await click(document.getElementById("addr-qr-address"));
  await click(document.getElementById("addr-qr-image"));
  assert.deepEqual(writes, []);
}));

for (const fallback of [false, true]) {
  test(`the PSBT copy button copies the full payload${fallback ? " through the fallback" : ""}`, () => withOverlay(async ({ document, writes, click, open }) => {
    await open(PSBT, "psbt");
    const button = document.getElementById("addr-qr-copy");
    await click(button);
    assert.deepEqual(writes, [PSBT], "the full PSBT is copied even if the readout is abbreviated");
    assert.equal(document.querySelector("textarea"), null);
  }, { fallback }));
}

test("the QR copy button stays before Close in the actions row across reopenings", () => withOverlay(async ({ document, click, open }) => {
  const copyButton = document.getElementById("addr-qr-copy");
  const closeButton = document.getElementById("addr-qr-close");
  const actions = closeButton.parentElement;
  for (const [value, kind] of [[ADDRESS, ""], [PSBT, "psbt"], [ADDRESS, ""]]) {
    await open(value, kind);
    assert.deepEqual([...actions.children].map((button) => button.id), [copyButton.id, closeButton.id]);
    await click(closeButton);
  }
}));

test("returning to a public address restores text and QR-image copying", () => withOverlay(async ({ document, writes, click, open }) => {
  await open(PSBT, "psbt");
  await click(document.getElementById("addr-qr-close"));
  await open(ADDRESS);
  for (const id of ["addr-qr-address", "addr-qr-image", "addr-qr-copy"]) await click(document.getElementById(id));
  assert.deepEqual(writes, [ADDRESS, ADDRESS, ADDRESS]);
}));

test("closing a private QR preview makes its clipboard inert", () => withOverlay(async ({ document, writes, click, open }) => {
  await open(PSBT, "psbt");
  const button = document.getElementById("addr-qr-copy");
  await click(document.getElementById("addr-qr-close"));
  await click(button);
  assert.deepEqual(writes, []);
}));

// End to end for a watch-only descriptor (review 5644223329): the button comes
// from the field builder's watchOnlyQrButtonHtml, a click goes through the
// real overlay handler, and the frames come from psbt-ur.js, as app.js wires
// them (hodlPsbtQrFrames hands kind "watch" to watchOnlyQrFrames).
const WATCH_KEY = (i) => `[73c5da0a/48h/0h/${i}h/2h]xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC8fRrjw7A9f/0/*`;
const watchHarness = () => {
  const asked = [], drawn = [];
  return {
    asked, drawn,
    frames: (value, kind) => { asked.push(kind); return kind === "watch" ? watchOnlyQrFrames(value) : null; },
    renderQr: (value) => { drawn.push(value); return "<svg></svg>"; },
  };
};
const openWatch = async (document, click, value) => {
  const host = document.createElement("div");
  host.innerHTML = watchOnlyQrButtonHtml(value, "Watch-only wallet descriptor");
  document.body.append(host);
  const button = host.querySelector("button");
  if (button) await click(button);
  return button;
};

test("a long watch-only descriptor animates its UR parts through the overlay", () => {
  const spy = watchHarness();
  const descriptor = `wsh(sortedmulti(2,${Array.from({ length: 10 }, (_, i) => WATCH_KEY(i)).join(",")}))`;
  assert.ok(descriptor.length > WATCH_ONLY_QR_STATIC_MAX_CHARS, "fixture must overflow one QR");
  return withOverlay(async ({ document, click }) => {
    assert.ok(await openWatch(document, click, descriptor), "a public descriptor got no QR button");
    assert.deepEqual(spy.asked, ["watch"], "the overlay did not ask for watch frames");
    const parts = watchOnlyQrFrames(descriptor);
    assert.ok(parts.length > 1);
    mock.timers.tick(600 * (parts.length - 1));
    assert.deepEqual(spy.drawn, parts, "the overlay did not cycle every UR part");
    assert.equal(hodlUrDecodeWatchOnly(spy.drawn.join("\n")), descriptor);
  }, { frames: spy.frames, renderQr: spy.renderQr });
});

test("a short watch-only descriptor stays one static QR of its text", () => {
  const spy = watchHarness();
  const descriptor = `wpkh(${WATCH_KEY(0)})`;
  return withOverlay(async ({ document, click }) => {
    const button = await openWatch(document, click, descriptor);
    assert.ok(button && !button.hasAttribute("data-address-qr-animate"), "a short descriptor asked to animate");
    assert.deepEqual(spy.asked, [], "a static QR asked for frames");
    mock.timers.tick(1200);
    assert.deepEqual(spy.drawn, [descriptor]);
  }, { frames: spy.frames, renderQr: spy.renderQr });
});

test("a watch-only field with private key material offers no QR button", () => {
  const spy = watchHarness();
  return withOverlay(async ({ document, click }) => {
    for (const text of ["wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)", `wpkh(${"0".repeat(63)}1)`]) {
      assert.equal(await openWatch(document, click, text), null, "private material got a QR button");
    }
    assert.deepEqual(spy.asked, []);
    assert.deepEqual(spy.drawn, []);
  }, { frames: spy.frames, renderQr: spy.renderQr });
});
