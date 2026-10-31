// The app's own clipboard for private values: one value held as UTF-8 bytes,
// never written to the system clipboard. End Session (pagehide) zeroes it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { appClipboardPut, appClipboardHas, appClipboardText, appClipboardBytes, appClipboardClear, initAppClipboard } from "../src/js/app-clipboard.js";

const withDocument = (body) => {
  const events = [];
  const previous = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", { configurable: true, value: { dispatchEvent: (event) => events.push(event.type) } });
  try { return body(events); }
  finally {
    appClipboardClear();
    if (previous) Object.defineProperty(globalThis, "document", previous);
    else delete globalThis.document;
  }
};

test("put, has and text round-trip the exact value, including non-ASCII text", () => withDocument(() => {
  appClipboardClear();
  assert.equal(appClipboardHas(), false);
  assert.equal(appClipboardText(), "");
  assert.equal(appClipboardPut("abandon ability"), true);
  assert.equal(appClipboardHas(), true);
  assert.equal(appClipboardText(), "abandon ability");
  assert.equal(appClipboardPut("  pássphrase ✓  "), true);
  assert.equal(appClipboardText(), "  pássphrase ✓  ");
}));

test("a second put zeroes the first value's bytes", () => withDocument(() => {
  appClipboardClear();
  appClipboardPut("first secret");
  const first = appClipboardBytes();
  assert.ok(first instanceof Uint8Array);
  assert.ok(first.length > 0);
  appClipboardPut("second secret");
  assert.ok(first.every((byte) => byte === 0), "the previous buffer is zeroed in place");
  assert.equal(appClipboardText(), "second secret");
}));

test("clear zeroes the held bytes and empties the store", () => withDocument(() => {
  appClipboardClear();
  appClipboardPut("secret");
  const held = appClipboardBytes();
  appClipboardClear();
  assert.ok(held.every((byte) => byte === 0));
  assert.equal(appClipboardHas(), false);
  assert.equal(appClipboardText(), "");
  assert.equal(appClipboardBytes(), null);
}));

test("put refuses an empty or non-string value and keeps the current one", () => withDocument(() => {
  appClipboardClear();
  appClipboardPut("kept");
  for (const value of ["", null, undefined, 42, {}, ["kept"]]) {
    assert.equal(appClipboardPut(value), false);
    assert.equal(appClipboardText(), "kept");
  }
}));

test("each put and clear announces hodl:app-clipboard on document", () => withDocument((events) => {
  appClipboardClear();
  events.length = 0;
  appClipboardPut("one");
  appClipboardPut("two");
  appClipboardClear();
  assert.deepEqual(events, ["hodl:app-clipboard", "hodl:app-clipboard", "hodl:app-clipboard"]);
}));

test("initAppClipboard clears on pagehide and its return removes the listener", () => withDocument(() => {
  appClipboardClear();
  const listeners = new Map();
  const target = {
    addEventListener(type, listener) { listeners.set(type, listener); },
    removeEventListener(type, listener) { if (listeners.get(type) === listener) listeners.delete(type); },
  };
  const stop = initAppClipboard(target);
  assert.equal(typeof listeners.get("pagehide"), "function");
  appClipboardPut("secret");
  listeners.get("pagehide")();
  assert.equal(appClipboardHas(), false);
  assert.equal(appClipboardText(), "");
  appClipboardPut("secret");
  stop();
  assert.equal(listeners.has("pagehide"), false);
  assert.equal(appClipboardText(), "secret", "removing the listener leaves the store alone");
}));
