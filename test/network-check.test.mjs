// Tests for src/js/network-check.js using Node's built-in test runner.
// The module is a browser IIFE, so each test executes it inside a sandbox
// with stubbed document/navigator/window globals and asserts how it treats
// the #network-status tag.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const src = read("src/js/network-check.js");

const loadModule = ({ onLine, withConnectionApi = false, hasElement = true }) => {
  const el = {
    dataset: { state: "online" },
    textContent: "Online",
    attributes: {},
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
  };
  const listeners = {};
  const connectionListeners = {};
  const nav = { onLine };
  if (withConnectionApi) {
    nav.connection = { addEventListener: (type, fn) => { connectionListeners[type] = fn; } };
  }
  const sandbox = {
    document: { getElementById: (id) => (hasElement && id === "network-status" ? el : null) },
    navigator: nav,
    window: { addEventListener: (type, fn) => { listeners[type] = fn; } },
  };
  new Function(...Object.keys(sandbox), src)(...Object.values(sandbox));
  return { el, listeners, connectionListeners, nav };
};

test("never generates network traffic", () => {
  assert.doesNotMatch(src, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
});

// The tag's three faces move together, so each check reads all of them: a
// state the colour follows, the visible word, and the label screen readers get.
const assertOnline = (el) => {
  assert.equal(el.dataset.state, "online");
  assert.equal(el.textContent, "Online");
  assert.equal(el.attributes["aria-label"], "Network status: online");
};

const assertOffline = (el) => {
  assert.equal(el.dataset.state, "offline");
  assert.equal(el.textContent, "Offline");
  assert.equal(el.attributes["aria-label"], "Network status: offline");
};

test("reads online when a network adapter is available", () => {
  assertOnline(loadModule({ onLine: true }).el);
});

test("reads offline when no network adapter is available", () => {
  assertOffline(loadModule({ onLine: false }).el);
});

test("reads online when the online event fires", () => {
  const { el, listeners, nav } = loadModule({ onLine: false });
  assertOffline(el);
  nav.onLine = true;
  listeners.online();
  assertOnline(el);
});

test("reads offline when the offline event fires", () => {
  const { el, listeners, nav } = loadModule({ onLine: true });
  assertOnline(el);
  nav.onLine = false;
  listeners.offline();
  assertOffline(el);
});

test("re-checks when the Network Information API reports a change", () => {
  const { el, connectionListeners, nav } = loadModule({ onLine: true, withConnectionApi: true });
  assertOnline(el);
  assert.equal(typeof connectionListeners.change, "function");
  nav.onLine = false;
  connectionListeners.change();
  assertOffline(el);
});

test("works without the Network Information API (Firefox/Safari)", () => {
  assertOnline(loadModule({ onLine: true, withConnectionApi: false }).el);
});

test("never leaves a stale offline tag standing when the adapter returns", () => {
  // The dangerous direction: a tag still reading OFFLINE on a machine that has
  // come back online would vouch for an air gap that no longer exists.
  const { el, listeners, nav } = loadModule({ onLine: false });
  assertOffline(el);
  nav.onLine = true;
  listeners.online();
  assertOnline(el);
  nav.onLine = false;
  listeners.offline();
  assertOffline(el);
});

test("does not throw when the status tag is missing", () => {
  assert.doesNotThrow(() => loadModule({ onLine: true, hasElement: false }));
  assert.doesNotThrow(() => loadModule({ onLine: false, hasElement: false }));
});

test("the status tag ships online, sits in the header, and is wired to the build", () => {
  const template = read("src/index.html");
const shell = read("src/shell.html");
  const app = read("src/js/app.js");
  const build = read("scripts/build.mjs");
  const css = read("src/css/styles.css");
  const live = (markup) => markup.replace(/<!--[\s\S]*?-->/g, "");
  for (const markup of [shell]) {
    const doc = live(markup);
    const tag = doc.match(/<span[^>]*id="network-status"[^>]*>/)?.[0];
    assert.ok(tag, "the network status tag is missing from the live document");
    // Ships in the cautionary state: a script-less or not-yet-checked render
    // must never claim an air gap that nothing has verified.
    assert.match(tag, /data-state="online"/);
    assert.match(tag, /role="status"/);
    assert.match(doc, /id="network-status"[^>]*>Online</);
    // It belongs to the header, not the page body the banner used to sit in.
    const header = doc.indexOf('<div class="site-header no-print">');
    const wrapper = doc.indexOf('<div class="wrap">');
    const tagAt = doc.indexOf('id="network-status"');
    assert.ok(header < tagAt && tagAt < wrapper, "the status tag must sit inside the header");
    // The banner it replaced is gone from the live document; only the TODO
    // comment keeps its copy, for the modal that is to come.
    assert.doesNotMatch(doc, /id="network-warning"/);
    assert.match(markup, /TODO:[\s\S]*?air-gapped computer\." -->/);
  }
  assert.match(template, /\/\*@@JS_NETWORK@@\*\//);
  assert.match(build, /network-check\.js/);
  // Green when offline, bright red when online, carried by the text alone.
  assert.match(css, /\.network-status\[data-state="offline"\] \{ color: var\(--ok-bright\); \}/);
  assert.match(css, /\.network-status\[data-state="online"\] \{ color: var\(--danger-bright\); \}/);
  // Both themes have to define these, or one of them falls back to nothing.
  for (const token of ["--danger-bright", "--ok-bright"]) {
    assert.match(css, new RegExp(":root \\{[^}]*" + token + ":", "s"));
    assert.match(css, new RegExp(':root\\[data-theme="light"\\] \\{[^}]*' + token + ":", "s"));
  }
  // letter-spacing leaves a trailing gap after the last letter; the indent puts
  // a matching one in front so the word sits centred in its own box.
  assert.match(css, /\.network-status \{[^}]*letter-spacing: 0\.1em;[^}]*text-indent: 0\.1em;/s);
  // Transparent, but still 1px: the outline goes without the height moving.
  assert.match(css, /\.network-status \{[^}]*border: 1px solid transparent;[^}]*text-transform: uppercase;/s);
  // Half the tag's height is how far it rises above the rule, and the logo art
  // clears that by ~2px, so its height cannot be left to the font's metrics.
  assert.match(css, /\.network-status \{[^}]*line-height: 1;/s);
  // The bar's own rule follows the tag, off the same attribute, so the two can
  // never disagree about whether an adapter is live.
  assert.match(css, /\.site-header:has\(\.network-status\[data-state="online"\]\) \{ border-bottom-color: var\(--danger\); \}/);
  // Nothing repaints it for the offline state; it falls back to the grey.
  assert.match(css, /\.site-header \{[^}]*border-bottom: 1px solid var\(--border\);/s);
  // Left-aligned under the lockup, which needs the header row as its containing
  // block. Still derived from the bar's own padding token so the two cannot
  // drift, offset by the 3px the halo reaches past the label.
  assert.match(css, /\.network-status \{[^}]*position: absolute; left: calc\(var\(--site-header-pad\) \+ 3px\); bottom: 0; transform: translateY\(50%\);/s);
  assert.match(css, /\.site-header-inner \{\s*position: relative;/);
  // The tag's halo reaches up under the lockup, so the mark outranks it.
  assert.match(css, /\.site-logo \{[^}]*z-index: 2;/s);
  assert.match(css, /\.site-header-inner \{[^}]*padding: 0 var\(--site-header-pad\);/s);
  // Hung half over the bottom rule, with an opaque fill so the rule stops at
  // the tag's edges instead of striking through the word.
  assert.match(css, /\.network-status \{[^}]*background: var\(--bg\);/s);
  // It clears the control row, so it stays centred at every width and nothing
  // in the header has to be dropped to make room for it.
  const narrow = css.slice(css.indexOf("@media (max-width: 719px)"));
  assert.doesNotMatch(narrow, /\.network-status \{/);
  // The old banner's rules went with the banner.
  assert.doesNotMatch(css, /\.network-warning/);
});

test("CSP keeps connect-src locked down to 'none'", () => {
  const csp = read("src/index.html").match(/connect-src[^;"]*/)?.[0] ?? "";
  assert.equal(csp.trim(), "connect-src 'none'");
});
