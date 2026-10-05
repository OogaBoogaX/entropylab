// Contract: record only fixed, timestamped security events in page memory;
// report initial connectivity and real changes without making a connection,
// never accept arbitrary text, and discard the history on pagehide.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { initSecurityLog, SECURITY_LOG_LIMIT } from "../src/js/security-log.js";

const fixture = (...values) => {
  const onLine = values.length ? values[0] : true;
  const doc = new MiniDocument();
  doc.body.innerHTML = '<section id="security-log"><ol id="security-log-output"></ol></section>';
  const win = new EventTarget();
  const nav = { onLine, connection: new EventTarget() };
  let tick = 0;
  const log = initSecurityLog({ doc, win, nav, now: () => new Date(Date.UTC(2026, 9, 4, 12, 0, tick++)) });
  const output = doc.getElementById("security-log-output");
  const codes = () => output.children.map((row) => row.dataset.event);
  return { doc, win, nav, log, output, codes };
};

test("initial status is recorded for online, offline and unavailable browser reports", () => {
  for (const [value, code] of [[true, "network-online"], [false, "network-offline"], [undefined, "network-unknown"]]) {
    const { output, codes } = fixture(value);
    assert.deepEqual(codes(), ["session-started", code]);
    for (const row of output.children) {
      assert.ok(row.querySelector("time").getAttribute("datetime"));
      assert.ok(row.querySelector("[data-security-message]").textContent);
    }
    assert.equal(output.children[1].dataset.level, value === false ? "info" : "warning");
    if (value === false) assert.match(output.textContent, /air gap/i);
  }
});

test("connectivity transitions append in order, repeated notifications do not", () => {
  const { win, nav, output, codes } = fixture();
  win.dispatchEvent(new Event("online"));
  nav.connection.dispatchEvent(new Event("change"));
  assert.equal(output.children.length, 2);
  nav.onLine = false;
  win.dispatchEvent(new Event("offline"));
  nav.onLine = true;
  nav.connection.dispatchEvent(new Event("change"));
  assert.deepEqual(codes(), ["session-started", "network-online", "network-offline", "network-online"]);
  const times = output.children.map((row) => row.querySelector("time").getAttribute("datetime"));
  assert.deepEqual(times, [...times].sort());
});

test("only known events are accepted and no supplied secret can become log text", () => {
  const { log, output, codes } = fixture();
  const secret = "xprv-this-must-never-be-recorded";
  for (const input of [secret, { code: "page-translated", message: secret }, undefined, "toString", "__proto__"]) {
    assert.equal(log.record(input), false);
  }
  assert.equal(log.record("page-translated", secret), true);
  assert.equal(output.textContent.includes(secret), false);
  assert.equal(codes().at(-1), "page-translated");
  assert.equal(output.children.at(-1).dataset.level, "warning");
});

test("history is bounded and evicts the oldest rows", () => {
  const { log, output, codes } = fixture();
  for (let n = 0; n < SECURITY_LOG_LIMIT + 10; n++) log.record("page-translated");
  assert.equal(output.children.length, SECURITY_LOG_LIMIT);
  assert.ok(codes().every((code) => code === "page-translated"));
});

test("pagehide clears the log, stopped sessions reject events, and bfcache starts fresh", () => {
  const { log, win, nav, output, codes } = fixture();
  log.record("page-translated");
  win.dispatchEvent(new Event("pagehide"));
  assert.equal(output.children.length, 0);
  assert.equal(log.record("page-translated"), false);
  nav.onLine = false;
  win.dispatchEvent(new Event("offline"));
  assert.equal(output.children.length, 0);
  const restored = new Event("pageshow");
  Object.defineProperty(restored, "persisted", { value: true });
  win.dispatchEvent(restored);
  assert.deepEqual(codes(), ["session-started", "network-offline"]);
});

test("refresh preserves event order and timestamps and absent markup is harmless", () => {
  const { log, output } = fixture();
  const original = output.textContent;
  log.refresh();
  assert.equal(output.textContent, original);
  assert.equal(initSecurityLog({ doc: new MiniDocument(), win: new EventTarget(), nav: {} }), null);
});

test("restoring a page retains a latched translation warning in the new history", () => {
  const { doc, win, codes } = fixture();
  doc.body.append(doc.createElement("aside"));
  const warning = doc.body.children.at(-1);
  warning.id = "translated-warning";
  warning.hidden = false;
  win.dispatchEvent(new Event("pagehide"));
  const restored = new Event("pageshow");
  Object.defineProperty(restored, "persisted", { value: true });
  win.dispatchEvent(restored);
  assert.deepEqual(codes(), ["session-started", "network-online", "page-translated"]);
});
