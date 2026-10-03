// Revealed secrets must not stay on screen once the user has left the page:
// Windows Recall snapshots the screen, a screen share broadcasts it, and iOS
// saves the app-switcher picture to disk.
//
// Contract: the conceal callback runs when the window loses focus, when the
// page becomes hidden (not when it becomes visible), and when no key, click,
// touch or scroll has reached the page for the idle period; any of those
// inputs restarts the idle period. The page's own hiding (each view
// re-rendering masked, tabs off screen included) is covered in the browser
// suite.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { initConcealOnLeave } from "../src/js/conceal-on-leave.js";

const IDLE = 300000;
const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart"];

// A window and document that record listeners, with a clock the test turns.
function page() {
  const listeners = { win: new Map(), doc: new Map() };
  const timers = new Map();
  let now = 0, nextId = 1;
  const add = (target) => (type, listener, options) => listeners[target].set(type, { listener, options });
  const win = {
    addEventListener: add("win"),
    setTimeout: (fn, ms) => { timers.set(nextId, { fn, at: now + ms }); return nextId++; },
    clearTimeout: (id) => { timers.delete(id); },
  };
  const doc = { visibilityState: "visible", addEventListener: add("doc") };
  const advance = (ms) => {
    now += ms;
    for (const [id, timer] of [...timers]) {
      if (timer.at <= now) {
        timers.delete(id);
        timer.fn();
      }
    }
  };
  const fire = (target, type) => listeners[target].get(type).listener({ type });
  return { win, doc, listeners, advance, fire, pending: () => timers.size };
}

const start = () => {
  const p = page();
  let calls = 0;
  initConcealOnLeave({ conceal: () => { calls++; }, idleMs: IDLE, win: p.win, doc: p.doc });
  return { ...p, calls: () => calls };
};

test("losing focus conceals", () => {
  const p = start();
  p.fire("win", "blur");
  assert.equal(p.calls(), 1);
});

test("becoming hidden conceals, and becoming visible does not", () => {
  const p = start();
  p.doc.visibilityState = "visible";
  p.fire("doc", "visibilitychange");
  assert.equal(p.calls(), 0);
  p.doc.visibilityState = "hidden";
  p.fire("doc", "visibilitychange");
  assert.equal(p.calls(), 1);
});

test("an idle page conceals once the idle period has passed", () => {
  const p = start();
  p.advance(IDLE - 1);
  assert.equal(p.calls(), 0, "concealed before the idle period ended");
  p.advance(1);
  assert.equal(p.calls(), 1);
});

test("every kind of input restarts the idle period", () => {
  for (const type of ACTIVITY) {
    const p = start();
    const { options } = p.listeners.doc.get(type);
    assert.equal(options.capture, true, `${type} must be heard before a handler can stop it`);
    assert.equal(options.passive, true, `${type} must not hold up scrolling`);
    p.advance(IDLE - 1);
    p.fire("doc", type);
    assert.equal(p.pending(), 1, `${type} left more than one idle timer running`);
    p.advance(IDLE - 1);
    assert.equal(p.calls(), 0, `${type} did not restart the idle period`);
    p.advance(1);
    assert.equal(p.calls(), 1, `${type}: the restarted period never ended`);
  }
});
