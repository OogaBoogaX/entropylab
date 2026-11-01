import test from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { mountSecureDicePad } from "../src/js/secure-dice-pad.js";
import { rollsEntry, rollsPush, rollsUndo, rollAt } from "../src/js/secure-entry.js";

const find = (ctx, id) => ctx.host.querySelector(`#${id}`);
const click = (element) => element.dispatchEvent({ type: "click", target: element, preventDefault() {} });
const change = (element) => element.dispatchEvent({ type: "change", target: element, preventDefault() {} });
const input = (element) => element.dispatchEvent({ type: "input", target: element, preventDefault() {} });
const keydown = (element, key, extra = {}) => {
  const event = {
    type: "keydown",
    key,
    repeat: false,
    isComposing: false,
    ctrlKey: false,
    altKey: false,
    metaKey: false,
    preventDefault() { this.defaultPrevented = true; },
    ...extra,
  };
  element.dispatchEvent(event);
  return event;
};

const setup = (options = {}) => {
  const doc = new MiniDocument();
  doc.visibilityState = "visible";
  const host = doc.createElement("div");
  host.id = "secure-dice-host";
  const entry = options.entry || rollsEntry("coldcard", options.capacity || 6);
  const changes = [];
  const calls = { push: [], undo: [], rollAt: [] };
  const pad = mountSecureDicePad(host, {
    entry,
    rollsPush: (target, face) => {
      calls.push.push([target, face]);
      return rollsPush(target, face);
    },
    rollsUndo: (target) => {
      calls.undo.push(target);
      return rollsUndo(target);
    },
    rollAt: (target, index) => {
      calls.rollAt.push([target, index]);
      return rollAt(target, index);
    },
    labelledBy: options.labelledBy ?? "dice-label",
    translate: options.translate || ((text) => text),
    onChange: (state) => changes.push(state),
    doc,
  });
  return { doc, host, entry, changes, calls, pad };
};

test("mount refuses a seed entry and missing helpers", () => {
  const doc = new MiniDocument();
  const host = doc.createElement("div");
  assert.throws(() => mountSecureDicePad(host, {
    entry: { kind: "seed" },
    rollsPush,
    rollsUndo,
    rollAt,
    doc,
  }), /rolls entry/);
  assert.throws(() => mountSecureDicePad(host, {
    entry: rollsEntry("coldcard", 6),
    rollsPush,
    rollsUndo,
    doc,
  }), /helpers/);
});

test("six face buttons record one roll each", () => {
  const ctx = setup();
  const pad = find(ctx, "secure-dice-pad");
  assert.equal(pad.getAttribute("role"), "group");
  assert.equal(pad.getAttribute("aria-labelledby"), "dice-label");
  assert.equal(find(ctx, "secure-dice-status").getAttribute("data-roll-state"), "open");
  const buttons = ctx.host.querySelectorAll("[data-secure-roll]");
  assert.equal(buttons.length, 6);
  for (let i = 0; i < buttons.length; i += 1) {
    assert.equal(buttons[i].getAttribute("data-secure-roll"), String(i + 1));
    assert.equal(buttons[i].textContent, String(i + 1));
    assert.ok(buttons[i].getAttribute("aria-label").includes(String(i + 1)));
  }
  click(buttons[3]);
  assert.equal(ctx.calls.push.length, 1);
  assert.equal(ctx.calls.push[0][1], 4);
  assert.equal(ctx.entry.count, 1);
  assert.equal(ctx.entry.rolls[0], 4);
  assert.equal(find(ctx, "secure-dice-status").getAttribute("data-roll-count"), "1");
  assert.deepEqual(ctx.changes[0], { count: 1, capacity: 6, full: false });
});

test("keys 1-6 on the pad record, and other keys do not", () => {
  const ctx = setup();
  const pad = find(ctx, "secure-dice-pad");
  for (const extra of [{ repeat: true }, { isComposing: true }, { ctrlKey: true }, { altKey: true }, { metaKey: true }]) {
    const event = keydown(pad, "3", extra);
    assert.equal(ctx.entry.count, 0);
    if (extra.repeat) assert.equal(event.defaultPrevented, true);
  }
  const seven = keydown(pad, "7");
  assert.equal(ctx.entry.count, 0);
  assert.notEqual(seven.defaultPrevented, true);
  keydown(find(ctx, "secure-dice-review-position"), "3");
  assert.equal(ctx.entry.count, 0);
  const valid = keydown(pad, "3");
  assert.equal(ctx.entry.count, 1);
  assert.equal(ctx.entry.rolls[0], 3);
  assert.equal(valid.defaultPrevented, true);
});

test("undo removes the last roll and hides the actions at zero", () => {
  const ctx = setup();
  const undo = find(ctx, "secure-dice-undo");
  const reviewOpen = find(ctx, "secure-dice-review-open");
  assert.equal(undo.hidden, true);
  assert.equal(reviewOpen.hidden, true);
  click(ctx.host.querySelectorAll("[data-secure-roll]")[4]);
  assert.equal(ctx.entry.count, 1);
  assert.equal(undo.hidden, false);
  assert.equal(reviewOpen.hidden, false);
  click(undo);
  assert.equal(ctx.calls.undo.length, 1);
  assert.equal(ctx.entry.count, 0);
  assert.equal(ctx.entry.rolls[0], 0);
  assert.equal(undo.hidden, true);
  assert.equal(reviewOpen.hidden, true);
  assert.equal(find(ctx, "secure-dice-status").getAttribute("data-roll-count"), "0");
});

test("a full pad disables every face and refuses a fourth roll", () => {
  const ctx = setup({ entry: rollsEntry("coldcard", 3) });
  const buttons = ctx.host.querySelectorAll("[data-secure-roll]");
  click(buttons[0]);
  click(buttons[1]);
  click(buttons[2]);
  assert.equal(ctx.entry.count, 3);
  for (const button of buttons) assert.equal(button.disabled, true);
  const status = find(ctx, "secure-dice-status");
  assert.equal(status.getAttribute("data-roll-state"), "full");
  assert.equal(status.getAttribute("data-roll-count"), "3");
  const before = Array.from(ctx.entry.rolls);
  assert.doesNotThrow(() => click(buttons[3]));
  assert.equal(ctx.entry.count, 3);
  assert.deepEqual(Array.from(ctx.entry.rolls), before);
  assert.equal(ctx.calls.push.length, 3);
});

test("review shows one chosen roll and moves without keeping a face", () => {
  const ctx = setup();
  const buttons = ctx.host.querySelectorAll("[data-secure-roll]");
  for (const index of [0, 1, 2, 3]) click(buttons[index]);
  click(find(ctx, "secure-dice-review-open"));
  const review = find(ctx, "secure-dice-review");
  const pad = find(ctx, "secure-dice-pad");
  const undo = find(ctx, "secure-dice-undo");
  const reviewOpen = find(ctx, "secure-dice-review-open");
  const position = find(ctx, "secure-dice-review-position");
  const show = find(ctx, "secure-dice-review-show");
  const prev = find(ctx, "secure-dice-review-prev");
  const next = find(ctx, "secure-dice-review-next");
  assert.equal(review.hidden, false);
  assert.equal(pad.hidden, true);
  assert.equal(undo.hidden, true);
  assert.equal(reviewOpen.hidden, true);
  assert.equal(position.value, "4");
  assert.equal(position.getAttribute("max"), "4");
  assert.equal(prev.disabled, false);
  assert.equal(next.disabled, true);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);

  show.checked = true;
  change(show);
  const faces = ctx.host.querySelectorAll("[data-secure-dice-face]");
  assert.equal(faces.length, 1);
  assert.equal(faces[0].textContent, "4");
  assert.equal(faces[0].getAttribute("data-private-value"), "");
  assert.equal(faces[0].getAttribute("translate"), "no");
  assert.equal(faces[0].getAttribute("data-i18n-skip"), "");
  assert.equal(ctx.calls.rollAt.length, 1);
  assert.equal(ctx.calls.rollAt[0][1], 3);

  click(prev);
  assert.equal(position.value, "3");
  assert.equal(show.checked, false);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);
  assert.equal(ctx.calls.rollAt.length, 1);

  click(next);
  assert.equal(position.value, "4");
  assert.equal(show.checked, false);

  position.value = "2";
  input(position);
  assert.equal(position.value, "2");
  assert.equal(show.checked, false);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);

  // Anything that is not an integer in 1..count is ignored: the position
  // stays where it was, which the face still shows.
  for (const bad of ["0", "5", "abc", "1.5", ""]) {
    position.value = bad;
    input(position);
    show.checked = true;
    change(show);
    const face = ctx.host.querySelectorAll("[data-secure-dice-face]");
    assert.equal(face.length, 1);
    assert.equal(face[0].textContent, "2");
    show.checked = false;
    change(show);
  }

  click(prev);
  assert.equal(position.value, "1");
  assert.equal(prev.disabled, true);
  assert.equal(next.disabled, false);

  click(next);
  click(next);
  click(next);
  assert.equal(position.value, "4");
  assert.equal(next.disabled, true);

  show.checked = true;
  change(show);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 1);
  click(find(ctx, "secure-dice-review-close"));
  assert.equal(review.hidden, true);
  assert.equal(pad.hidden, false);
  assert.equal(undo.hidden, false);
  assert.equal(reviewOpen.hidden, false);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);
});

test("no transcript: the recorded sequence is never written as text", () => {
  const ctx = setup();
  const buttons = ctx.host.querySelectorAll("[data-secure-roll]");
  for (const button of buttons) click(button);
  assert.equal(ctx.entry.count, 6);
  const pad = find(ctx, "secure-dice-pad");
  const rest = ctx.host.textContent.replace(pad.textContent, "");
  assert.ok(!rest.includes("123456"));
  for (const element of [ctx.host, ...ctx.host.querySelectorAll("*")]) {
    for (const name of element.getAttributeNames()) {
      assert.ok(!String(element.getAttribute(name)).includes("123456"), `${name} on ${element.id || element.tagName}`);
    }
  }
  assert.equal(ctx.calls.rollAt.length, 0);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);
});

test("conceal removes a shown face and unchecks the box", () => {
  const ctx = setup();
  const buttons = ctx.host.querySelectorAll("[data-secure-roll]");
  click(buttons[0]);
  click(buttons[1]);
  click(find(ctx, "secure-dice-review-open"));
  const show = find(ctx, "secure-dice-review-show");
  show.checked = true;
  change(show);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 1);
  ctx.doc.dispatchEvent({ type: "hodl:conceal" });
  assert.equal(show.checked, false);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);

  show.checked = true;
  change(show);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 1);
  ctx.doc.visibilityState = "hidden";
  ctx.doc.dispatchEvent({ type: "visibilitychange" });
  assert.equal(show.checked, false);
  assert.equal(ctx.host.querySelectorAll("[data-secure-dice-face]").length, 0);
});

test("copy, cut and dragstart on the host are refused until destroy", () => {
  const ctx = setup();
  const clipboardEvent = (type) => {
    let prevented = false;
    return { type, cancelable: true, get defaultPrevented() { return prevented; }, preventDefault() { prevented = true; } };
  };
  for (const type of ["copy", "cut", "dragstart"]) {
    const event = clipboardEvent(type);
    ctx.host.dispatchEvent(event);
    assert.equal(event.defaultPrevented, true, `${type} on the host`);
  }
  ctx.pad.destroy();
  for (const type of ["copy", "cut", "dragstart"]) {
    const event = clipboardEvent(type);
    ctx.host.dispatchEvent(event);
    assert.equal(event.defaultPrevented, false, `${type} on the host after destroy`);
  }
});

test("destroy empties the host, drops its listeners and leaves the entry intact", () => {
  const ctx = setup();
  const buttons = ctx.host.querySelectorAll("[data-secure-roll]");
  click(buttons[0]);
  click(buttons[1]);
  click(find(ctx, "secure-dice-review-open"));
  const show = find(ctx, "secure-dice-review-show");
  show.checked = true;
  change(show);
  const before = Array.from(ctx.entry.rolls);
  ctx.pad.destroy();
  assert.equal(ctx.host.childNodes.length, 0);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 0);
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 0);
  assert.equal(ctx.host.listenerCount("copy"), 0);
  assert.equal(ctx.entry.count, 2);
  assert.deepEqual(Array.from(ctx.entry.rolls), before);
  assert.equal(ctx.entry.wiped, false);
});
