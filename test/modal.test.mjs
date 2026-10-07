// The one modal shell (src/js/modal.js): every bundled modal builds its
// overlay through createModal, which owns dismissal, the focus trap and
// returning focus to whatever opened the modal.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const { createModal } = await import("../src/js/modal.js");

// Just enough DOM for the shell: one element type that records listeners,
// focus, and where it was appended.
const fakeDocument = () => {
  const focused = [];
  const element = (name) => {
    const listeners = {};
    return {
      name, hidden: false, className: "", id: "", innerHTML: "",
      addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
      fire(type, event) { for (const fn of listeners[type] ?? []) fn(event); },
      focus() { focused.push(name); document.activeElement = this; },
    };
  };
  const background = element("background");
  background.id = "btc-calc";
  background.inert = false;
  const body = { children: [background], append(node) { this.children.push(node); } };
  const document = { body, activeElement: null, createElement: () => element("overlay"), getElementById: (id) => id === "btc-calc" ? background : null };
  return { document, element, focused, background };
};
const withDocument = (fake, run) => {
  const saved = globalThis.document;
  globalThis.document = fake.document;
  try {
    return run();
  } finally {
    globalThis.document = saved;
  }
};

test("the shell builds one hidden overlay with the card, and show focuses and hide returns focus", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    let dismissed = 0;
    const modal = createModal({ id: "x-overlay", className: "x-overlay", card: "<div class=\"modal-card\"></div>", focusables: () => [], onDismiss: () => dismissed++ });
    assert.equal(fake.document.body.children.length, 2);
    assert.equal(modal.overlay.className, "modal-overlay x-overlay no-print");
    assert.equal(modal.overlay.id, "x-overlay");
    assert.equal(modal.overlay.innerHTML, "<div class=\"modal-card\"></div>");
    assert.equal(modal.isOpen(), false, "the overlay starts visible");
    const opener = fake.element("opener"), close = fake.element("close");
    modal.show(close, opener);
    assert.equal(modal.isOpen(), true);
    assert.equal(fake.background.inert, true, "the background remains interactive while a modal is open");
    assert.deepEqual(fake.focused, ["close"], "show did not focus the given control");
    modal.hide();
    assert.equal(modal.isOpen(), false);
    assert.equal(fake.background.inert, false, "closing the modal did not restore the background");
    assert.deepEqual(fake.focused, ["close", "opener"], "hide did not return focus to the opener");
    modal.show(close, opener);
    modal.hide({ restoreFocus: false });
    assert.deepEqual(fake.focused, ["close", "opener", "close"], "a teardown hide moved focus");
    assert.equal(dismissed, 0);
  });
});

test("show remembers whatever had focus when no opener is given", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const modal = createModal({ id: "y", className: "y", card: "", focusables: () => [], onDismiss() {} });
    const before = fake.element("before"), first = fake.element("first");
    before.focus();
    modal.show(first);
    modal.hide();
    assert.deepEqual(fake.focused, ["before", "first", "before"]);
  });
});

test("Escape and a click on the dimmed page dismiss; a click inside the card does not", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    let dismissed = 0;
    const modal = createModal({ id: "z", className: "z", card: "", focusables: () => [], onDismiss: () => dismissed++ });
    modal.overlay.fire("keydown", { key: "Escape" });
    modal.overlay.fire("keydown", { key: "Enter" });
    modal.overlay.fire("click", { target: modal.overlay });
    modal.overlay.fire("click", { target: { inside: true } });
    assert.equal(dismissed, 2);
  });
});

test("no module but modal.js builds a modal overlay or binds the focus trap", () => {
  const dir = join(root, "src/js");
  const offenders = [];
  for (const name of readdirSync(dir).filter((file) => file.endsWith(".js") && !["modal.js", "modal-focus.js"].includes(file))) {
    const source = readFileSync(join(dir, name), "utf8");
    if (/trapModalFocus\s*\(|className\s*=\s*["'`]modal-overlay/.test(source)) offenders.push(name);
  }
  assert.deepEqual(offenders, [], `modal plumbing outside modal.js: ${offenders.join(", ")}`);
});
