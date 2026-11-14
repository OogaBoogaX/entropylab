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
const { isUsableFocusable, isUsableOpener } = await import("../src/js/modal-focus.js");

// Just enough DOM for the shell: one element type that records listeners,
// focus, attributes and where it was appended. `innerHTML` keeps the markup
// string and gives the overlay a card root carrying that markup's attributes,
// so the shell can put role/aria-modal on it and focus it.
const fakeDocument = () => {
  const focused = [];
  const element = (name) => {
    const listeners = {};
    const node = {
      name, hidden: false, className: "", id: "", inert: false, disabled: false,
      isConnected: true, parentElement: null, children: [], attributes: {},
      _innerHTML: "",
      get innerHTML() { return this._innerHTML; },
      set innerHTML(value) {
        this._innerHTML = value;
        this.children = [];
        const card = element("card");
        card.parentElement = this;
        const tag = /<[a-zA-Z][^<>]*>/.exec(value)?.[0] ?? "";
        for (const [, attribute, attributeValue] of tag.matchAll(/([a-zA-Z-]+)="([^"]*)"/g)) card.setAttribute(attribute, attributeValue);
        this.children.push(card);
      },
      get firstElementChild() { return this.children[0] ?? null; },
      append(...nodes) { for (const child of nodes) { child.parentElement = this; this.children.push(child); } },
      setAttribute(attribute, value) { this.attributes[attribute] = String(value); },
      getAttribute(attribute) { return Object.hasOwn(this.attributes, attribute) ? this.attributes[attribute] : null; },
      hasAttribute(attribute) { return Object.hasOwn(this.attributes, attribute); },
      removeAttribute(attribute) { delete this.attributes[attribute]; },
      closest(selector) {
        if (selector === "[hidden]") {
          for (let current = this; current; current = current.parentElement) if (current.hidden) return current;
          return null;
        }
        if (selector === "[inert]") {
          for (let current = this; current; current = current.parentElement) if (current.inert) return current;
          return null;
        }
        return null;
      },
      addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
      fire(type, event) { for (const fn of listeners[type] ?? []) fn(event); },
      focus() { focused.push(this.name); document.activeElement = this; },
    };
    return node;
  };
  const body = element("body");
  const document = { body, activeElement: null, createElement: () => element("overlay") };
  return { document, element, focused };
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
    assert.equal(fake.document.body.children.length, 1);
    assert.equal(modal.overlay.className, "modal-overlay x-overlay no-print");
    assert.equal(modal.overlay.id, "x-overlay");
    assert.equal(modal.overlay.innerHTML, "<div class=\"modal-card\"></div>");
    assert.equal(modal.isOpen(), false, "the overlay starts visible");
    const opener = fake.element("opener"), close = fake.element("close");
    modal.overlay.append(close);
    modal.show(close, opener);
    assert.equal(modal.isOpen(), true);
    assert.deepEqual(fake.focused, ["close"], "show did not focus the given control");
    modal.hide();
    assert.equal(modal.isOpen(), false);
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
    modal.overlay.append(first);
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

test("show makes the page behind inert and hide restores exactly what it changed", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const main = fake.element("main"), alreadyInert = fake.element("already-inert"), alreadyHidden = fake.element("already-hidden");
    alreadyInert.inert = true;
    alreadyHidden.setAttribute("aria-hidden", "false");
    fake.document.body.append(main, alreadyInert, alreadyHidden);
    const modal = createModal({ id: "inert", className: "inert", card: "", focusables: () => [], onDismiss() {} });
    modal.show();
    assert.equal(main.inert, true);
    assert.equal(main.getAttribute("aria-hidden"), "true");
    assert.equal(alreadyInert.inert, true);
    assert.equal(alreadyInert.getAttribute("aria-hidden"), "true", "an already-inert element still gets aria-hidden");
    assert.equal(alreadyHidden.getAttribute("aria-hidden"), "true", "the page behind the modal is hidden from assistive tech");
    assert.equal(modal.overlay.inert, false, "the overlay itself is never made inert");
    modal.hide();
    assert.equal(main.inert, false);
    assert.equal(main.hasAttribute("aria-hidden"), false);
    assert.equal(alreadyInert.inert, true, "an element inert before show stays inert");
    assert.equal(alreadyInert.hasAttribute("aria-hidden"), false, "the aria-hidden this modal added is removed");
    assert.equal(alreadyHidden.getAttribute("aria-hidden"), "false");
  });
});

test("show twice without hide does not record the overlay or double-record", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const main = fake.element("main");
    fake.document.body.append(main);
    const modal = createModal({ id: "twice", className: "twice", card: "", focusables: () => [], onDismiss() {} });
    modal.show();
    modal.show();
    assert.equal(modal.overlay.inert, false, "the overlay is never made inert");
    assert.equal(modal.overlay.hasAttribute("aria-hidden"), false);
    modal.hide();
    assert.equal(main.inert, false, "one hide restores the page");
    assert.equal(main.hasAttribute("aria-hidden"), false);
    modal.hide();
    assert.equal(main.inert, false, "a second hide does nothing");
  });
});

test("nested modals: the inner hide leaves the outer usable and the page inert", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const main = fake.element("main");
    fake.document.body.append(main);
    const outer = createModal({ id: "outer", className: "outer", card: "", focusables: () => [], onDismiss() {} });
    const inner = createModal({ id: "inner", className: "inner", card: "", focusables: () => [], onDismiss() {} });
    outer.show();
    assert.equal(main.inert, true);
    inner.show();
    assert.equal(outer.overlay.inert, true, "the outer overlay is inert while the inner is open");
    assert.equal(main.inert, true);
    inner.hide();
    assert.equal(outer.overlay.inert, false, "the outer overlay is usable again");
    assert.equal(outer.overlay.hasAttribute("aria-hidden"), false);
    assert.equal(main.inert, true, "the page is still inert behind the outer modal");
    outer.hide();
    assert.equal(main.inert, false);
    assert.equal(main.hasAttribute("aria-hidden"), false);
  });
});

test("closing the outer modal first leaves the inner modal live and the page inert", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const main = fake.element("main");
    fake.document.body.append(main);
    const outer = createModal({ id: "outer-first", className: "outer-first", card: "", focusables: () => [], onDismiss() {} });
    const inner = createModal({ id: "inner-first", className: "inner-first", card: "", focusables: () => [], onDismiss() {} });
    const outerOpener = fake.element("outer-opener"), innerOpener = fake.element("inner-opener");
    fake.document.body.append(outerOpener, innerOpener);
    outer.show(undefined, outerOpener);
    inner.show(undefined, innerOpener);
    fake.focused.length = 0;
    outer.hide();
    assert.equal(main.inert, true, "the page is still inert behind the inner modal");
    assert.equal(main.getAttribute("aria-hidden"), "true");
    assert.equal(inner.overlay.inert, false, "the inner overlay is live");
    assert.equal(inner.overlay.hasAttribute("aria-hidden"), false);
    assert.deepEqual(fake.focused, [], "focus did not move to the outer opener");
    inner.hide();
    assert.equal(main.inert, false);
    assert.equal(main.hasAttribute("aria-hidden"), false);
    assert.deepEqual(fake.focused, ["inner-opener"], "focus returned to the inner opener");
  });
});

test("three modals closed out of order restore the page exactly", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const main = fake.element("main"), preInert = fake.element("pre-inert"), preHidden = fake.element("pre-hidden");
    preInert.inert = true;
    preHidden.setAttribute("aria-hidden", "false");
    fake.document.body.append(main, preInert, preHidden);
    const first = createModal({ id: "stack-a", className: "stack-a", card: "", focusables: () => [], onDismiss() {} });
    const second = createModal({ id: "stack-b", className: "stack-b", card: "", focusables: () => [], onDismiss() {} });
    const third = createModal({ id: "stack-c", className: "stack-c", card: "", focusables: () => [], onDismiss() {} });
    first.show();
    second.show();
    third.show();
    second.hide();
    assert.equal(third.overlay.inert, false, "the top modal stays live");
    assert.equal(first.overlay.inert, true, "a modal below the top is inert");
    assert.equal(main.inert, true);
    first.hide();
    assert.equal(third.overlay.inert, false, "the top modal stays live");
    assert.equal(main.inert, true, "the page is still inert behind the top modal");
    third.hide();
    assert.equal(main.inert, false);
    assert.equal(main.hasAttribute("aria-hidden"), false);
    assert.equal(preInert.inert, true, "an element inert before any modal stays inert");
    assert.equal(preInert.hasAttribute("aria-hidden"), false);
    assert.equal(preHidden.inert, false);
    assert.equal(preHidden.getAttribute("aria-hidden"), "false", "an existing aria-hidden value is restored");
  });
});

test("show twice keeps the opener remembered by the first show", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const modal = createModal({ id: "double", className: "double", card: "", focusables: () => [], onDismiss() {} });
    const first = fake.element("first-opener"), second = fake.element("second-opener");
    fake.document.body.append(first, second);
    modal.show(undefined, first);
    modal.show(undefined, second);
    fake.focused.length = 0;
    modal.hide();
    assert.deepEqual(fake.focused, ["first-opener"], "the opener remembered at the first show is used");
  });
});

test("the usable-element filter refuses controls outside the overlay and unrendered ones", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const overlay = fake.element("overlay"), card = fake.element("card");
    card.parentElement = overlay;
    const inside = fake.element("inside"), outside = fake.element("outside");
    inside.parentElement = card;
    const unrendered = fake.element("unrendered");
    unrendered.parentElement = card;
    unrendered.getClientRects = () => [];
    const rendered = fake.element("rendered");
    rendered.parentElement = card;
    rendered.getClientRects = () => [{ width: 10, height: 10 }];
    assert.equal(isUsableFocusable(inside, overlay), true);
    assert.equal(isUsableFocusable(outside, overlay), false, "an element outside the overlay is not reachable from it");
    assert.equal(isUsableFocusable(unrendered, overlay), false, "an element with no client rects is not rendered");
    assert.equal(isUsableFocusable(rendered, overlay), true);
  });
});

test("the opener check refuses inert subtrees and disconnected elements", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const inertAncestor = fake.element("inert-ancestor");
    inertAncestor.inert = true;
    const insideInert = fake.element("inside-inert");
    insideInert.parentElement = inertAncestor;
    const plain = fake.element("plain");
    const gone = fake.element("gone");
    gone.isConnected = false;
    const noClosest = { isConnected: true, disabled: false, focus() {}, parentElement: { inert: true } };
    assert.equal(isUsableOpener(insideInert), false, "an opener inside an inert subtree is not usable");
    assert.equal(isUsableOpener(noClosest), false, "the fallback walk finds an inert ancestor");
    assert.equal(isUsableOpener(plain), true);
    assert.equal(isUsableOpener(gone), false, "a disconnected opener is not usable");
    assert.equal(isUsableOpener(null), false);
  });
});

test("initial focus falls back to the first usable control, then to the card root", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const first = fake.element("first"), second = fake.element("second");
    const modal = createModal({ id: "focus", className: "focus", card: "", focusables: () => [first, second], onDismiss() {} });
    modal.overlay.append(first, second);
    modal.show();
    assert.deepEqual(fake.focused, ["first"], "no focus given: the first usable control takes it");
    modal.hide();
    fake.focused.length = 0;
    const disabled = fake.element("disabled");
    disabled.disabled = true;
    modal.show(disabled);
    assert.deepEqual(fake.focused, ["first"], "a disabled focus is skipped");
    modal.hide();
    fake.focused.length = 0;
    const hidden = fake.element("hidden");
    hidden.hidden = true;
    modal.show(hidden);
    assert.deepEqual(fake.focused, ["first"], "a hidden focus is skipped");
    modal.hide();
    fake.focused.length = 0;
    const gone = fake.element("gone");
    gone.isConnected = false;
    modal.show(gone);
    assert.deepEqual(fake.focused, ["first"], "a disconnected focus is skipped");
    modal.hide();
    fake.focused.length = 0;
    const noFocus = { name: "no-focus", hidden: false, disabled: false, isConnected: true, parentElement: null };
    modal.show(noFocus);
    assert.deepEqual(fake.focused, ["first"], "a focus without a focus method is skipped");
    modal.hide();
    fake.focused.length = 0;
    const empty = createModal({ id: "focus-empty", className: "focus-empty", card: "", focusables: () => [], onDismiss() {} });
    empty.show();
    assert.deepEqual(fake.focused, ["card"], "no controls: the card root takes focus");
    assert.equal(empty.overlay.firstElementChild.getAttribute("tabindex"), "-1");
    empty.hide({ restoreFocus: false });
  });
});

test("the trap skips disabled and hidden controls, and keeps focus on the card when there are none", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const first = fake.element("first"), disabled = fake.element("disabled"), hidden = fake.element("hidden");
    disabled.disabled = true;
    hidden.hidden = true;
    const modal = createModal({ id: "trap", className: "trap", card: "", focusables: () => [first, disabled, hidden], onDismiss() {} });
    modal.overlay.append(first, disabled, hidden);
    modal.show(first);
    fake.focused.length = 0;
    let prevented = 0;
    modal.overlay.fire("keydown", { key: "Tab", shiftKey: false, preventDefault: () => { prevented += 1; } });
    assert.deepEqual(fake.focused, ["first"], "Tab cycles to the only usable control");
    assert.equal(prevented, 1);
    const empty = createModal({ id: "trap-empty", className: "trap-empty", card: "", focusables: () => [], onDismiss() {} });
    empty.show();
    fake.focused.length = 0;
    let preventedEmpty = 0;
    empty.overlay.fire("keydown", { key: "Tab", shiftKey: false, preventDefault: () => { preventedEmpty += 1; } });
    assert.deepEqual(fake.focused, ["card"], "with no controls focus stays on the card root");
    assert.equal(preventedEmpty, 1);
    empty.hide({ restoreFocus: false });
    modal.hide({ restoreFocus: false });
  });
});

test("the usable-element filter drops disconnected, disabled and hidden controls", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const overlay = fake.element("overlay"), card = fake.element("card");
    card.parentElement = overlay;
    const ok = fake.element("ok"), disabled = fake.element("disabled"), hidden = fake.element("hidden"), gone = fake.element("gone"), nested = fake.element("nested");
    ok.parentElement = card;
    disabled.parentElement = card;
    disabled.disabled = true;
    hidden.parentElement = card;
    hidden.hidden = true;
    gone.parentElement = card;
    gone.isConnected = false;
    nested.parentElement = hidden;
    assert.equal(isUsableFocusable(ok, overlay), true);
    assert.equal(isUsableFocusable(disabled, overlay), false);
    assert.equal(isUsableFocusable(hidden, overlay), false);
    assert.equal(isUsableFocusable(gone, overlay), false);
    assert.equal(isUsableFocusable(nested, overlay), false, "an ancestor's hidden attribute hides the control");
    assert.equal(isUsableFocusable(null, overlay), false);
  });
});

test("hide does not return focus to a removed or disabled opener", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const modal = createModal({ id: "return", className: "return", card: "", focusables: () => [], onDismiss() {} });
    const removed = fake.element("removed"), disabled = fake.element("disabled");
    modal.show(undefined, removed);
    removed.isConnected = false;
    fake.focused.length = 0;
    assert.doesNotThrow(() => modal.hide());
    assert.deepEqual(fake.focused, [], "focus was not moved to a removed opener");
    modal.show(undefined, disabled);
    disabled.disabled = true;
    fake.focused.length = 0;
    assert.doesNotThrow(() => modal.hide());
    assert.deepEqual(fake.focused, [], "focus was not moved to a disabled opener");
  });
});

test("the card root gets dialog semantics without overriding a caller's role", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const plain = createModal({ id: "plain", className: "plain", card: "<div class=\"modal-card\"></div>", focusables: () => [], onDismiss() {} });
    assert.equal(plain.overlay.firstElementChild.getAttribute("role"), "dialog");
    assert.equal(plain.overlay.firstElementChild.getAttribute("aria-modal"), "true");
    const alert = createModal({ id: "alert", className: "alert", card: "<div class=\"modal-card\" role=\"alertdialog\" aria-modal=\"true\"></div>", focusables: () => [], onDismiss() {} });
    assert.equal(alert.overlay.firstElementChild.getAttribute("role"), "alertdialog");
    assert.equal(alert.overlay.firstElementChild.getAttribute("aria-modal"), "true");
  });
});

test("Escape during an IME composition does not dismiss", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    let dismissed = 0;
    const modal = createModal({ id: "compose", className: "compose", card: "", focusables: () => [], onDismiss: () => dismissed++ });
    modal.overlay.fire("keydown", { key: "Escape", isComposing: true });
    assert.equal(dismissed, 0, "an IME composition's Escape cancelled the dialog");
    modal.overlay.fire("keydown", { key: "Escape", isComposing: false });
    assert.equal(dismissed, 1);
  });
});

test("an overlay removed from the page without hide() does not keep the page inert", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    const main = fake.element("main");
    fake.document.body.append(main);
    const gone = createModal({ id: "gone", className: "gone", card: "", focusables: () => [], onDismiss() {} });
    gone.show();
    assert.equal(main.inert, true);
    // A teardown removes the overlay without calling hide().
    fake.document.body.children.splice(fake.document.body.children.indexOf(gone.overlay), 1);
    gone.overlay.isConnected = false;
    const next = createModal({ id: "next", className: "next", card: "", focusables: () => [], onDismiss() {} });
    next.show();
    assert.equal(next.overlay.inert, false, "the new modal is live, not stuck under the removed one");
    next.hide();
    assert.equal(main.inert, false, "the page is restored once the last live modal closes");
    assert.equal(main.hasAttribute("aria-hidden"), false);
  });
});

test("Escape reported as keyCode 229 (an IME ending a composition) does not dismiss", () => {
  const fake = fakeDocument();
  withDocument(fake, () => {
    let dismissed = 0;
    const modal = createModal({ id: "ime229", className: "ime229", card: "", focusables: () => [], onDismiss: () => dismissed++ });
    modal.overlay.fire("keydown", { key: "Escape", isComposing: false, keyCode: 229 });
    assert.equal(dismissed, 0);
    modal.overlay.fire("keydown", { key: "Escape", isComposing: false, keyCode: 27 });
    assert.equal(dismissed, 1);
  });
});

test("every bundled caller names its dialog", () => {
  const dir = join(root, "src/js");
  const unnamed = [];
  for (const name of readdirSync(dir).filter((file) => file.endsWith(".js"))) {
    const source = readFileSync(join(dir, name), "utf8");
    if (!/from\s+["'][^"']*modal\.js["']/.test(source)) continue;
    const tags = source.match(/<[a-zA-Z][^<>]*>/g) ?? [];
    const cardTags = tags.filter((tag) => /class\s*=\s*["'][^"']*\bmodal-card\b/.test(tag));
    if (!cardTags.some((tag) => /aria-(?:labelledby|label)\s*=/.test(tag))) unnamed.push(name);
  }
  assert.deepEqual(unnamed, [], `modal cards without an accessible name: ${unnamed.join(", ")}`);
});
