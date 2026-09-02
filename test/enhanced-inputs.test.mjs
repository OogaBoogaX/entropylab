// Custom select activation ordering, including the iOS WebKit tap path.
// Run with: node --test test/enhanced-inputs.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(rootDir, "..", "src/js/enhanced-inputs.js"), "utf8");

class FakeClassList {
  constructor() { this.values = new Set(); }
  add(value) { this.values.add(value); }
  remove(value) { this.values.delete(value); }
  contains(value) { return this.values.has(value); }
}

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.attributes = new Map();
    this.classList = new FakeClassList();
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.textContent = "";
    this.isConnected = true;
    this.ownerDocument = null;
  }
  append(...children) { this.children.push(...children); }
  after(node) { this.afterNode = node; }
  setAttribute(name, value = "") {
    this.attributes.set(name, String(value));
    if (name === "hidden") this.hidden = true;
  }
  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === "hidden") this.hidden = false;
  }
  replaceChildren(...children) { this.children = children; }
  matches(selector) { return selector === "select" && this.tagName === "SELECT"; }
  querySelectorAll(selector) {
    if (selector === "select") return [];
    if (selector === ".custom-select-option:not(:disabled)") return this.children.filter((child) => child.className === "custom-select-option" && !child.disabled);
    return [];
  }
  querySelector(selector) {
    if (selector === ".custom-select-button") return this.children.find((child) => child.className === "custom-select-button") || null;
    if (selector === ".custom-select-list") return this.children.find((child) => child.className === "custom-select-list") || null;
    if (selector === '[aria-selected="true"]:not(:disabled)') return this.children.find((child) => child.attributes.get("aria-selected") === "true" && !child.disabled) || null;
    if (selector === ".custom-select-option:not(:disabled)") return this.children.find((child) => child.className === "custom-select-option" && !child.disabled) || null;
    return null;
  }
  contains(target) { return target === this || this.children.some((child) => child.contains(target)); }
  focus(options) {
    this.focusOptions = options;
    if (this.ownerDocument) this.ownerDocument.activeElement = this;
  }
}

class FakeSelect extends FakeElement {
  constructor(options, value) {
    super("select");
    this.options = options;
    this.value = value;
    this.listeners = new Map();
  }
  get selectedIndex() { return Math.max(0, this.options.findIndex((option) => option.value === this.value)); }
  addEventListener(name, listener) {
    const listeners = this.listeners.get(name) || [];
    listeners.push(listener);
    this.listeners.set(name, listeners);
  }
  dispatchEvent(event) {
    for (const listener of this.listeners.get(event.type) || []) listener(event);
    return true;
  }
}

class FakeEvent {
  constructor(type, options = {}) { this.type = type; this.bubbles = Boolean(options.bubbles); }
}

class FakeMutationObserver {
  static instances = [];
  constructor(callback) {
    this.callback = callback;
    FakeMutationObserver.instances.push(this);
  }
  observe(target, options) {
    this.target = target;
    this.options = options;
  }
}

function makeHarness({ optionIcon } = {}) {
  const options = [
    { value: "mainnet", textContent: "Bitcoin mainnet", disabled: false, dataset: {} },
    { value: "testnet", textContent: "Testnet (practice)", disabled: false, dataset: {} },
  ];
  const select = new FakeSelect(options, "mainnet");
  const body = new FakeElement("body");
  const listeners = new Map();
  const document = {
    body,
    activeElement: null,
    createElement(tagName) {
      const element = new FakeElement(tagName);
      element.ownerDocument = document;
      return element;
    },
    createElementNS(_namespace, tagName) {
      return this.createElement(tagName);
    },
    querySelectorAll(selector) { return selector === "select" ? [select] : []; },
    addEventListener(name, listener) { listeners.set(name, [...(listeners.get(name) || []), listener]); },
    listeners,
  };
  select.ownerDocument = document;
  body.ownerDocument = document;
  if (optionIcon) select.entropylabOptionIcon = optionIcon;
  new Function("document", "Element", "MutationObserver", "Event", source)(document, FakeElement, FakeMutationObserver, FakeEvent);
  return { select, root: select.afterNode, document, body };
}

test("custom option finishes the tap before dispatching change", async () => {
  const { select, root } = makeHarness();
  const button = root.children[0];
  const list = root.children[1];
  const calls = [];
  select.addEventListener("change", (event) => calls.push(`change:${event.bubbles}`));
  const click = {
    preventDefault() { calls.push("preventDefault"); },
    stopPropagation() { calls.push("stopPropagation"); },
  };

  button.onclick();
  assert.equal(button.attributes.get("aria-expanded"), "true");
  assert.equal(list.hidden, false);
  list.children[1].onclick(click);

  assert.equal(select.value, "testnet");
  assert.equal(list.hidden, true);
  assert.equal(button.attributes.get("aria-expanded"), "false");
  assert.equal(button.children[0].textContent, "Testnet (practice)");
  assert.equal(list.children[0].attributes.get("aria-selected"), "false");
  assert.equal(list.children[1].attributes.get("aria-selected"), "true");
  assert.deepEqual(button.focusOptions, { preventScroll: true });
  assert.deepEqual(calls, ["preventDefault", "stopPropagation"]);

  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.deepEqual(calls, ["preventDefault", "stopPropagation", "change:true"]);
});

test("custom selects use the same stroked caret as the network picker", () => {
  const { root } = makeHarness();
  const caret = root.children[0].children[1];
  assert.equal(caret.tagName, "SVG");
  assert.equal(caret.attributes.get("class"), "custom-select-chevron");
  assert.equal(caret.attributes.get("viewBox"), "0 0 24 24");
  assert.equal(caret.children[0].tagName, "PATH");
  assert.equal(caret.children[0].attributes.get("d"), "m6 9 6 6 6-6");
  assert.doesNotMatch(source, /▼/);
});

test("deferred change is not sent to a select removed during activation", async () => {
  const { select, root } = makeHarness();
  const calls = [];
  select.addEventListener("change", () => calls.push("change"));

  root.children[1].children[1].onclick({ preventDefault() {}, stopPropagation() {} });
  select.isConnected = false;

  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.deepEqual(calls, []);
});

test("Enter, Space, and ArrowDown on the button open the list and focus the selection", () => {
  for (const key of ["Enter", " ", "ArrowDown"]) {
    const { root, document } = makeHarness();
    const button = root.children[0];
    const list = root.children[1];
    let prevented = 0;
    button.onkeydown({ key, preventDefault: () => (prevented += 1) });
    assert.equal(prevented, 1, key);
    assert.equal(list.hidden, false, key);
    assert.equal(button.attributes.get("aria-expanded"), "true", key);
    assert.equal(document.activeElement, list.children[0], `${key}: the selected option takes focus`);
  }
});

test("arrow keys move the highlight with clamping and Escape closes", () => {
  const { root, document } = makeHarness();
  const button = root.children[0];
  const list = root.children[1];
  button.onkeydown({ key: "ArrowDown", preventDefault() {} });
  assert.equal(document.activeElement, list.children[0]);
  list.onkeydown({ key: "ArrowDown", preventDefault() {} });
  assert.equal(document.activeElement, list.children[1]);
  list.onkeydown({ key: "ArrowDown", preventDefault() {} });
  assert.equal(document.activeElement, list.children[1], "clamped at the last option");
  list.onkeydown({ key: "ArrowUp", preventDefault() {} });
  assert.equal(document.activeElement, list.children[0]);
  list.onkeydown({ key: "ArrowUp", preventDefault() {} });
  assert.equal(document.activeElement, list.children[0], "clamped at the first option");
  list.onkeydown({ key: "Escape", preventDefault() {} });
  assert.equal(list.hidden, true);
  assert.equal(button.attributes.get("aria-expanded"), "false");
  assert.equal(document.activeElement, button, "Escape returns focus to the button");
});

test("the select's MutationObserver rebuilds the option list and skips the placeholder", () => {
  const { select, root } = makeHarness();
  const list = root.children[1];
  assert.equal(list.children.length, 2);
  select.options.push(
    { value: "signet", textContent: "Signet", disabled: false, dataset: {} },
    { value: "", textContent: "Choose a network", disabled: true, dataset: { customSelectPlaceholder: "true" } },
  );
  const observer = FakeMutationObserver.instances.find((instance) => instance.target === select);
  assert.ok(observer, "the enhancement observes its select");
  observer.callback();
  assert.equal(list.children.length, 3, "the placeholder option is not rendered as a choice");
  assert.equal(list.children[2].textContent, "Signet");
});

test("selects inserted into the document later are enhanced", () => {
  const { document, body } = makeHarness();
  const observer = FakeMutationObserver.instances.find((instance) => instance.target === body);
  assert.ok(observer, "the document body is observed for added nodes");
  assert.doesNotThrow(() => observer.callback([{ addedNodes: [null, {}] }]), "non-element nodes are skipped");
  const added = new FakeSelect([{ value: "a", textContent: "A", disabled: false, dataset: {} }], "a");
  added.ownerDocument = document;
  observer.callback([{ addedNodes: [added] }]);
  assert.ok(added.afterNode, "a custom-select root was inserted");
  assert.equal(added.afterNode.className, "custom-select");
  added.afterNode.children[0].onclick();
  assert.equal(added.afterNode.children[0].attributes.get("aria-expanded"), "true", "the new select is fully wired");
});

test("clicking outside an open custom select closes it", () => {
  const { root, document, body } = makeHarness();
  const button = root.children[0];
  const list = root.children[1];
  button.onclick();
  assert.equal(list.hidden, false);
  const clicks = document.listeners.get("click") || [];
  assert.ok(clicks.length > 0, "the document click listener is registered");
  for (const listener of clicks) listener({ target: list.children[0] });
  assert.equal(list.hidden, false, "a click inside the root keeps it open");
  for (const listener of clicks) listener({ target: button });
  assert.equal(list.hidden, false, "a click on the button is handled by the button");
  for (const listener of clicks) listener({ target: body });
  assert.equal(list.hidden, true, "a click outside closes the list");
  assert.equal(button.attributes.get("aria-expanded"), "false");
});

test("a select can put a mark ahead of every option label", () => {
  const asked = [];
  const { root } = makeHarness({
    optionIcon: (value) => {
      asked.push(value);
      const mark = new FakeElement("span");
      mark.className = `mark-${value}`;
      return mark;
    },
  });
  const label = root.children[0].children[0];
  const list = root.children[1];
  // The button shows the selected method's mark, then its name.
  assert.equal(label.className, "custom-select-value");
  assert.equal(label.children.length, 2, "the button label carries a mark and its text");
  assert.equal(label.children[0].className, "mark-mainnet");
  assert.equal(label.children[1].textContent, "Bitcoin mainnet");
  // So does each option in the list.
  assert.equal(list.children[0].children[0].className, "mark-mainnet");
  assert.equal(list.children[0].children[1].textContent, "Bitcoin mainnet");
  assert.equal(list.children[1].children[0].className, "mark-testnet");
  assert.ok(asked.includes("mainnet") && asked.includes("testnet"), "every option is offered a mark");
});

test("a select without the hook keeps its plain option text", () => {
  const { root } = makeHarness();
  const label = root.children[0].children[0];
  const list = root.children[1];
  assert.equal(label.textContent, "Bitcoin mainnet", "the label stays bare text");
  assert.equal(label.children.length, 0, "no wrapper is introduced without a mark");
  assert.equal(list.children[0].textContent, "Bitcoin mainnet");
  assert.equal(list.children[0].children.length, 0);
});
