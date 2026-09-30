// A small DOM for tests that run the app's own rendering and click code
// without a browser (the repo has no DOM library, and takes no new
// dependencies). It models what a real element does that the copy-button
// tests depend on:
//   - `dataset` and `title`/`disabled`/`className` are views of attributes, so
//     a secret written through `dataset.x = ...` shows up as a `data-x`
//     attribute, exactly as in a browser;
//   - an element's own JS properties are only the ones page code added (an
//     `onclick`, a timer id), so a test can enumerate them;
//   - `innerHTML` parses markup, so the app's own row and station templates
//     build the fixture;
//   - a disabled button does not click;
//   - `document.createTreeWalker` walks text nodes, so the app's own
//     translation sweep (i18n.js) runs over the fixture;
//   - a select reports its options, selected index and value, so the custom
//     select (enhanced-inputs.js) can mirror one;
//   - listeners added to an element or the document are recorded (never
//     dispatched), so a test can count what a re-render leaves behind.
// Selectors: tag, #id, .class, [attr], [attr=value], compounds, descendant
// chains and comma lists. Anything else throws, so an unsupported selector
// fails loudly rather than matching nothing.
const state = new WeakMap();
const me = (node) => state.get(node);
// Listeners are recorded on elements and on the document, so a test can count
// what a re-render leaves registered; held by their target, as in a browser, a
// listener keeps what it holds alive exactly as long as the target lives.
const listeners = new WeakMap();
function addListener(target, type, listener) {
  if (!listeners.has(target)) listeners.set(target, new Map());
  const byType = listeners.get(target);
  if (!byType.has(type)) byType.set(type, new Set());
  byType.get(type).add(listener);
}
const removeListener = (target, type, listener) => listeners.get(target)?.get(type)?.delete(listener);
const countListeners = (target, type) => listeners.get(target)?.get(type)?.size ?? 0;
const camel = (name) => name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
const dataName = (key) => "data-" + key.replace(/[A-Z]/g, (letter) => "-" + letter.toLowerCase());
const VOID = new Set(["img", "input", "br", "hr", "meta", "link"]);
const unescapeText = (text) => text.replace(/&(amp|lt|gt|quot|#39|apos);/g, (_, name) => ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", apos: "'" })[name]);

function parseSelector(text) {
  return text.split(",").map((part) => part.trim().split(/\s+/).map((compound) => {
    const parsed = { tag: null, id: null, classes: [], attrs: [], checked: false };
    let rest = compound;
    while (rest) {
      let match;
      if ((match = rest.match(/^#([\w-]+)/))) parsed.id = match[1];
      else if ((match = rest.match(/^\.([\w-]+)/))) parsed.classes.push(match[1]);
      else if ((match = rest.match(/^\[([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/))) parsed.attrs.push([match[1], match[2] ?? match[3] ?? match[4] ?? null]);
      else if ((match = rest.match(/^:checked/))) parsed.checked = true;
      else if ((match = rest.match(/^([a-zA-Z][\w-]*|\*)/))) parsed.tag = match[1] === "*" ? null : match[1].toLowerCase();
      else throw new Error(`mini-dom: unsupported selector "${text}"`);
      rest = rest.slice(match[0].length);
    }
    return parsed;
  }));
}
function matchesCompound(element, compound) {
  const own = me(element);
  if (compound.tag && own.tag !== compound.tag) return false;
  if (compound.id !== null && own.attrs.get("id") !== compound.id) return false;
  const classes = (own.attrs.get("class") || "").split(/\s+/);
  if (!compound.classes.every((name) => classes.includes(name))) return false;
  if (compound.checked && !(element.checked ?? own.attrs.has("checked"))) return false;
  return compound.attrs.every(([name, value]) => own.attrs.has(name) && (value === null || own.attrs.get(name) === value));
}
function matchesChain(element, chain, index) {
  if (!matchesCompound(element, chain[index])) return false;
  if (index === 0) return true;
  for (let ancestor = me(element).parent; ancestor instanceof MiniElement; ancestor = me(ancestor).parent) if (matchesChain(ancestor, chain, index - 1)) return true;
  return false;
}
const matchesSelector = (element, selector) => parseSelector(selector).some((chain) => matchesChain(element, chain, chain.length - 1));

export class MiniText {
  constructor(data) {
    this.nodeType = 3;
    this.data = String(data);
    state.set(this, { parent: null });
  }
  get textContent() { return this.data; }
  get nodeValue() { return this.data; }
  set nodeValue(value) { this.data = String(value); }
  get parentNode() { return me(this).parent; }
  get parentElement() { return me(this).parent instanceof MiniElement ? me(this).parent : null; }
}

function adopt(parent, node) {
  const own = me(node);
  if (own.parent) me(own.parent).kids.splice(me(own.parent).kids.indexOf(node), 1);
  own.parent = parent;
  me(parent).kids.push(node);
}
function insert(parent, nodes) {
  for (const node of nodes) {
    if (node instanceof MiniFragment) for (const kid of [...me(node).kids]) adopt(parent, kid);
    else adopt(parent, typeof node === "string" ? new MiniText(node) : node);
  }
}
function clear(parent) {
  for (const kid of me(parent).kids) me(kid).parent = null;
  me(parent).kids = [];
}
const textOf = (node) => node instanceof MiniText ? node.data : me(node).kids.map(textOf).join("");

export class MiniFragment {
  constructor(ownerDocument) {
    this.nodeType = 11;
    state.set(this, { doc: ownerDocument, kids: [], parent: null });
  }
  appendChild(node) { insert(this, [node]); return node; }
  append(...nodes) { insert(this, nodes); }
}

export class MiniElement {
  constructor(tagName, ownerDocument) {
    this.nodeType = 1;
    state.set(this, { tag: String(tagName).toLowerCase(), doc: ownerDocument, attrs: new Map(), kids: [], parent: null, value: "", style: { setProperty() {}, removeProperty() {}, getPropertyValue() { return ""; } } });
  }
  get tagName() { return me(this).tag.toUpperCase(); }
  get ownerDocument() { return me(this).doc; }
  get parentNode() { return me(this).parent; }
  get parentElement() { return me(this).parent instanceof MiniElement ? me(this).parent : null; }
  get childNodes() { return [...me(this).kids]; }
  get children() { return me(this).kids.filter((kid) => kid instanceof MiniElement); }
  get firstChild() { return me(this).kids[0] || null; }
  get isConnected() {
    let node = this;
    while (node instanceof MiniElement) node = me(node).parent;
    return node === me(this).doc;
  }
  get textContent() { return textOf(this); }
  set textContent(value) {
    clear(this);
    if (String(value) !== "") insert(this, [String(value)]);
  }
  get innerHTML() { return me(this).kids.map((kid) => kid instanceof MiniText ? kid.data : kid.outerHTML).join(""); }
  set innerHTML(html) {
    clear(this);
    insert(this, [parseHtml(me(this).doc, String(html))]);
  }
  get outerHTML() {
    const own = me(this), attrs = [...own.attrs].map(([name, value]) => ` ${name}="${value}"`).join("");
    return `<${own.tag}${attrs}>${this.innerHTML}</${own.tag}>`;
  }
  appendChild(node) { insert(this, [node]); return node; }
  append(...nodes) { insert(this, nodes); }
  replaceChildren(...nodes) {
    clear(this);
    insert(this, nodes);
  }
  remove() {
    const own = me(this);
    if (!own.parent) return;
    me(own.parent).kids.splice(me(own.parent).kids.indexOf(this), 1);
    own.parent = null;
  }
  after(...nodes) {
    const parent = me(this).parent;
    if (!parent) return;
    let at = me(parent).kids.indexOf(this) + 1;
    for (const node of nodes) {
      const child = typeof node === "string" ? new MiniText(node) : node;
      if (child instanceof MiniElement) child.remove();
      me(child).parent = parent;
      me(parent).kids.splice(at++, 0, child);
    }
  }
  get previousElementSibling() {
    const parent = me(this).parent;
    if (!parent) return null;
    const siblings = me(parent).kids.filter((kid) => kid instanceof MiniElement);
    return siblings[siblings.indexOf(this) - 1] || null;
  }
  // A select and its options, as far as the custom select and the final-word
  // picker use them: the selected option, and the value it gives the select.
  get options() { return me(this).tag === "select" ? this.querySelectorAll("option") : undefined; }
  get selectedIndex() {
    const options = this.options || [], selected = options.findIndex((option) => me(option).selected);
    return selected >= 0 ? selected : options.findIndex((option) => !option.disabled);
  }
  get selected() { return Boolean(me(this).selected); }
  set selected(value) {
    if (value) for (const option of this.closest("select")?.options || []) me(option).selected = false;
    me(this).selected = Boolean(value);
  }
  getAttribute(name) { return me(this).attrs.get(name) ?? null; }
  setAttribute(name, value) { me(this).attrs.set(String(name), String(value)); }
  removeAttribute(name) { me(this).attrs.delete(name); }
  hasAttribute(name) { return me(this).attrs.has(name); }
  getAttributeNames() { return [...me(this).attrs.keys()]; }
  get id() { return this.getAttribute("id") ?? ""; }
  set id(value) { this.setAttribute("id", value); }
  get className() { return this.getAttribute("class") ?? ""; }
  set className(value) { this.setAttribute("class", value); }
  get title() { return this.getAttribute("title") ?? ""; }
  set title(value) { this.setAttribute("title", value); }
  get disabled() { return this.hasAttribute("disabled"); }
  set disabled(value) { if (value) this.setAttribute("disabled", ""); else this.removeAttribute("disabled"); }
  get hidden() { return this.hasAttribute("hidden"); }
  set hidden(value) { if (value) this.setAttribute("hidden", ""); else this.removeAttribute("hidden"); }
  get value() {
    const own = me(this);
    if (own.tag === "select") return this.options[this.selectedIndex]?.value ?? "";
    if (own.tag === "option" && !own.valueSet) return this.getAttribute("value") ?? this.textContent;
    // Until set, an input's value is its value attribute and a textarea's its text.
    if (!own.valueSet && own.tag === "input") return this.getAttribute("value") ?? "";
    if (!own.valueSet && own.tag === "textarea") return this.textContent;
    return own.value;
  }
  set value(value) {
    const own = me(this);
    if (own.tag === "select") {
      for (const option of this.options) me(option).selected = option.value === String(value);
      return;
    }
    own.value = String(value);
    own.valueSet = true;
  }
  get style() { return me(this).style; }
  get classList() {
    const read = () => (this.getAttribute("class") || "").split(/\s+/).filter(Boolean), write = (names) => this.setAttribute("class", names.join(" "));
    return {
      add: (...names) => write([...new Set([...read(), ...names])]),
      remove: (...names) => write(read().filter((name) => !names.includes(name))),
      contains: (name) => read().includes(name),
      toggle: (name, force) => {
        const on = force ?? !read().includes(name);
        write(on ? [...new Set([...read(), name])] : read().filter((other) => other !== name));
        return on;
      },
    };
  }
  get dataset() {
    return new Proxy({}, {
      get: (_, key) => typeof key === "string" ? this.getAttribute(dataName(key)) ?? undefined : undefined,
      set: (_, key, value) => (this.setAttribute(dataName(key), value), true),
      deleteProperty: (_, key) => (this.removeAttribute(dataName(key)), true),
      has: (_, key) => this.hasAttribute(dataName(key)),
      ownKeys: () => this.getAttributeNames().filter((name) => name.startsWith("data-")).map((name) => camel(name.slice(5))),
      getOwnPropertyDescriptor: (_, key) => this.hasAttribute(dataName(key)) ? { value: this.getAttribute(dataName(key)), enumerable: true, configurable: true, writable: true } : undefined,
    });
  }
  matches(selector) { return matchesSelector(this, selector); }
  closest(selector) {
    for (let node = this; node instanceof MiniElement; node = me(node).parent) if (matchesSelector(node, selector)) return node;
    return null;
  }
  querySelectorAll(selector) {
    const found = [], walk = (node) => {
      for (const kid of me(node).kids) if (kid instanceof MiniElement) {
        if (matchesSelector(kid, selector)) found.push(kid);
        walk(kid);
      }
    };
    walk(this);
    return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  addEventListener(type, listener) { addListener(this, type, listener); }
  removeEventListener(type, listener) { removeListener(this, type, listener); }
  listenerCount(type) { return countListeners(this, type); }
  // Runs this element's own listeners for the event (no bubbling).
  dispatchEvent(event) {
    for (const listener of [...(listeners.get(this)?.get(event.type) ?? [])]) listener.call(this, Object.assign(event, { target: this }));
    return true;
  }
  focus() {}
  select() {}
  click() {
    if (this.disabled) return;
    this.onclick?.({ type: "click", target: this, preventDefault() {}, stopPropagation() {} });
  }
}

function parseHtml(ownerDocument, html) {
  const root = new MiniFragment(ownerDocument);
  let current = root;
  const token = /<!--[\s\S]*?-->|<\/([a-zA-Z][\w:-]*)\s*>|<([a-zA-Z][\w:-]*)((?:"[^"]*"|'[^']*'|[^'">])*)>|([^<]+)|(<)/g;
  for (let match; (match = token.exec(html)); ) {
    if (match[0].startsWith("<!--")) continue;
    if (match[1]) {
      const tag = match[1].toLowerCase();
      for (let node = current; node instanceof MiniElement; node = me(node).parent) if (me(node).tag === tag) {
        current = me(node).parent || root;
        break;
      }
    } else if (match[2]) {
      const element = new MiniElement(match[2], ownerDocument), selfClosing = match[3].trimEnd().endsWith("/");
      for (const attribute of match[3].matchAll(/([^\s=/"'>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) element.setAttribute(attribute[1], unescapeText(attribute[2] ?? attribute[3] ?? attribute[4] ?? ""));
      current.appendChild(element);
      if (!selfClosing && !VOID.has(me(element).tag)) current = element;
    } else current.appendChild(new MiniText(unescapeText(match[4] ?? match[5])));
  }
  return root;
}

// The text-node walk the app's translation sweep uses (whatToShow is taken to
// be SHOW_TEXT). A rejected text node is simply not returned.
export const MiniNodeFilter = Object.freeze({ SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3 });
function textNodesUnder(node, out = []) {
  for (const kid of me(node).kids) {
    if (kid instanceof MiniText) out.push(kid);
    else if (kid instanceof MiniElement) textNodesUnder(kid, out);
  }
  return out;
}

export class MiniDocument {
  constructor() {
    this.body = new MiniElement("body", this);
    me(this.body).parent = this;
    this.documentElement = { lang: "en" };
    state.set(this, { kids: [this.body] });
  }
  createTreeWalker(root, _whatToShow, filter) {
    const nodes = textNodesUnder(root).filter((node) => !filter?.acceptNode || filter.acceptNode(node) === MiniNodeFilter.FILTER_ACCEPT);
    let index = -1;
    return {
      get currentNode() { return nodes[index] ?? root; },
      nextNode() { return ++index < nodes.length ? nodes[index] : null; },
    };
  }
  createElement(tag) { return new MiniElement(tag, this); }
  createElementNS(_namespace, tag) { return new MiniElement(tag, this); }
  createDocumentFragment() { return new MiniFragment(this); }
  createTextNode(text) { return new MiniText(text); }
  addEventListener(type, listener) { addListener(this, type, listener); }
  removeEventListener(type, listener) { removeListener(this, type, listener); }
  listenerCount(type) { return countListeners(this, type); }
  getElementById(id) { return this.body.querySelector(`#${id}`); }
  querySelector(selector) { return this.body.querySelector(selector); }
  querySelectorAll(selector) { return this.body.querySelectorAll(selector); }
  execCommand() { return true; }
}
