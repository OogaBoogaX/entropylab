// Security contract: only a connected, enabled clipboard control can copy
// its currently displayed private value, byte-for-byte; values themselves,
// concealed/missing results and stale controls must never copy anything.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument, MiniElement, MiniNodeFilter } from "./mini-dom.mjs";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { privateCopyButtonHtml, initPrivateCopy } from "../src/js/private-data.js";
import { hodlInitLn, hodlLnWipeMem } from "../src/js/lightning.js";
import { hodlApplyStaticI18n, hodlSetLocale } from "../src/js/i18n.js";

const app = await loadAppFunctions(["hodlPrivateFieldHtml", "hodlPrivateFieldMarkup", "hodlJournalPrivateValue", "hodlBip85SecretField"], {
  stubs: { hodlRevealPrivate: true, hodlJournalReveal: true, hodlBip85Reveal: true },
});

const copyIcon = () => '<svg data-test-copy-icon aria-hidden="true"><path></path></svg>';
const copiedIcon = () => '<svg data-test-copied-icon aria-hidden="true"><path></path></svg>';
// BIP32 vector 1's input seed, and exact user-authored text (including
// significant whitespace); neither expected value comes from the handler.
const SECRET = "000102030405060708090a0b0c0d0e0f";
const PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

async function withPage(body, { fallback = false, denied = false } = {}) {
  const saved = Object.fromEntries(["document", "navigator", "NodeFilter"].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const document = new MiniDocument(), writes = [], executed = [], listeners = new WeakMap();
  const listen = function (type, callback) {
    if (!listeners.has(this)) listeners.set(this, new Map());
    listeners.get(this).set(type, callback);
  };
  mock.method(MiniElement.prototype, "addEventListener", listen);
  Object.defineProperty(MiniElement.prototype, "getClientRects", { configurable: true, writable: true, value() { return [{}]; } });
  document.addEventListener = listen;
  document.removeEventListener = function (type, callback) {
    if (listeners.get(this)?.get(type) === callback) listeners.get(this).delete(type);
  };
  document.defaultView = { getComputedStyle: (node) => ({ visibility: node.style.visibility || "visible" }) };
  document.execCommand = (command) => {
    executed.push([command, document.querySelector("textarea")?.value]);
    return !denied;
  };
  Object.defineProperty(globalThis, "document", { configurable: true, value: document });
  Object.defineProperty(globalThis, "NodeFilter", { configurable: true, value: MiniNodeFilter });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: fallback ? {} : { clipboard: { writeText: async (value) => {
    if (denied) throw new Error("clipboard refused");
    writes.push(value);
  } } } });
  mock.timers.enable({ apis: ["setTimeout"] });
  const teardown = initPrivateCopy({ copyIcon, copiedIcon });
  const click = (target) => listeners.get(document)?.get("click")?.({ target });
  const change = (target) => listeners.get(target)?.get("change")?.({ target });
  try { await body({ document, writes, executed, click, change, teardown }); }
  finally {
    teardown();
    hodlLnWipeMem();
    hodlSetLocale("en", false);
    mock.timers.reset();
    mock.restoreAll();
    delete MiniElement.prototype.getClientRects;
    for (const [key, descriptor] of Object.entries(saved)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
}

function field(document, secret = SECRET, options = {}) {
  const container = document.createElement("div");
  container.setAttribute("data-private-field", "");
  container.innerHTML = `<span>${privateCopyButtonHtml(copyIcon, options)}</span><span data-private-value></span>`;
  container.querySelector("[data-private-value]").textContent = secret;
  document.body.append(container);
  return { container, button: container.querySelector("button"), value: container.querySelector("[data-private-value]") };
}

function assertNoSecret(button, secret) {
  for (const name of button.getAttributeNames()) assert.ok(!button.getAttribute(name).includes(secret), name);
  for (const [name, value] of Object.entries(button)) if (typeof value === "string") assert.ok(!value.includes(secret), name);
  assert.ok(!button.textContent.includes(secret));
}

test("an intentional clipboard click copies only its field, with accessible confirmation and no secret on the button", () => withPage(async ({ document, writes, click }) => {
  field(document, "unrelated secret");
  const { button } = field(document);
  const initialLabel = button.getAttribute("aria-label");
  assert.ok(initialLabel);
  assert.equal(button.title, initialLabel);
  assertNoSecret(button, SECRET);
  await click(button.querySelector("path"));
  assert.deepEqual(writes, [SECRET]);
  assertNoSecret(button, SECRET);
  assert.notEqual(button.getAttribute("aria-label"), initialLabel);
  mock.timers.tick(1600);
  assert.equal(button.getAttribute("aria-label"), initialLabel);
}));

for (const secret of [PHRASE, "  leading and trailing \t\n", " ", "<tag> & literal characters"]) {
  test(`copy preserves the exact displayed text ${JSON.stringify(secret)}`, () => withPage(async ({ document, writes, click }) => {
    const { button } = field(document, secret);
    await click(button);
    assert.deepEqual(writes, [secret]);
  }));
}

for (const locale of ["es", "pt", "fr", "de"]) {
  for (const [name, render] of [
    ["private passphrase", (secret) => app.hodlPrivateFieldHtml("BIP39 passphrase", secret)],
    ["Journal secret", (secret) => app.hodlPrivateFieldMarkup("BIP39 seed or passphrase", app.hodlJournalPrivateValue(secret))],
    ["BIP85 output", (secret) => app.hodlBip85SecretField("Derived entropy", () => secret, secret.length)],
  ]) {
    test(`${name} remains byte-faithful when copied after switching to ${locale}`, () => withPage(async ({ document, writes, click }) => {
      const secret = "  account  ";
      document.body.innerHTML = render(secret);
      const button = document.querySelector("[data-private-copy]");
      const originalLabel = button.getAttribute("aria-label");
      hodlSetLocale(locale, false);
      hodlApplyStaticI18n();
      assert.notEqual(button.getAttribute("aria-label"), originalLabel, "copy controls still translate");
      await click(button);
      assert.deepEqual(writes, [secret], "a catalog key used as private data is never translated");
    }));
  }
}

test("clicking a private value never writes to the clipboard", () => withPage(async ({ document, writes, click }) => {
  const { value } = field(document);
  await click(value);
  assert.deepEqual(writes, []);
}));

test("a closed details group cannot copy, even when its hidden descendants report layout boxes", () => withPage(async ({ document, writes, click }) => {
  const { container, button } = field(document);
  const details = document.createElement("details"), summary = document.createElement("summary");
  summary.textContent = "Recovery";
  details.append(summary, container);
  document.body.append(details);
  // Chrome reports getClientRects() and visible computed visibility for
  // descendants of a closed details element; the fake page does too.
  await click(button);
  assert.deepEqual(writes, []);
  details.setAttribute("open", "");
  await click(button);
  assert.deepEqual(writes, [SECRET]);
  details.removeAttribute("open");
  await click(button);
  assert.deepEqual(writes, [SECRET]);
}));

test("a closed outer details group hides an open nested group's clipboard", () => withPage(async ({ document, writes, click }) => {
  const { container, button } = field(document);
  const outer = document.createElement("details"), inner = document.createElement("details");
  inner.setAttribute("open", "");
  inner.append(container);
  outer.append(inner);
  document.body.append(outer);
  await click(button);
  assert.deepEqual(writes, []);
}));

test("only the first summary of a closed details group remains a visible copy source", () => withPage(async ({ document, writes, click }) => {
  const first = field(document), second = field(document, "concealed second summary");
  const details = document.createElement("details"), summary = document.createElement("summary"), laterSummary = document.createElement("summary");
  summary.append(first.container);
  laterSummary.append(second.container);
  details.append(summary, laterSummary);
  document.body.append(details);
  await click(first.button);
  await click(second.button);
  assert.deepEqual(writes, [SECRET]);
}));

for (const [name, alter] of [
  ["disabled control", ({ button }) => { button.disabled = true; }],
  ["empty value", ({ value }) => { value.textContent = ""; }],
  ["missing value", ({ value }) => value.remove()],
  ["concealed value without marker", ({ value }) => { value.removeAttribute("data-private-value"); value.textContent = "************"; }],
  ["hidden value", ({ value }) => { value.hidden = true; }],
  ["hidden ancestor", ({ container }) => { container.hidden = true; }],
  ["aria-hidden value", ({ value }) => value.setAttribute("aria-hidden", "true")],
  ["inert field", ({ container }) => container.setAttribute("inert", "")],
  ["unrendered value", ({ value }) => { value.getClientRects = () => []; }],
  ["visibility-hidden value", ({ value }) => { value.style.visibility = "hidden"; }],
  ["detached control", ({ button }) => button.remove()],
  ["detached field", ({ container }) => container.remove()],
  ["stale control after rerender", ({ container }) => { container.innerHTML = "replacement result"; }],
  ["control moved outside its field", ({ button }, document) => document.body.append(button)],
]) {
  test(`${name} cannot copy private data`, () => withPage(async ({ document, writes, executed, click }) => {
    const parts = field(document);
    alter(parts, document);
    await click(parts.button);
    assert.deepEqual(writes, []);
    assert.deepEqual(executed, []);
  }));
}

test("clipboard fallback receives the exact secret and leaves no temporary field", () => withPage(async ({ document, executed, click }) => {
  const { button } = field(document, "  passphrase  ");
  await click(button);
  assert.deepEqual(executed, [["copy", "  passphrase  "]]);
  assert.equal(document.querySelector("textarea"), null);
}, { fallback: true }));

test("clipboard fallback stays inside the private field's modal focus trap", () => withPage(async ({ document, click }) => {
  const { container, button } = field(document);
  const modal = document.createElement("div");
  modal.setAttribute("role", "dialog");
  document.body.append(modal);
  modal.append(container);
  let fallbackHost;
  document.execCommand = () => {
    fallbackHost = document.querySelector("textarea").closest('[role="dialog"]');
    return true;
  };
  await click(button);
  assert.equal(fallbackHost, modal);
}, { fallback: true }));

test("failed copies never confirm success", () => withPage(async ({ document, writes, click }) => {
  const { button } = field(document);
  const before = button.getAttribute("aria-label");
  await click(button);
  assert.deepEqual(writes, []);
  assert.equal(button.getAttribute("aria-label"), before);
}, { denied: true }));

test("specialized controls retain their own handler and teardown removes delegation", () => withPage(async ({ document, writes, click, teardown }) => {
  const { button } = field(document, SECRET, { id: "child-copy", attribute: "data-bip85-copy" });
  assert.equal(button.id, "child-copy");
  assert.ok(button.hasAttribute("data-bip85-copy"));
  await click(button);
  teardown();
  await click(field(document).button);
  assert.deepEqual(writes, []);
}));

test("Lightning reveals each secret beside a copy control and removes the controls when concealed", () => withPage(async ({ document, writes, click, change }) => {
  document.body.innerHTML = '<select id="ln-format"><option value="aezeed">aezeed</option></select><select id="ln-network"><option value="mainnet">mainnet</option></select><textarea id="ln-seed"></textarea><input id="ln-pass"><button id="ln-go"></button><button id="ln-wipe"></button><p id="ln-error"></p><p id="ln-session"></p><div id="ln-out"></div>';
  document.getElementById("ln-seed").value = "ability result leisure oven shiver wedding toe broccoli exclude mosquito kind van action waste merit bundle robust source able advice core humor kitchen siren";
  hodlInitLn({ copyIcon });
  document.getElementById("ln-go").click();
  const publicKey = document.getElementById("ln-node-pubkey");
  assert.ok(publicKey.hasAttribute("data-public-value"));
  assert.ok(publicKey.hasAttribute("data-copy-field"));
  assert.ok(publicKey.closest("[data-copy-group]").querySelector("[data-public-copy]"));
  assert.ok(document.querySelectorAll("[data-copy-field]").some((value) => value.textContent === "m/1017'/0'/6'/0/0"));
  assert.equal(document.querySelectorAll("[data-private-value]").length, 0);
  document.getElementById("ln-reveal").checked = true;
  change(document.getElementById("ln-reveal"));
  const controls = document.querySelectorAll("[data-private-copy]");
  assert.equal(controls.length, 3, "entropy, salt, and root private key each supply a copy control");
  for (const button of controls) {
    assert.ok(button.closest("[data-private-field]").querySelector("[data-private-value]"));
    assert.ok(button.getAttribute("aria-label"));
  }
  await click(document.getElementById("ln-entropy").closest("[data-private-field]").querySelector("[data-private-copy]"));
  assert.deepEqual(writes, [SECRET]);
  document.getElementById("ln-reveal").checked = false;
  change(document.getElementById("ln-reveal"));
  assert.equal(document.querySelectorAll("[data-private-value]").length, 0);
  for (const button of controls) await click(button);
  assert.deepEqual(writes, [SECRET]);
}));
