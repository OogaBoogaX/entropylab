// #546 B3: the copy buttons build their text when clicked. The Key Station's
// "Copy seed phrase" button and the BIP-85 Station's child copy button used to
// keep the whole secret in a `data-phrase` attribute for as long as the output
// was on the page, and after a wallet is derived that attribute was the last
// full copy of the seed words. Neither button holds the secret now: a click
// reads the words its grid shows (Key Station) or the active child (BIP-85
// Station).
//
// Security contract: a copy button holds no secret in any attribute or
// property. A revealed child copies its published text; hidden children and
// detached controls cannot copy. Confirmation never retains the secret.
//
// Expected values: the published BIP39 vectors (trezor/python-mnemonic
// vectors.json), each cross-checked below against @scure/bip39 from its
// published entropy, and the published BIP-85 children (bitcoin/bips
// bip-0085, the same values test/bip85.test.mjs pins). Labels are asserted as
// relations (available, unavailable, copied), not as wording.
//
// The page code under test is the app's own (test/app-slice-harness.mjs) run
// against test/mini-dom.mjs, which builds the fixtures from the app's own
// markup. The button's real behaviour in a browser is covered by the rendered
// comparison in the PR and by test/browser-suite.html.
// Run with `npm test`.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HDKey } from "@scure/bip32";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { deriveApplication, wipeBip85Result } from "../src/js/bip85.js";
import { hodlApplyStaticI18n, hodlSetLocale, t as translate } from "../src/js/i18n.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument, MiniElement, MiniNodeFilter } from "./mini-dom.mjs";

const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
const seed = await loadAppFunctions(["hodlRenderDiceWordGrid", "hodlCopySeedPhraseButton", "hodlDerivedSeedRowMarkup"]);
const station = await loadAppFunctions(["hodlRenderBip85Out", "hodlCopyBip85Child"], { stubs: { hodlFillKeyTabLifehash: () => {} }, settable: ["hodlBip85Children", "hodlActiveBip85", "hodlBip85Reveal"] });
const publicReadouts = await loadAppFunctions(["hodlVanityKeyMarkup", "hodlSetMasterFingerprintCard"]);
const journal = await loadAppFunctions(["hodlJournalSyncCopyButton", "hodlJournalCopyContent"]);
const journalText = await loadAppFunctions([
  "hodlJournalRenderVisual", "hodlCreateJournalPageTab", "hodlKeyManagerRender", "hodlJournalRenderList", "hodlJournalOpenView",
], {
  stubs: {
    hodlJournalSyncNotesRender() {}, hodlJournalSyncCopyButton() {}, hodlFillKeyTabLifehash() {}, hodlJournalFillFingerprint() {},
    hodlBeginJournalPageRename() {}, hodlSelectJournalPage() {}, hodlJournalPageTabKeydown() {},
    hodlKeyManagerDetails: () => [], hodlKeyManagerRename() {}, hodlKeyManagerUseInStation() {}, hodlKeyManagerIgnore() {}, hodlKeyManagerRestoreIgnored() {},
    hodlKeyManagerStatus() {}, hodlJournalHideEditor() {}, hodlJournalShowWork() {}, hodlJournalLog() {}, hodlRevealTab() {},
  },
  settable: ["hodlJournal", "hodlKeys", "hodlKeyManagerPending", "hodlKeyManagerIgnored", "hodlJournalDoc"],
});
delete globalThis.document;
delete globalThis.window;

const hex = (text) => Uint8Array.from(text.match(/../g).map((byte) => parseInt(byte, 16)));
const VECTORS = [
  ["12 words", "9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"],
  ["12 words", "c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"],
  ["24 words", "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"],
  ["24 words", "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"],
];
test("the expected phrases are the published vectors", () => {
  for (const [, entropy, phrase] of VECTORS) assert.equal(entropyToMnemonic(hex(entropy), wordlist), phrase);
});
const [TWELVE, , TWENTY_FOUR] = VECTORS.map(([, , phrase]) => phrase.split(" "));

// The page, per test: a fresh document, mocked timers and a clipboard that
// records what it is given.
const written = [], executed = [];
const previousContains = MiniElement.prototype.contains, previousFocus = MiniElement.prototype.focus;
const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
const clipboard = (mode) => Object.defineProperty(globalThis, "navigator", { configurable: true, writable: true, value: mode === "none" ? {} : { clipboard: { writeText: (text) => mode === "denied" ? Promise.reject(new Error("denied")) : (written.push(text), Promise.resolve()) } } });
function page(mode = "works") {
  written.length = executed.length = 0;
  globalThis.document = new MiniDocument();
  // Record rerenders preserve focus only when the old control belongs to
  // that view. Model DOM ancestry and activeElement, including detached
  // nodes, rather than treating every element as contained or focused.
  MiniElement.prototype.contains = function (target) {
    for (let node = target; node; node = node.parentNode) if (node === this) return true;
    return false;
  };
  MiniElement.prototype.focus = function () { this.ownerDocument.activeElement = this; };
  globalThis.document.execCommand = (command) => (executed.push([command, globalThis.document.querySelector("textarea")?.value]), true);
  globalThis.NodeFilter = MiniNodeFilter;
  clipboard(mode);
  mock.timers.enable({ apis: ["setTimeout"] });
  return globalThis.document;
}
function leave() {
  mock.timers.reset();
  if (previousContains) MiniElement.prototype.contains = previousContains;
  else delete MiniElement.prototype.contains;
  MiniElement.prototype.focus = previousFocus;
  hodlSetLocale("en", false);
  delete globalThis.NodeFilter;
  delete globalThis.document;
  if (navigatorDescriptor) Object.defineProperty(globalThis, "navigator", navigatorDescriptor);
  else delete globalThis.navigator;
}
const settle = () => new Promise((resolve) => setImmediate(resolve));
const withPage = (mode, body) => async () => {
  const document = page(mode);
  try {
    await body(document);
  } finally {
    leave();
  }
};

test("a vanity fingerprint supplies its exact public value to both copy controls", withPage("works", async (document) => {
  document.body.innerHTML = publicReadouts.hodlVanityKeyMarkup("73c5da0a");
  const value = document.querySelector("[data-public-value]");
  assert.ok(value, "the fingerprint is exposed through the public-value interface");
  assert.equal(value.textContent, "73c5da0a");
  assert.ok(value.hasAttribute("data-copy-field"));
  assert.ok(value.closest("[data-copy-group]").querySelector("[data-public-copy]"));
  document.body.innerHTML = publicReadouts.hodlVanityKeyMarkup("");
  assert.equal(document.querySelector("[data-public-copy]"), null);
}));

test("fingerprint previews offer direct copying only while a value is available", withPage("works", async (document) => {
  document.body.innerHTML = '<div id="card" data-copy-group><button id="fingerprint" data-copy-field data-public-value></button><span data-copy-status aria-live="polite"></span></div>';
  const card = document.getElementById("card"), value = document.getElementById("fingerprint");
  const status = card.querySelector("[data-copy-status]");
  assert.equal(publicReadouts.hodlSetMasterFingerprintCard(card, value, "73c5da0a", null), true);
  assert.equal(value.textContent, "73c5da0a");
  assert.ok(value.hasAttribute("data-copy-field"));
  assert.equal(card.querySelector("[data-public-copy]"), null);
  assert.equal(status.closest("[data-copy-group]"), value.closest("[data-copy-group]"));
  assert.equal(value.disabled, false);
  assert.equal(publicReadouts.hodlSetMasterFingerprintCard(card, value, "", null), false);
  assert.equal(value.textContent, "");
  assert.equal(card.querySelector("[data-public-copy]"), null);
  assert.equal(status.textContent, "");
  assert.equal(value.disabled, true);
}));

// Everything a button holds as text: each attribute (name and value), its
// markup, and every string reachable from its own properties (the ones page
// code added: a handler, a timer, a flag), never following a link to another
// DOM node.
function heldText(button) {
  const held = [["innerHTML", button.innerHTML], ["textContent", button.textContent]], seen = new Set();
  for (const name of button.getAttributeNames()) held.push([`attribute ${name} (name)`, name], [`attribute ${name}`, button.getAttribute(name)]);
  const walk = (label, value, depth) => {
    if (typeof value === "string") held.push([label, value]);
    else if (value && typeof value === "object" && !value.nodeType && depth < 4 && !seen.has(value)) {
      seen.add(value);
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor && "value" in descriptor) walk(`${label}.${String(key)}`, descriptor.value, depth + 1);
      }
    }
  };
  for (const key of Reflect.ownKeys(button)) walk(`property ${String(key)}`, Object.getOwnPropertyDescriptor(button, key).value, 0);
  return held;
}
// What in `button` gives away `secret`: the whole secret, any run of two of
// its words (a phrase), or, for a one-word secret or a password, the word or
// the first 8 characters.
function leaks(button, secret) {
  const words = secret.split(" "), probes = words.length > 1 ? words.slice(1).map((word, index) => `${words[index]} ${word}`) : [secret.slice(0, 8)];
  return heldText(button).filter(([, text]) => text.includes(secret) || probes.some((probe) => text.includes(probe))).map(([label]) => label);
}

// ---- The Key Station's "Copy seed phrase" button ---------------------------

function seedPage(document) {
  document.body.innerHTML = `<div id="form">${seed.hodlDerivedSeedRowMarkup()}<div id="dice-words" class="dice-word-grid"></div></div>`;
  const button = document.querySelector("[data-copy-seed-phrase]");
  assert.ok(button, "the fixture has the copy button");
  return {
    button,
    grid: document.getElementById("dice-words"),
    render: (words, target = words.length > 12 ? 24 : 12) => seed.hodlRenderDiceWordGrid(document.getElementById("dice-words"), words, target, false),
    labels: () => [button.getAttribute("aria-label"), button.title],
  };
}
// [name, words in the grid, grid size, the text a click copies]. Expected
// text is the vector's words joined, or nothing where the grid cannot be
// copied: a grid with a gap in it, or an empty one.
const GRIDS = [
  ["12-word grid", TWELVE, 12, TWELVE.join(" ")],
  ["24-word grid", TWENTY_FOUR, 24, TWENTY_FOUR.join(" ")],
  ["partial grid, 5 of 12", TWELVE.slice(0, 5), 12, TWELVE.slice(0, 5).join(" ")],
  ["partial grid, 11 of 24", TWENTY_FOUR.slice(0, 11), 24, TWENTY_FOUR.slice(0, 11).join(" ")],
  ["partial grid, 1 of 12", TWELVE.slice(0, 1), 12, TWELVE[0]],
  ["grid with a gap", [TWELVE[0], "", ...TWELVE.slice(2, 6)], 12, ""],
  ["empty grid", [], 12, ""],
];
const COPYABLE = GRIDS.filter(([, , , text]) => text);
const NOT_COPYABLE = GRIDS.filter(([, , , text]) => !text);

for (const [name, words, target, text] of GRIDS) {
  test(`${name}: the button holds no secret in any attribute or property`, withPage("works", async (document) => {
    const { button, render } = seedPage(document);
    render(words, target);
    const shown = words.filter(Boolean).join(" ");
    assert.deepEqual(shown ? leaks(button, shown) : [], []);
    if (!text) return;
    button.click();
    await settle();
    assert.deepEqual(leaks(button, text), [], "while it shows Copied");
    mock.timers.tick(1600);
    assert.deepEqual(leaks(button, text), [], "after the Copied state times out");
  }));

  test(`${name}: disabled state and labels`, withPage("works", async (document) => {
    const { button, render, labels } = seedPage(document);
    render(TWELVE, 12);
    const available = labels();
    render(words, target);
    assert.equal(button.disabled, !text);
    const [label, title] = labels();
    assert.equal(label, title, "aria-label and title agree");
    if (text) assert.deepEqual(labels(), available, "copyable grids share the available label");
    else {
      assert.notDeepEqual(labels(), available, "an uncopyable grid says so");
      render([], 12);
      assert.deepEqual(labels(), [label, title], "and says it the same way for every uncopyable grid");
    }
  }));
}

for (const [name, words, target, text] of COPYABLE) {
  test(`${name}: a click copies exactly the phrase`, withPage("works", async (document) => {
    const { button, render } = seedPage(document);
    render(words, target);
    button.click();
    await settle();
    assert.deepEqual(written, [text]);
  }));

  test(`${name}: the fallback copy path gets exactly the phrase too`, withPage("none", async (document) => {
    const { button, render } = seedPage(document);
    render(words, target);
    button.click();
    await settle();
    assert.deepEqual(executed, [["copy", text]]);
  }));

  test(`${name}: a refused clipboard write falls back to the same text`, withPage("denied", async (document) => {
    const { button, render } = seedPage(document);
    render(words, target);
    button.click();
    await settle();
    assert.deepEqual(executed, [["copy", text]]);
  }));
}

for (const [name, words, target] of NOT_COPYABLE) {
  test(`${name}: a click copies nothing`, withPage("works", async (document) => {
    const { button, render } = seedPage(document);
    render(words, target);
    button.click();
    button.onclick?.({});
    await settle();
    assert.deepEqual(written, []);
    assert.deepEqual(executed, []);
    assert.ok(!button.classList.contains("is-copied"));
  }));
}

test("the button's Copied state and its return to the copy label", withPage("works", async (document) => {
  const { button, render, labels } = seedPage(document);
  render(TWELVE, 12);
  const available = labels();
  button.click();
  await settle();
  assert.ok(button.classList.contains("is-copied"));
  assert.notDeepEqual(labels(), available, "Copied has its own label");
  const copied = labels();
  mock.timers.tick(1599);
  assert.deepEqual(labels(), copied, "still Copied just before the timeout");
  mock.timers.tick(1);
  assert.ok(!button.classList.contains("is-copied"));
  assert.deepEqual(labels(), available, "back to the copy label, because the grid is still copyable");
  assert.equal(button.disabled, false);
}));

for (const [name, words] of NOT_COPYABLE) {
  test(`${name}: reached while the button shows Copied, it returns as unavailable`, withPage("works", async (document) => {
    const { button, render, labels } = seedPage(document);
    render([], 12);
    const unavailable = labels();
    render(TWELVE, 12);
    const available = labels();
    button.click();
    await settle();
    render(words, 12);
    assert.equal(button.disabled, true);
    mock.timers.tick(1600);
    assert.deepEqual(labels(), unavailable);
    assert.notDeepEqual(unavailable, available);
    assert.equal(button.disabled, true);
  }));
}

test("a click copies the grid as it is now, not as it was when the button was first used", withPage("works", async (document) => {
  const { button, render } = seedPage(document);
  render(TWELVE, 12);
  button.click();
  await settle();
  mock.timers.tick(1600);
  render(VECTORS[1][2].split(" "), 12);
  button.click();
  await settle();
  mock.timers.tick(1600);
  render(TWELVE.slice(0, 3), 12);
  button.click();
  await settle();
  mock.timers.tick(1600);
  render(TWENTY_FOUR, 24);
  button.click();
  await settle();
  assert.deepEqual(written, [TWELVE.join(" "), VECTORS[1][2], TWELVE.slice(0, 3).join(" "), TWENTY_FOUR.join(" ")]);
}));

test("after the page's pagehide sweep the button copies nothing", withPage("works", async (document) => {
  const { button, render } = seedPage(document);
  render(TWELVE, 12);
  // The sweep in app.js: it empties the word grids and drops [data-phrase].
  document.querySelectorAll(".dice-word-grid").forEach((grid) => { grid.textContent = ""; });
  document.querySelectorAll("[data-phrase]").forEach((element) => element.removeAttribute("data-phrase"));
  button.click();
  await settle();
  assert.deepEqual(written, []);
  assert.deepEqual(executed, []);
  mock.timers.tick(1600);
  assert.deepEqual(leaks(button, TWELVE.join(" ")), []);
}));

test("the Journal's Notes copy control never retains page text", withPage("works", async (document) => {
  document.body.innerHTML = '<button id="journal-notes-copy" type="button" aria-label="Copy notepad page" title="Copy notepad page" data-copy-label="Copy notepad page" data-copied-label="Notepad page copied"></button>';
  const button = document.getElementById("journal-notes-copy");
  const field = { value: VECTORS[0][2] };
  journal.hodlJournalSyncCopyButton(field, button);
  assert.equal(button.disabled, false);
  assert.deepEqual(leaks(button, field.value), []);
  field.value = "";
  journal.hodlJournalSyncCopyButton(field, button);
  assert.equal(button.disabled, true);
  assert.deepEqual(leaks(button, VECTORS[0][2]), []);
}));

// Notes can hold recovery material; imported Activity is untrusted text and
// may do the same. Both read the live field at the click, use the notebook's
// readable-text formatting or the exact activity text, and refuse a control
// or source that is no longer shown.
for (const notebook of [true, false]) {
  const area = notebook ? "Notes" : "Activity";
  function journalPage(document) {
    document.body.innerHTML = `<div id="journal-section"><${notebook ? "textarea" : "pre"} id="journal-content"></${notebook ? "textarea" : "pre"}><button id="journal-copy" type="button" aria-label="Copy" title="Copy" data-copy-label="Copy" data-copied-label="Copied"></button></div>`;
    const button = document.getElementById("journal-copy"), field = document.getElementById("journal-content");
    const setText = (text) => { if (notebook) field.value = text; else field.textContent = text; };
    return { button, field, setText };
  }
  test(`Journal ${area} copies current text without retaining it on the control`, withPage("works", async (document) => {
    const { button, field, setText } = journalPage(document);
    for (const phrase of [VECTORS[0][2], VECTORS[1][2]]) {
      const content = `first line\n  ${phrase}${notebook ? "" : "\n\n"}`;
      setText(content);
      await journal.hodlJournalCopyContent(button, field, notebook);
      assert.equal(written.at(-1), content);
      assert.deepEqual(leaks(button, phrase), [], "the control retains no payload during confirmation");
      mock.timers.tick(1600);
      assert.deepEqual(leaks(button, phrase), [], "the control retains no payload after confirmation");
      assert.equal(button.getAttribute("aria-label"), button.dataset.copyLabel);
    }
    assert.equal(written.length, 2);
  }));
  test(`Journal ${area} uses the shared clipboard fallback`, withPage("none", async (document) => {
    const { button, field, setText } = journalPage(document);
    const content = `  ${VECTORS[0][2]}${notebook ? "" : "\n"}`;
    setText(content);
    // The fallback creates a temporary textarea. Locate that readonly field
    // rather than the notebook's editable textarea.
    document.execCommand = (command) => (executed.push([command, document.querySelector("textarea[readonly]")?.value]), true);
    await journal.hodlJournalCopyContent(button, field, notebook);
    assert.deepEqual(executed, [["copy", content]]);
    assert.equal(document.querySelector("textarea[readonly]"), null);
    assert.deepEqual(leaks(button, VECTORS[0][2]), []);
  }));
  for (const condition of ["disabled", "hidden source", "hidden control", "detached source", "detached control", "empty source"]) {
    test(`Journal ${area} refuses a ${condition}`, withPage("works", async (document) => {
      const { button, field, setText } = journalPage(document);
      setText(VECTORS[0][2]);
      if (condition === "disabled") button.disabled = true;
      else if (condition === "hidden source") field.hidden = true;
      else if (condition === "hidden control") button.hidden = true;
      else if (condition === "detached source") field.remove();
      else if (condition === "detached control") button.remove();
      else setText("");
      await journal.hodlJournalCopyContent(button, field, notebook);
      assert.deepEqual(written, []);
      assert.deepEqual(executed, []);
      assert.deepEqual(leaks(button, VECTORS[0][2]), []);
    }));
  }
}

// ---- A seed word is data, not text to translate ----------------------------

// The page's translation sweep (i18n.js, run on every language switch and at
// boot) rewrites any text node whose text is a catalog key, and three BIP39
// words are keys: "account", "coin" and "online". The grid must show them, and
// the button must copy them, unchanged in every language (#609 review).
const LOCALES = ["es", "pt", "fr", "de"];
const shell = readFileSync(new URL("../src/shell.html", import.meta.url), "utf8");
for (const locale of LOCALES) {
  test(`Journal user content remains exact after the ${locale} translation sweep`, withPage("works", async (document) => {
    const noteMarkup = shell.match(/<div\b[^>]*\bid="journal-notes-render"[^>]*><\/div>/)?.[0];
    assert.ok(noteMarkup, "fixture uses the actual notebook rendering surface");
    document.body.innerHTML = `${noteMarkup}<div id="page-tabs"></div><div id="journal-keymanager-tabs"></div><div id="journal-keymanager-panel"></div><section id="journal-keymanager-ignored"><div id="journal-keymanager-ignored-list"></div></section><div id="journal-list"></div><div id="journal-view"></div>`;
    const pages = [{ id: 1, number: 1, name: "account", notesText: "coin" }];
    journalText.__set.hodlJournal({ pages, activePage: 0 });
    journalText.hodlJournalRenderVisual({ value: "coin" });
    document.getElementById("page-tabs").append(journalText.hodlCreateJournalPageTab(0));
    journalText.__set.hodlKeys([]);
    journalText.__set.hodlKeyManagerPending([{ id: 1, number: 1, name: "account", needsDerivation: true, result: null }]);
    journalText.__set.hodlKeyManagerIgnored([{ id: 2, number: 2, name: "coin", needsDerivation: true, result: null }]);
    journalText.hodlKeyManagerRender();
    journalText.__set.hodlJournalDoc({ entries: [{ id: 1, label: "online", method: "dice", created: "2026-10-22", input: "account", phrase: "coin" }] });
    journalText.hodlJournalRenderList();
    journalText.hodlJournalOpenView(1);
    const note = document.getElementById("journal-notes-render");
    const pageLabel = document.getElementById("page-tabs").children[0].children[0];
    const keyLabel = document.getElementById("journal-keymanager-tabs").children[0].children[1];
    const keyHeading = document.getElementById("journal-keymanager-panel").querySelector("h3");
    const archived = document.getElementById("journal-keymanager-ignored-list").querySelector("strong");
    const recordLabel = document.getElementById("journal-list").children[0].children[1];
    const recordHeading = document.getElementById("journal-entry-heading");
    const names = [note, pageLabel, keyLabel, keyHeading, archived, recordLabel, recordHeading];
    const before = names.map((node) => node.textContent);
    hodlSetLocale(locale, false);
    hodlApplyStaticI18n();
    assert.deepEqual(names.map((node) => node.textContent), before);
    assert.equal(note.textContent, "coin");
    assert.equal(pages[0].name, "account");
    assert.equal(pages[0].notesText, "coin");
  }));
}
// Entropy whose phrase starts with the given words: their 11-bit indices, then
// zero bits. @scure/bip39 turns it into the phrase, checksum word included.
function entropyStartingWith(words, bytes) {
  const bits = words.map((word) => wordlist.indexOf(word).toString(2).padStart(11, "0")).join("").padEnd(bytes * 8, "0");
  return Uint8Array.from(bits.match(/.{8}/g), (byte) => parseInt(byte, 2));
}
const TRANSLATABLE = [
  // The review's case: 12 words ending "account accident".
  ["12 words ending in account", entropyToMnemonic(hex("00000000000000000000000000000600"), wordlist).split(" "), 12],
  ["24 words with all three", entropyToMnemonic(entropyStartingWith(["online", "legal", "coin", "winner", "account", "coin", "online", "account"], 32), wordlist).split(" "), 24],
  ["partial grid, 5 of 12", entropyToMnemonic(entropyStartingWith(["coin", "online", "account", "zoo", "coin"], 16), wordlist).split(" ").slice(0, 5), 12],
];
const shownWords = (document, count) => [...document.querySelectorAll("#form [data-word-slot] [data-word]")].slice(0, count).map((slot) => slot.textContent);

test("the fixtures carry the BIP39 words that are translation keys", () => {
  assert.deepEqual(TRANSLATABLE[0][1].slice(-2), ["account", "accident"]);
  for (const [name, words] of TRANSLATABLE) assert.ok(words.some((word) => ["account", "coin", "online"].includes(word)), name);
  assert.ok(TRANSLATABLE.slice(1).every(([, words]) => ["account", "coin", "online"].every((word) => words.includes(word))));
  // Without the skip, the sweep would change these words: Spanish translates all three.
  try {
    hodlSetLocale("es", false);
    for (const word of ["account", "coin", "online"]) assert.notEqual(translate(word), word, word);
  } finally {
    hodlSetLocale("en", false);
  }
});

for (const [name, words, target] of TRANSLATABLE) {
  for (const locale of LOCALES) {
    test(`${name}, language switched to ${locale}: the grid shows the words and a click copies them exactly`, withPage("works", async (document) => {
      const { button, render } = seedPage(document);
      render(words, target);
      hodlSetLocale(locale, false);
      button.click();
      await settle();
      assert.deepEqual(written, [words.join(" ")]);
      assert.deepEqual(shownWords(document, words.length), words);
      assert.deepEqual(leaks(button, words.join(" ")), []);
    }));

    test(`${name}, rendered in ${locale}: the grid shows the words and a click copies them exactly`, withPage("works", async (document) => {
      hodlSetLocale(locale, false);
      const { button, render } = seedPage(document);
      render(words, target);
      hodlApplyStaticI18n();
      button.click();
      await settle();
      assert.deepEqual(written, [words.join(" ")]);
      assert.deepEqual(shownWords(document, words.length), words);
      assert.deepEqual(leaks(button, words.join(" ")), []);
    }));
  }
}

// ---- The BIP-85 Station's child copy button --------------------------------

// The published BIP-85 test parent and its children (index 0).
const BIP85_MASTER = HDKey.fromExtendedKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb");
const CHILDREN = [
  ["BIP-39, 12 words", { app: "bip39", words: 12 }, "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"],
  ["BIP-39, 18 words", { app: "bip39", words: 18 }, "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"],
  ["BIP-39, 24 words", { app: "bip39", words: 24 }, "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"],
  ["WIF", { app: "wif" }, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"],
  ["XPRV", { app: "xprv" }, "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"],
  ["HEX, 64 bytes", { app: "hex", numBytes: 64 }, "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"],
  ["Base64 password", { app: "pwd-base64", length: 21 }, "dKLoepugzdVJvdL56ogNV"],
  ["Base85 password", { app: "pwd-base85", length: 12 }, "_s`{TW89)i4`"],
];
// A station holding the bench tab and every child, as Run leaves it.
function childState(spec, index) {
  const result = deriveApplication(BIP85_MASTER, spec);
  return { isLab: false, id: index, name: `child ${index}`, result, reveal: false, fingerprint: "0badc0de", fingerprintKind: "child", network: "mainnet", parentFingerprint: "f00dcafe" };
}
function bip85Page(document, active, revealed = true) {
  // The parent sits in the page too, in the station's root field.
  document.body.innerHTML = '<input id="bip85-key"><div id="bip85-out"></div>';
  document.getElementById("bip85-key").value = BIP85_MASTER.privateExtendedKey;
  const children = [{ isLab: true, id: 0, name: "BIP-85 Station", result: null, reveal: false, fingerprint: "", fingerprintKind: "" }, ...CHILDREN.map(([, spec], index) => ({ ...childState(spec, index + 1), reveal: revealed }))];
  station.__set.hodlBip85Children(children);
  const show = (index) => {
    station.__set.hodlActiveBip85(index);
    station.__set.hodlBip85Reveal(Boolean(children[index]?.reveal));
    station.hodlRenderBip85Out();
    return document.getElementById("bip85-copy");
  };
  return { children, show, button: show(active) };
}

test("the BIP-85 fixtures are the published children", () => {
  for (const [, spec, secret] of CHILDREN) assert.equal(deriveApplication(BIP85_MASTER, spec).secret, secret);
});

test("BIP-85 refuses to copy a hidden child", withPage("works", async (document) => {
  const { button } = bip85Page(document, 1);
  station.__set.hodlBip85Reveal(false);
  button.click();
  await settle();
  assert.deepEqual(written, [], "a hidden child reached the clipboard");
}));

test("BIP-85 renders no clipboard control for a concealed child", withPage("works", async (document) => {
  const { button } = bip85Page(document, 1, false);
  assert.equal(button, null);
  assert.equal(document.querySelector("[data-private-copy]"), null);
}));

test("BIP-85 refuses a detached control after switching children", withPage("works", async (document) => {
  const { button, show } = bip85Page(document, 1);
  show(2);
  button.click();
  await settle();
  assert.deepEqual(written, [], "a stale control copied the new child");
}));

for (const [index, [name, , secret]] of CHILDREN.entries()) {
  test(`BIP-85 ${name}: the button holds no secret in any attribute or property`, withPage("works", async (document) => {
    const { button } = bip85Page(document, index + 1);
    assert.ok(button, "a child of every type has the copy button");
    assert.deepEqual(leaks(button, secret), []);
    button.click();
    await settle();
    assert.deepEqual(leaks(button, secret), [], "after the click");
    mock.timers.tick(1600);
    assert.deepEqual(leaks(button, secret), [], "after the Copied note times out");
  }));

  test(`BIP-85 ${name}: a click copies exactly the child`, withPage("works", async (document) => {
    const { button } = bip85Page(document, index + 1);
    assert.equal(button.disabled, false);
    button.click();
    await settle();
    assert.deepEqual(written, [secret]);
    assert.equal(button.disabled, false);
  }));

  test(`BIP-85 ${name}: the fallback copy path gets exactly the child`, withPage("none", async (document) => {
    const { button } = bip85Page(document, index + 1);
    button.click();
    await settle();
    assert.deepEqual(executed, [["copy", secret]]);
  }));
}

test("BIP-85: a click copies the active child, whichever tab it is", withPage("works", async (document) => {
  const { show } = bip85Page(document, 1);
  // Forwards, backwards, and the same tab twice.
  for (const index of [4, 2, 8, 1, 1, 6]) {
    show(index).click();
    await settle();
    mock.timers.tick(1600);
  }
  assert.deepEqual(written, [4, 2, 8, 1, 1, 6].map((index) => CHILDREN[index - 1][2]));
}));

test("BIP-85: with no child on show there is no button to copy from", withPage("works", async (document) => {
  const { show } = bip85Page(document, 2);
  assert.equal(show(0), null, "the bench tab has no copy button");
  station.__set.hodlBip85Children([]);
  station.__set.hodlActiveBip85(-1);
  station.hodlRenderBip85Out();
  assert.equal(document.getElementById("bip85-copy"), null);
  assert.equal(document.getElementById("bip85-out").textContent, "");
}));

test("after the page's pagehide sweep the BIP-85 button copies nothing", withPage("works", async (document) => {
  const { button, children } = bip85Page(document, 4);
  // The sweep in app.js: it wipes every child's result and drops [data-phrase].
  for (const state of children) wipeBip85Result(state.result);
  document.querySelectorAll("[data-phrase]").forEach((element) => element.removeAttribute("data-phrase"));
  button.click();
  await settle();
  assert.deepEqual(written, []);
  assert.deepEqual(executed, []);
}));
