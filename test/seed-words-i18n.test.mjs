// #610: a seed word on screen is data, not copy. Three BIP39 English words,
// "account", "coin" and "online", are also translation catalog keys, and the
// page's translation sweep (i18n.js, run on every language switch and at
// boot) rewrites any text node whose text is a key. Wherever the page shows a
// seed word as an element's whole text, a language switch used to replace it
// with a translation ("cuenta", "Konto", "en ligne"): the wallet's revealed
// seed phrase, the final-word picker (its options and the custom select that
// mirrors them) and the D++, BitBox and number-base calculation panels. The
// Key Station word grid had the same bug, fixed in #609.
//
// Security contract: every seed word the page shows is the same word in
// every language; the text around it still translates.
//
// The tests need no second implementation: each place is rendered by the
// app's own code (test/app-slice-harness.mjs, test/mini-dom.mjs), the custom
// select is the app's own enhanced-inputs.js, and the sweep is i18n.js with
// the real catalogs. What a place shows in English is the reference, and it
// must be shown unchanged after a switch to es, pt, fr and de, and when
// rendered in those languages. Fixtures: phrases built to contain all three
// words, turned into mnemonics by @scure/bip39; the valid final words of an
// 11-word prefix, from @scure/bip39; and dice rolls chosen by the published
// D++ and BitBox mappings, checked below to show those words in English.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { hodlSetLocale, t as translate } from "../src/js/i18n.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument, MiniElement, MiniNodeFilter } from "./mini-dom.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const enhancedInputs = readFileSync(join(root, "src/js/enhanced-inputs.js"), "utf8");
const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
const app = await loadAppFunctions(["hodlSeedPhraseField", "hodlRenderLastWordPicker", "hodlManualCalculationMarkup", "hodlRenderNumberBaseCalculations"], { settable: ["hodlRevealPrivate"] });
delete globalThis.document;
delete globalThis.window;

const COLLIDING = ["account", "coin", "online"];
const LOCALES = ["es", "pt", "fr", "de"];
const BIP39 = new Set(wordlist);
const bytesFromBits = (bits) => Uint8Array.from(bits.match(/.{8}/g), (byte) => parseInt(byte, 2));
// Entropy whose phrase starts with the given words: their 11-bit indices, then
// zero bits.
const entropyStartingWith = (words, bytes) => bytesFromBits(words.map((word) => wordlist.indexOf(word).toString(2).padStart(11, "0")).join("").padEnd(bytes * 8, "0"));
const PHRASE_24 = entropyToMnemonic(entropyStartingWith(["online", "legal", "coin", "winner", "account", "coin", "online", "account"], 32), wordlist);
const HEX_12 = Buffer.from(entropyStartingWith(["coin", "online", "account", "zoo", "coin"], 16)).toString("hex");
// The valid final words after 11 words: every 7-bit ending, checksum by @scure/bip39.
const PREFIX = "abandon abandon abandon abandon abandon abandon abandon abandon abandon legal below".split(" ");
const FINAL_WORDS = Array.from({ length: 128 }, (_, ending) => entropyToMnemonic(bytesFromBits(PREFIX.map((word) => wordlist.indexOf(word).toString(2).padStart(11, "0")).join("") + ending.toString(2).padStart(7, "0")), wordlist).split(" ").pop());
// D++: word index = D8 value x 256 + D16 x 16 + D16, a D8 face being its value
// plus one. BitBox: five dice on faces 1-4 as base-4 digits, doubled, plus a
// coin bit (faces 1-3 heads = 0, 4-6 tails = 1). account 12, coin 363, online 1239.
const DPLUS_ROLLS = "10C" + "26B" + "5D7";
const BITBOX_ROLLS = "111231" + "134226" + "323346";

function page() {
  globalThis.document = new MiniDocument();
  globalThis.NodeFilter = MiniNodeFilter;
  return globalThis.document;
}
function leave() {
  hodlSetLocale("en", false);
  delete globalThis.NodeFilter;
  delete globalThis.document;
}
// The custom select, as the page runs it: it replaces every select already in
// the document.
const enhanceSelects = (document) => new Function("document", "Element", "MutationObserver", "Event", enhancedInputs)(document, MiniElement, class { observe() {} }, class {});
// Every text node in the page, in order.
const texts = (document) => {
  const walker = document.createTreeWalker(document.body, MiniNodeFilter.SHOW_TEXT), out = [];
  for (let node; (node = walker.nextNode()); ) out.push(node.nodeValue);
  return out;
};
const seedPositions = (english) => english.flatMap((text, index) => BIP39.has(text.trim()) ? [index] : []);

const picker = (candidates, selected, forceSelect) => (document) => {
  document.body.innerHTML = '<div id="last-words"></div>';
  app.hodlRenderLastWordPicker(document.getElementById("last-words"), candidates, selected, () => {}, { forceSelect, targetWords: 12 });
  enhanceSelects(document);
};
// [place, render into the page, the text around the words that must still translate]
const PLACES = [
  ["the revealed seed phrase", (document) => {
    app.__set.hodlRevealPrivate(true);
    document.body.innerHTML = `<div id="out">${app.hodlSeedPhraseField("Your seed phrase \xB7 24 words", PHRASE_24)}</div>`;
  }],
  ["the final-word picker", picker(FINAL_WORDS, "", true), "Choose a confirmed final word"],
  ["the final-word picker with a word chosen", picker(FINAL_WORDS, "account", true)],
  ["the final-word picker as buttons", picker(["account", "coin", "online", "zoo"], "", false)],
  ["the D++ calculations", (document) => {
    document.body.innerHTML = app.hodlManualCalculationMarkup("dplus", DPLUS_ROLLS, 12);
  }],
  ["the BitBox calculations", (document) => {
    document.body.innerHTML = app.hodlManualCalculationMarkup("bitbox", BITBOX_ROLLS, 12);
  }],
  ["the number-base calculations", (document) => {
    document.body.innerHTML = '<input id="show-number-base-calculations"><div id="number-base-calculations"></div>';
    document.getElementById("show-number-base-calculations").checked = true;
    app.hodlRenderNumberBaseCalculations(HEX_12, "hex", 12);
  }],
];

for (const [place, render, around] of PLACES) {
  test(`${place} shows all three words in English`, () => {
    const document = page();
    try {
      render(document);
      const english = texts(document), words = seedPositions(english).map((index) => english[index].trim());
      for (const word of COLLIDING) assert.ok(words.includes(word), `${word} is not shown`);
      if (around) assert.ok(english.includes(around), "the text around the words is on the page");
    } finally {
      leave();
    }
  });

  for (const locale of LOCALES) {
    test(`${place}, language switched to ${locale}: every seed word is unchanged`, () => {
      const document = page();
      try {
        render(document);
        const english = texts(document), at = seedPositions(english);
        hodlSetLocale(locale, false);
        const after = texts(document);
        assert.equal(after.length, english.length, "the switch changed no structure");
        assert.deepEqual(at.map((index) => after[index]), at.map((index) => english[index]));
        // A mark on more than the words would keep the text around them in English.
        if (around) {
          const translated = translate(around);
          assert.notEqual(translated, around, "the catalog translates the text around the words");
          assert.equal(english.filter((text) => text === around).length, after.filter((text) => text === translated).length, "the text around the words translates everywhere it is shown");
        }
      } finally {
        leave();
      }
    });

    test(`${place}, rendered in ${locale}: every seed word is the English one`, () => {
      let english;
      const document = page();
      try {
        render(document);
        english = texts(document);
        hodlSetLocale(locale, false);
        render(page());
        hodlSetLocale(locale, false);
        const after = texts(globalThis.document), at = seedPositions(english);
        assert.equal(after.length, english.length, "the same structure in every language");
        assert.deepEqual(at.map((index) => after[index]), at.map((index) => english[index]));
      } finally {
        leave();
      }
    });
  }
}
