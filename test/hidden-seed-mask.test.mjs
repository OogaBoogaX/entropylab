// A hidden seed phrase must not give away its words. The mask used to draw
// one bullet per letter of each word, so a screenshot of the hidden card
// showed every word's length: BIP39 words are 3 to 8 letters, and a length
// narrows a word from 2,048 candidates to between 88 and 555 (about 2.3 bits
// per word, 28 bits of a 12-word seed). The hidden field may show how many
// words there are, which its label already says, and nothing else.
//
// A hidden passphrase must not give away its length either, which narrows a
// search for it: the Key Station's BIP39 passphrase and the Journal's seed or
// passphrase field show one fixed placeholder, whatever they hold. (A hidden
// BIP-85 child phrase is tested with its station, in station-secrets.)
//
// Phrases: the published BIP39 vectors (trezor/python-mnemonic); seeds from
// @scure/bip39 as the reference library.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mnemonicToEntropy, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument } from "./mini-dom.mjs";

const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
const view = await loadAppFunctions(["hodlSeedPhraseField", "hodlSeedRecoveryFields", "hodlJournalPrivateValue"], {
  // The QR renderer is the uqr package, which the slice loader does not
  // import; the hidden card draws no QR.
  stubs: { hodlUqrRenderSvg: () => "" },
  settable: ["hodlRevealPrivate", "hodlJournalReveal"],
});
delete globalThis.document;
delete globalThis.window;

// Same word count, different word lengths.
const twelve = [
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "legal winner thank year wave sausage worth useful legal winner thank yellow",
  "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
];
const twentyFour = [
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
  "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
];
const label = (count) => `Your seed phrase \xB7 ${count} words`;
// Passphrases of different lengths, on both sides of the 12-character
// placeholder: the published vectors' own, and longer ones.
const passphrases = ["TREZOR", "twelve chars", "thirteen char", "correct horse battery staple", "p\xE4ssphr\xE4se \xFCber alles"];

test("a hidden seed phrase looks the same whatever its words are", () => {
  view.__set.hodlRevealPrivate(false);
  for (const [count, phrases] of [[12, twelve], [24, twentyFour]]) {
    const hidden = phrases.map((phrase) => view.hodlSeedPhraseField(label(count), phrase));
    assert.deepEqual(new Set(hidden).size, 1, `${count} words: the hidden field depends on the words`);
    const document = new MiniDocument();
    document.body.innerHTML = hidden[0];
    // Check data, including concealed attributes, without treating an HTML
    // attribute name such as "title" as a leaked BIP39 word.
    const values = [document.body.textContent, ...document.body.querySelectorAll("*").flatMap((node) => node.getAttributeNames().map((name) => node.getAttribute(name)))];
    for (const phrase of phrases) for (const word of new Set(phrase.split(" "))) assert.ok(values.every((value) => !value.includes(word)), `${count} words: the hidden field shows "${word}"`);
  }
});

test("a revealed seed phrase still shows every word in order", () => {
  view.__set.hodlRevealPrivate(true);
  for (const phrase of [...twelve, ...twentyFour]) {
    const html = view.hodlSeedPhraseField(label(phrase.split(" ").length), phrase);
    const shown = [...html.matchAll(/>([a-z]+)</g)].map((match) => match[1]);
    assert.deepEqual(shown, phrase.split(" "));
  }
});

// A seed wallet as the Key Station keeps it: entropy, seed and passphrase as
// bytes (#546 B2).
const wallet = (words, pass) => ({
  kind: "hd",
  entropy: mnemonicToEntropy(words, bip39English),
  seed: mnemonicToSeedSync(words, pass),
  passphrase: new TextEncoder().encode(pass),
  passphraseUsed: true,
});

test("a hidden BIP39 passphrase looks the same whatever its length", () => {
  view.__set.hodlRevealPrivate(false);
  const words = twelve[1];
  const hidden = passphrases.map((pass) => view.hodlSeedRecoveryFields(wallet(words, pass)).join(""));
  assert.equal(new Set(hidden).size, 1, "the hidden card depends on the passphrase");
  for (const pass of passphrases) assert.ok(!hidden[0].includes(pass), `the hidden card shows "${pass}"`);
});

test("a hidden Journal phrase looks the same whatever it holds", () => {
  view.__set.hodlJournalReveal(false);
  const values = [...twelve, ...twentyFour, ...passphrases];
  const hidden = values.map((value) => view.hodlJournalPrivateValue(value));
  assert.equal(new Set(hidden).size, 1, "the hidden field depends on the phrase");
  for (const value of values) for (const word of new Set(value.split(" "))) assert.ok(!hidden[0].includes(word), `the hidden field shows "${word}"`);
});

test("a revealed Journal phrase shows exactly what it holds", () => {
  view.__set.hodlJournalReveal(true);
  for (const value of [...twelve, ...passphrases]) assert.match(view.hodlJournalPrivateValue(value), new RegExp(`>${value}<`));
});
