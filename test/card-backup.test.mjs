import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeMnemonicToDeck, decodeDeckToMnemonic, DECK, PREFIX_SIZE } from "../src/js/card-backup.js";
import { entropyToMnemonic, bip39English } from "../src/js/bip39.js";

const MNEMONICS = Object.fromEntries([[12, 16], [15, 20], [18, 24], [21, 28], [24, 32]].map(([words, bytes]) => [words, entropyToMnemonic(Uint8Array.from({ length: bytes }, (_, index) => (index * 37 + 11) & 255), bip39English)]));

for (const [words, mnemonic] of Object.entries(MNEMONICS)) {
  test(`card backup round-trips ${words} words`, () => {
    const encoded = encodeMnemonicToDeck(mnemonic, "correct horse battery staple");
    assert.equal(encoded.words, Number(words));
    assert.equal(encoded.deck.split(" ").length, 52);
    assert.equal(new Set(encoded.deck.split(" ")).size, 52);
    if (Number(words) === 24) {
      assert.equal(encoded.secondDeck.split(" ").length, 52);
      assert.equal(encoded.secondDeck.split(" ").slice(0, PREFIX_SIZE).length, PREFIX_SIZE);
    } else assert.equal(encoded.secondDeck, "");
    const decoded = decodeDeckToMnemonic(encoded.deck, encoded.secondDeck, "correct horse battery staple");
    assert.equal(decoded.words, Number(words));
    assert.equal(decoded.mnemonic, mnemonic);
    assert.equal(decoded.passphraseMarker, encoded.passphraseMarker);
    const pinned = decodeDeckToMnemonic(encoded.deck, encoded.secondDeck, "correct horse battery staple", Number(words));
    assert.equal(pinned.mnemonic, mnemonic);
  });
}

test("24-word backup round-trips with just the 6-card prefix", () => {
  const encoded = encodeMnemonicToDeck(MNEMONICS[24], "passphrase");
  const prefix = encoded.secondDeck.split(" ").slice(0, PREFIX_SIZE).join(" ");
  const decoded = decodeDeckToMnemonic(encoded.deck, prefix, "passphrase");
  assert.equal(decoded.words, 24);
  assert.equal(decoded.mnemonic, MNEMONICS[24]);
});

test("second deck rejects fewer than 6 cards", () => {
  const encoded = encodeMnemonicToDeck(MNEMONICS[24]);
  const short = encoded.secondDeck.split(" ").slice(0, 5).join(" ");
  assert.throws(() => decodeDeckToMnemonic(encoded.deck, short), /6 cards|52/);
});

test("full second deck with a wrong tail is rejected", () => {
  const encoded = encodeMnemonicToDeck(MNEMONICS[24]);
  const cards = encoded.secondDeck.split(" ");
  const tampered = [...cards.slice(0, PREFIX_SIZE), ...cards.slice(PREFIX_SIZE).reverse()].join(" ");
  assert.throws(() => decodeDeckToMnemonic(encoded.deck, tampered), /canonical tail/);
});

test("recovery needs no length choice: sizes stay disjoint", () => {
  const decks = Object.entries(MNEMONICS)
    .filter(([words]) => Number(words) !== 24)
    .map(([, mnemonic]) => encodeMnemonicToDeck(mnemonic).deck);
  assert.equal(new Set(decks).size, decks.length);
  for (const [words, mnemonic] of Object.entries(MNEMONICS).filter(([words]) => Number(words) !== 24)) {
    const encoded = encodeMnemonicToDeck(mnemonic);
    assert.equal(decodeDeckToMnemonic(encoded.deck).words, Number(words));
  }
});

test("an explicit word count that disagrees with the deck is rejected", () => {
  const encoded = encodeMnemonicToDeck(MNEMONICS[18]);
  assert.throws(() => decodeDeckToMnemonic(encoded.deck, "", "", 12), /encodes an? 18-word backup, not 12/);
});

test("the zero 24-word vector is two canonical decks", () => {
  const encoded = encodeMnemonicToDeck(entropyToMnemonic(new Uint8Array(32), bip39English));
  assert.equal(encoded.deck, DECK.join(" "));
  assert.equal(encoded.secondDeck, DECK.join(" "));
});

test("one deck cannot be mistaken for a 24-word backup", () => {
  assert.throws(() => decodeDeckToMnemonic(DECK.join(" "), "", "", 24), /24 words requires/);
});

test("a rank beyond every encoded interval is rejected", () => {
  const reversed = [...DECK].reverse().join(" ");
  assert.throws(() => decodeDeckToMnemonic(reversed), /valid single-deck backup/);
});

test("passphrase marker changes without exposing the passphrase", () => {
  const encoded = encodeMnemonicToDeck(MNEMONICS[12], "one");
  const other = encodeMnemonicToDeck(MNEMONICS[12], "two");
  assert.notEqual(encoded.passphraseMarker, other.passphraseMarker);
  assert.doesNotMatch(encoded.deck, /one/);
});
