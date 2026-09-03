// Reversible physical-card backup for BIP39 entropy.
// This is deliberately separate from the existing cards -> SHA-256 input:
// hashes are suitable for conditioning entropy, but cannot be decoded.
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic, bip39English } from "./bip39.js";
import { sha256 } from "./hashes.js";

const RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "T", "J", "Q", "K"];
const SUITS = ["S", "H", "C", "D"];
const DECK = Object.freeze(SUITS.flatMap((suit) => RANKS.map((rank) => rank + suit)));
const WORD_BITS = Object.freeze({ 12: 128, 15: 160, 18: 192, 21: 224, 24: 256 });
const FACTORIAL = [1n];
for (let n = 1; n <= 52; n++) FACTORIAL[n] = FACTORIAL[n - 1] * BigInt(n);
const PREFIX_SIZE = 6;
const PREFIX_SPACE = FACTORIAL[52] / FACTORIAL[52 - PREFIX_SIZE];
function permutationCount(poolSize, length) {
  return FACTORIAL[poolSize] / FACTORIAL[poolSize - length];
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBytes(value, length) {
  const bytes = new Uint8Array(length);
  for (let index = length - 1; index >= 0; index--) {
    bytes[index] = Number(value & 255n);
    value >>= 8n;
  }
  return bytes;
}

// Lexicographic Lehmer-code ranking of a partial or complete permutation.
function rankPermutation(cards, pool = DECK) {
  let available = [...pool], rank = 0n;
  for (let index = 0; index < cards.length; index++) {
    const position = available.indexOf(cards[index]);
    if (position < 0) throw new Error("Card sequence is not a permutation of a standard deck.");
    rank += BigInt(position) * permutationCount(available.length - 1, cards.length - index - 1);
    available.splice(position, 1);
  }
  return rank;
}

function unrankPermutation(rank, length, pool = DECK) {
  let available = [...pool], cards = Array(length);
  for (let index = 0; index < length; index++) {
    const block = permutationCount(available.length - 1, length - index - 1);
    const position = Number(rank / block);
    rank %= block;
    cards[index] = available.splice(position, 1)[0];
  }
  return cards;
}

function normalizeDeck(cards) {
  const values = String(cards ?? "").toUpperCase().replace(/10/g, "T").match(/[A2-9TJQK][SHCD]/g) || [];
  return values;
}

function passphraseMarker(passphrase) {
  // This marker is only a check, never a replacement for the passphrase.
  // The passphrase itself cannot be encoded in a finite fixed-size deck.
  const digest = sha256(new TextEncoder().encode(String(passphrase ?? "").normalize("NFKD")));
  return [...digest.slice(0, 4)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function encodeMnemonicToDeck(mnemonic, passphrase = "") {
  const normalized = String(mnemonic ?? "").normalize("NFKD");
  if (!validateMnemonic(normalized, bip39English)) throw new Error("Invalid BIP39 mnemonic.");
  const words = normalized.split(" ").length;
  const bits = WORD_BITS[words];
  const entropy = mnemonicToEntropy(normalized, bip39English);
  const number = bytesToBigInt(entropy);
  let firstDeck, secondDeck = null;
  if (words === 24) {
    const prefixRank = number % PREFIX_SPACE;
    const deckRank = number / PREFIX_SPACE;
    firstDeck = unrankPermutation(deckRank, 52);
    const prefix = unrankPermutation(prefixRank, PREFIX_SIZE);
    secondDeck = [...prefix, ...DECK.filter((card) => !prefix.includes(card))];
  } else {
    firstDeck = unrankPermutation(number, 52);
  }
  return { words, bits, deck: firstDeck.join(" "), secondDeck: secondDeck?.join(" ") || "", passphraseMarker: passphraseMarker(passphrase) };
}

export function decodeDeckToMnemonic(deck, secondDeck = "", passphrase = "", words = secondDeck ? 24 : 12) {
  const first = normalizeDeck(deck);
  if (first.length !== 52 || new Set(first).size !== 52) throw new Error("The first deck must contain all 52 distinct cards.");
  const second = secondDeck ? normalizeDeck(secondDeck) : [];
  let number;
  if (secondDeck) {
    if (second.length !== 52 || new Set(second).size !== 52) throw new Error("The second deck must contain all 52 distinct cards.");
    const prefix = second.slice(0, PREFIX_SIZE);
    number = rankPermutation(first) * PREFIX_SPACE + rankPermutation(prefix);
    if (number >= (1n << 256n)) throw new Error("This card backup is outside the BIP39 24-word range.");
    const canonicalTail = DECK.filter((card) => !prefix.includes(card));
    if (second.slice(PREFIX_SIZE).some((card, index) => card !== canonicalTail[index])) throw new Error("The second deck tail is not the canonical tail for this backup.");
  } else {
    number = rankPermutation(first);
    if (number >= (1n << 224n)) throw new Error("A single deck cannot encode a 24-word backup; provide the second deck.");
  }
  if (!WORD_BITS[words] || (secondDeck ? words !== 24 : words === 24)) throw new Error("Select a supported word count; 24 words requires the second deck.");
  if (number >= (1n << BigInt(WORD_BITS[words]))) throw new Error("The card order is outside the selected BIP39 word-count range.");
  const length = WORD_BITS[words] / 8;
  const mnemonic = entropyToMnemonic(bigIntToBytes(number, length), bip39English);
  return { mnemonic, words: mnemonic.split(" ").length, passphraseMarker: passphraseMarker(passphrase) };
}

export { DECK, PREFIX_SIZE, PREFIX_SPACE, rankPermutation, unrankPermutation };
