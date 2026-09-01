// BIP39 word-number entry and one-based/zero-based translation.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateMnemonic } from "@scure/bip39";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not load ${name}`);
}

const hodlBip39Wordlist = Object.freeze(bip39English);
const hodlBip39WordIndex = new Map(hodlBip39Wordlist.map((word, index) => [word, index]));
const hodlSeedLengths = {
  12: { words: 12, bits: 128, bytes: 16, partialWords: 11, candidates: 128 },
  15: { words: 15, bits: 160, bytes: 20, partialWords: 14, candidates: 64 },
  18: { words: 18, bits: 192, bytes: 24, partialWords: 17, candidates: 32 },
  21: { words: 21, bits: 224, bytes: 28, partialWords: 20, candidates: 16 },
  24: { words: 24, bits: 256, bytes: 32, partialWords: 23, candidates: 8 },
};
const hodlSeedConfig = (words = 24) => hodlSeedLengths[words];
const hodlIsValidMnemonic = validateMnemonic;
const hodlNormalizeMnemonicText = (value) => String(value ?? "").trim().toLowerCase().replace(/\s+/g, " ");
const hodlLooksExtendedKey = () => false;
const hodlFilterSeedNumbers = new Function(`${loadSlice("hodlFilterSeedNumbers")}; return hodlFilterSeedNumbers;`)();
const hodlParseSeedNumbers = new Function("hodlSeedConfig", "hodlBip39Wordlist", "hodlIsValidMnemonic", `${loadSlice("hodlParseSeedNumbers")}; return hodlParseSeedNumbers;`)(hodlSeedConfig, hodlBip39Wordlist, hodlIsValidMnemonic);
const hodlSeedWordsToNumbers = new Function("hodlLooksExtendedKey", "hodlNormalizeMnemonicText", "hodlBip39WordIndex", `${loadSlice("hodlSeedWordsToNumbers")}; return hodlSeedWordsToNumbers;`)(hodlLooksExtendedKey, hodlNormalizeMnemonicText, hodlBip39WordIndex);
const hodlSeedNumbersToWords = new Function("hodlParseSeedNumbers", `${loadSlice("hodlSeedNumbersToWords")}; return hodlSeedNumbersToWords;`)(hodlParseSeedNumbers);
const hodlTranslateSeedNumberIndex = new Function(`${loadSlice("hodlTranslateSeedNumberIndex")}; return hodlTranslateSeedNumberIndex;`)();
const hodlSeedNumberCanInsertDigit = new Function(`${loadSlice("hodlSeedNumberCanInsertDigit")}; return hodlSeedNumberCanInsertDigit;`)();
const hodlAutocompleteSeedNumberInput = new Function("hodlSeedConfig", `${loadSlice("hodlAutocompleteSeedNumberInput")}; return hodlAutocompleteSeedNumberInput;`)(hodlSeedConfig);

test("word-number input keeps digits and single separators", () => {
  assert.equal(hodlFilterSeedNumbers("1,  2\n2048 words"), "1 2 2048 ");
  assert.equal(hodlFilterSeedNumbers("0 01 002 20", false), "1 2 20");
  assert.equal(hodlFilterSeedNumbers("0 01 002 20", true), "0 01 002 20");
});

test("one-based word numbers cannot start with zero", () => {
  const initial = { value: "", selectionStart: 0 };
  const afterSpace = { value: "12 ", selectionStart: 3 };
  const insideNumber = { value: "12", selectionStart: 2 };
  assert.equal(hodlSeedNumberCanInsertDigit(initial, "0", false), false);
  assert.equal(hodlSeedNumberCanInsertDigit(afterSpace, "0", false), false);
  assert.equal(hodlSeedNumberCanInsertDigit(insideNumber, "0", false), true);
  assert.equal(hodlSeedNumberCanInsertDigit(initial, "0", true), true);
});

test("unextendable word-number prefixes above 204 advance to the next word", () => {
  const input = {
    value: "1 205",
    selectionStart: 5,
    selectionEnd: 5,
    setRangeText(replacement, start, end) {
      this.value = this.value.slice(0, start) + replacement + this.value.slice(end);
      this.selectionStart = this.selectionEnd = start + replacement.length;
    },
  };
  assert.equal(hodlAutocompleteSeedNumberInput(input, { inputType: "insertText", data: "5" }, 24, false), true);
  assert.equal(input.value, "1 205 ");
  assert.equal(input.selectionStart, 6);

  input.value = "204";
  input.selectionStart = input.selectionEnd = 3;
  assert.equal(hodlAutocompleteSeedNumberInput(input, { inputType: "insertText", data: "4" }, 24, false), false);
  assert.equal(input.value, "204");
});

test("one-based and zero-based word numbers map to the same BIP39 words", () => {
  assert.deepEqual(hodlParseSeedNumbers("1 2 2048", 12, false).wordSlots, ["abandon", "ability", "zoo"]);
  assert.deepEqual(hodlParseSeedNumbers("0 1 2047", 12, true).wordSlots, ["abandon", "ability", "zoo"]);
  assert.equal(hodlSeedWordsToNumbers("abandon ability zoo", false), "1 2 2048");
  assert.equal(hodlSeedWordsToNumbers("abandon ability zoo", true), "0 1 2047");
});

test("the zero-index checkbox translation preserves represented words", () => {
  const oneBased = "1 2 2048";
  const zeroBased = hodlTranslateSeedNumberIndex(oneBased, true);
  assert.equal(zeroBased, "0 1 2047");
  assert.equal(hodlTranslateSeedNumberIndex(zeroBased, false), oneBased);
  assert.deepEqual(hodlParseSeedNumbers(oneBased, 12, false).wordSlots, hodlParseSeedNumbers(zeroBased, 12, true).wordSlots);
});

test("a complete numbered phrase follows normal BIP39 checksum validation", () => {
  const phrase = `${Array(11).fill("abandon").join(" ")} about`;
  const oneBased = `${Array(11).fill("1").join(" ")} 4`;
  const zeroBased = `${Array(11).fill("0").join(" ")} 3`;
  assert.equal(validateMnemonic(phrase, hodlBip39Wordlist), true);
  assert.equal(hodlParseSeedNumbers(oneBased, 12, false).complete, true);
  assert.equal(hodlParseSeedNumbers(zeroBased, 12, true).complete, true);
  assert.equal(hodlSeedNumbersToWords(oneBased, false, 12), phrase);
});

test("out-of-range, excess, and checksum-invalid numbers expose exact invalid ranges", () => {
  const outOfRange = hodlParseSeedNumbers("0 2049", 12, false);
  assert.deepEqual(outOfRange.invalidEntries.map((entry) => entry.token), ["0", "2049"]);
  const excess = hodlParseSeedNumbers(Array(13).fill("1").join(" "), 12, false);
  assert.equal(excess.extraEntries.length, 1);
  const badChecksum = hodlParseSeedNumbers(Array(12).fill("1").join(" "), 12, false);
  assert.equal(badChecksum.checksumInvalid, true);
  assert.deepEqual(badChecksum.invalidRanges.at(-1), [22, 23]);
});
