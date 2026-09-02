// BitBox diceware / Direct word selection for every target word size.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { wordlist as hodlBip39Wordlist } from "@scure/bip39/wordlists/english.js";
import { validateMnemonic as hodlIsValidMnemonic } from "@scure/bip39";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}
function loadVariable(name, nextName) {
  const start = app.search(new RegExp(`var\\s+${name}\\s*=`));
  const end = app.search(new RegExp(`var\\s+${nextName}\\s*=`));
  assert.ok(start >= 0 && end > start, name);
  return app.slice(start, end);
}

const hodlSha256 = (input) => new Uint8Array(createHash("sha256").update(input).digest());
const api = new Function(
  "hodlBip39Wordlist",
  "hodlIsValidMnemonic",
  "hodlSha256",
  `
  var hodlTargetWordCount = 24;
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${["hodlNote", "hodlSeedConfig", "hodlBitBoxLookupWord", "hodlTargetLastWords", "hodlComputeTargetLastWords", "hodlNormalizeMnemonicText", "hodlValidateMnemonic", "hodlBitBoxRolls", "hodlValidateTargetMnemonic", "hodlSeedCountStatus"].map(loadSlice).join("\n")}
  var hodlLastWordCache = new Map();
  var hodlBip39WordSet = new Set(hodlBip39Wordlist);
  var hodlBip39WordIndex = new Map(hodlBip39Wordlist.map((word, index) => [word, index]));
  return { hodlBitBoxRolls, hodlTargetLastWords, hodlValidateTargetMnemonic, hodlSeedConfig, hodlBitBoxLookupWord };
  `,
)(hodlBip39Wordlist, hodlIsValidMnemonic, hodlSha256);

const SIZES = [12, 15, 18, 21, 24];

test("BitBox diceware reaches the checksum pick for every target size", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    // Each word: a stray 5 skipped as a reroll, five dice showing 1-4, then
    // the sixth die (1-3 means Heads) as its coin flip.
    const word = "5" + "12341" + "3";
    const parsed = api.hodlBitBoxRolls(word.repeat(config.partialWords), words);
    assert.equal(parsed.waiting, "last-word", `${words}: waiting=${parsed.waiting}`);
    assert.equal(parsed.words.length, config.partialWords, `${words}: ${parsed.words.length}`);
    assert.ok(parsed.skippedHigh >= config.partialWords, `${words}: reroll faces were not skipped`);
    const options = api.hodlTargetLastWords(parsed.words.join(" "), words);
    assert.equal(options.candidates.length, config.candidates, `${words}-word candidates`);
    for (const candidate of options.candidates) {
      assert.equal(api.hodlValidateTargetMnemonic([...parsed.words, candidate].join(" "), words).ok, true, `${words}: ${candidate}`);
    }
  }
});

// Rows transcribed from the official BitBox02 Diceware lookup table
// (BitBox_Diceware_LookupTable.pdf): die 1 selects the page, dice 1-4 the row,
// and die 5 plus the coin the column. "1 2 3 heads" is the even column of a
// pair, "4 5 6 tails" the odd one.
const OFFICIAL_ROWS = [
  [[1, 1, 1, 1], ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract"]],
  [[1, 4, 4, 3], ["dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover"]],
  [[2, 4, 4, 2], ["laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law"]],
  [[3, 4, 4, 1], ["rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude"]],
  [[4, 4, 3, 3], ["wheel", "when", "where", "whip", "whisper", "wide", "width", "wife"]],
  [[4, 4, 4, 4], ["yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"]],
];

test("BitBox rolls map to the official lookup-table words", () => {
  for (const [dice, words] of OFFICIAL_ROWS) {
    const transcript = words.map((_, column) => {
      const die5 = (column >> 1) + 1;
      const coin = column & 1 ? 4 : 3; // heads column via a 3, tails via a 4
      return [...dice, die5, coin].join("");
    }).join(" ");
    assert.deepEqual(api.hodlBitBoxRolls(transcript, 24).words, words, `row ${dice.join("")}`);
  }
});

test("every dice combination lands on the table's BIP39-order index", () => {
  // The table is the BIP39 English list in order: page (die 1) * 512 +
  // row (dice 2-4) * 8 + column (die 5) * 2 + coin (heads 0, tails 1).
  for (let d1 = 1; d1 <= 4; d1++) for (let d2 = 1; d2 <= 4; d2++) for (let d3 = 1; d3 <= 4; d3++) for (let d4 = 1; d4 <= 4; d4++) {
    for (let d5 = 1; d5 <= 4; d5++) {
      for (const coin of [0, 1]) {
        const index = (d1 - 1) * 512 + (d2 - 1) * 128 + (d3 - 1) * 32 + (d4 - 1) * 8 + (d5 - 1) * 2 + coin;
        assert.equal(api.hodlBitBoxLookupWord([d1, d2, d3, d4, d5], coin), hodlBip39Wordlist[index], `${d1}${d2}${d3}${d4}${d5} coin ${coin}`);
      }
    }
  }
});

test("checksum pick matches the BitBox02 lastword choices", () => {
  // What a BitBox02 displays after 23 x "abandon" (firmware lastword_choices:
  // word index = suffix << 8 | sha256(seed)[0], suffix ascending).
  const options = api.hodlTargetLastWords(Array(23).fill("abandon").join(" "), 24);
  assert.deepEqual(options.candidates, ["art", "diesel", "false", "kite", "organ", "ready", "surface", "trouble"]);
});
