// Partial mnemonic previews: as the user types hex/binary/base-N entropy or
// dice rolls, the app shows the words the completed groups already fix. The
// preview must be a strict prefix of the mnemonic the finished input derives
// — otherwise the UI lies about the wallet being built. Cross-checked against
// @scure/bip39 and node:crypto (the same references dice-hashed uses).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hodlHexFormatLabels } from "../src/js/i18n-labels.js";
// The sliced app.js functions resolve the label tables through the global, like hodlT.
globalThis.hodlHexFormatLabels = hodlHexFormatLabels;
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

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
  throw new Error(`Could not extract ${name}`);
}

function loadVariable(name, nextName) {
  const start = app.search(new RegExp(`var\\s+${name}\\s*=`));
  const end = app.search(new RegExp(`var\\s+${nextName}\\s*=`));
  assert.ok(start >= 0 && end > start, name);
  return app.slice(start, end);
}

const hodlSha256 = (input) => new Uint8Array(createHash("sha256").update(input).digest());

const api = new Function(
  "hodlEntropyToMnemonic",
  "hodlBip39Wordlist",
  "hodlSha256",
  `
  var hodlTargetWordCount = 24;
  var hodlDiceCoinPositions = [];
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${loadVariable("hodlEntropyFormats", "hodlBip39WordSet")}
  ${[
    "hodlSeedConfig",
    "hodlNormalizeEntropyFormat",
    "hodlEntropyFormatConfig",
    "hodlNormalizeEntropyCharacter",
    "hodlEntropyDigitEntries",
    "hodlEntropyDigits",
    "hodlNumberBaseBits",
    "hodlAnalyzeEntropyInput",
    "hodlAnalyzeDiceInput",
    "hodlIanColemanDiceString",
    "hodlSplitDiceString",
    "hodlNumberBasePreviewWords",
    "hodlBinaryPreviewWords",
    "hodlHexPreviewWords",
    "hodlDicePreviewWords",
  ].map(loadSlice).join("\n")}
  function hodlDPlusRolls() { throw new Error("the D++ branch is covered by dplus.test.mjs"); }
  return {
    hodlNumberBasePreviewWords,
    hodlBinaryPreviewWords,
    hodlHexPreviewWords,
    hodlDicePreviewWords,
    setCoinPositions: (positions) => { hodlDiceCoinPositions = positions; },
  };
  `,
// The app calls the two-argument encoder with its frozen wordlist; forward the
// arguments so the comparison stays a differential against the app's bit math.
)((bytes, words) => entropyToMnemonic(bytes, words), wordlist, hodlSha256);

const { hodlNumberBasePreviewWords, hodlBinaryPreviewWords, hodlHexPreviewWords, hodlDicePreviewWords } = api;

// 32 bytes 00..1f: full 256-bit hex input for the 24-word target.
const FULL_HEX = Buffer.from(new Uint8Array(32).map((_, i) => i)).toString("hex");
const FULL_WORDS = entropyToMnemonic(Buffer.from(FULL_HEX, "hex"), wordlist).split(" ");

test("a complete hex input previews the full mnemonic", () => {
  assert.deepEqual(hodlHexPreviewWords(FULL_HEX, 24), FULL_WORDS);
  assert.equal(FULL_WORDS.length, 24, "fixture: the reference mnemonic is 24 words");
});

test("a partial hex input previews exactly the words its complete 11-bit groups fix", () => {
  // 22 hex characters = 88 bits = 8 complete groups.
  assert.deepEqual(hodlHexPreviewWords(FULL_HEX.slice(0, 22), 24), FULL_WORDS.slice(0, 8));
  // 63 hex characters = 252 bits = 22 complete groups (the 23rd word needs the final bits).
  assert.deepEqual(hodlHexPreviewWords(FULL_HEX.slice(0, 63), 24), FULL_WORDS.slice(0, 22));
  assert.deepEqual(hodlHexPreviewWords(FULL_HEX.slice(0, 2), 24), [], "8 bits complete no group");
  assert.deepEqual(hodlHexPreviewWords("", 24), []);
});

test("the hex preview hides on invalid characters or a bad final digit", () => {
  assert.deepEqual(hodlHexPreviewWords(`${FULL_HEX.slice(0, 40)}g`, 24), [], "an invalid character voids the preview");
  // base8 carries a 1-bit tail for a 24-word seed; a last digit past 0/1 is invalid.
  const base8Full = "0".repeat(86);
  assert.deepEqual(hodlNumberBasePreviewWords(base8Full, "base8", 24).length, 24, "fixture: a valid base8 input previews");
  assert.deepEqual(hodlNumberBasePreviewWords(`${"0".repeat(85)}7`, "base8", 24), [], "the tail digit may only be 0 or 1");
});

test("binary previews match the mnemonic of the same bits", () => {
  // 121 zero bits = 11 complete groups, all index 0.
  assert.deepEqual(hodlBinaryPreviewWords("0".repeat(121), 24), Array(11).fill("abandon"));
  const fullZero = entropyToMnemonic(new Uint8Array(16), wordlist).split(" ");
  assert.deepEqual(hodlBinaryPreviewWords("0".repeat(128), 12), fullZero);
  assert.equal(fullZero.join(" "), `${"abandon ".repeat(11)}about`, "fixture: the published all-zero mnemonic");
  // Grouped input (spaces every 11 bits, as the formatted field holds it) previews the same.
  assert.deepEqual(hodlBinaryPreviewWords("0".repeat(121).match(/.{1,11}/g).join(" "), 24), Array(11).fill("abandon"));
});

test("the dice preview hashes exactly the accepted rolls, matching scure", () => {
  const reference = (rolls) => entropyToMnemonic(hodlSha256(new TextEncoder().encode(rolls)).slice(0, 32), wordlist).split(" ");
  assert.deepEqual(hodlDicePreviewWords("1".repeat(99), "coldcard", 24), reference("1".repeat(99)));
  // The preview hashes whatever is present, even below the recommended count.
  assert.deepEqual(hodlDicePreviewWords("1".repeat(50), "coldcard", 24), reference("1".repeat(50)));
  // Keystone/Coleman mode maps 6 to 0 before hashing.
  assert.deepEqual(hodlDicePreviewWords("6".repeat(99), "coleman", 24), reference("0".repeat(99)));
});

test("the dice preview hides when the transcript is unusable", () => {
  assert.deepEqual(hodlDicePreviewWords("", "coldcard", 24), []);
  assert.deepEqual(hodlDicePreviewWords("123x", "coldcard", 24), [], "a non-dice character is leftover");
  api.setCoinPositions([1]);
  try {
    assert.deepEqual(hodlDicePreviewWords("1234", "coldcard", 24), [], "coin-derived digits are not preview entropy");
  } finally {
    api.setCoinPositions([]);
  }
});
