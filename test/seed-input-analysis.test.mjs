// Seed-phrase and BIP39-passphrase input analysis: the last-word candidate
// picker, checksum-error suppression while the final word can still be
// edited into a valid candidate, excess/invalid token flagging, and the
// on-screen keyboard gates. These decide what the user may type and what
// gets highlighted, so a regression either blocks valid phrases or waves
// invalid ones through.
//
// The slice keeps app.js's own import statements (pointed at src/) and the
// candidate sets are cross-checked by brute force against @scure/bip39.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { validateMnemonic as scureValidate } from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

// The analyzer reads document.activeElement to decide whether the word under
// the caret is still being typed; the tests drive that with a global stub.
globalThis.document = { activeElement: null };

function slice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

function importLine(module) {
  const match = app.match(new RegExp(`^import \\{[^}]*\\} from "\\./${module}\\.js";$`, "m"));
  assert.ok(match, `import from ./${module}.js`);
  return match[0].replace(`"./${module}.js"`, `"../src/js/${module}.js"`);
}

function between(startNeedle, endNeedle) {
  const start = app.indexOf(startNeedle);
  assert.ok(start >= 0, startNeedle);
  const end = app.indexOf(endNeedle, start);
  assert.ok(end > start, endNeedle);
  return app.slice(start, end + endNeedle.length);
}

const source = [
  importLine("hashes"),
  importLine("bip39"),
  importLine("bip39-english"),
  app.match(/^const hodlBip39Wordlist = .*$/m)[0],
  between("var hodlSeedLengths", "});"),
  between("var hodlBip39WordSet", ";"),
  "var hodlTargetWordCount = 24;",
  ...[
    "hodlSeedConfig",
    "hodlLooksExtendedKey",
    "hodlComputeTargetLastWords",
    "hodlSeedFinalWordContext",
    "hodlAnalyzeSeedInput",
    "hodlAnalyzeBip39Passphrase",
    "hodlSeedKeyboardCanEnterCharacter",
    "hodlSeedKeyboardCanEnterSpace",
    "hodlPassphraseBip39CanEnterCharacter",
    "hodlPassphraseBip39CanEnterSpace",
  ].map(slice),
  "export { hodlComputeTargetLastWords, hodlSeedFinalWordContext, hodlAnalyzeSeedInput, hodlAnalyzeBip39Passphrase, hodlSeedKeyboardCanEnterCharacter, hodlSeedKeyboardCanEnterSpace, hodlPassphraseBip39CanEnterCharacter, hodlPassphraseBip39CanEnterSpace };",
].join("\n");

const modulePath = join(root, "test", `.seed-input-analysis-${process.pid}.mjs`);
writeFileSync(modulePath, source);
let api;
try {
  api = await import(pathToFileURL(modulePath).href);
} finally {
  unlinkSync(modulePath);
}
const {
  hodlSeedFinalWordContext,
  hodlAnalyzeSeedInput,
  hodlAnalyzeBip39Passphrase,
  hodlSeedKeyboardCanEnterCharacter,
  hodlSeedKeyboardCanEnterSpace,
  hodlPassphraseBip39CanEnterCharacter,
  hodlPassphraseBip39CanEnterSpace,
} = api;

const bruteForceLastWords = (baseWords, targetWords) =>
  scureEnglish.filter((word) => scureValidate([...baseWords, word].join(" "), scureEnglish));

// BIP39 published vectors: entropy 00…00 is "abandon" ×11 + "about";
// entropy 7f…7f is "legal winner …" ×23 + "title".
const BASE_11 = Array(11).fill("abandon");
const BASE_23 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth".split(" ");

const inputOf = (value, caret = null) => {
  const at = caret ?? value.length;
  return { value, selectionStart: at, selectionEnd: at };
};

test("the last-word picker offers exactly the checksum-valid candidates", () => {
  const context12 = hodlSeedFinalWordContext(BASE_11.join(" "), 12);
  assert.equal(context12.candidates.length, 128);
  assert.ok(context12.candidates.includes("about"));
  assert.deepEqual([...context12.candidates].sort(), [...bruteForceLastWords(BASE_11, 12)].sort());
  const context24 = hodlSeedFinalWordContext(BASE_23.join(" "), 24);
  assert.equal(context24.candidates.length, 8);
  assert.ok(context24.candidates.includes("title"));
  assert.deepEqual([...context24.candidates].sort(), [...bruteForceLastWords(BASE_23, 24)].sort());
});

test("the last-word picker rejects unusable bases", () => {
  assert.equal(hodlSeedFinalWordContext(BASE_11.slice(0, 10).join(" "), 12), null, "too few words");
  assert.equal(hodlSeedFinalWordContext([...BASE_11, "about", "extra"].join(" "), 12), null, "too many words");
  assert.equal(hodlSeedFinalWordContext([...BASE_11.slice(0, 10), "zzzz"].join(" "), 12), null, "a non-list base word");
  assert.equal(hodlSeedFinalWordContext("", 12), null);
});

test("the last-word picker narrows by the in-progress prefix and selects only a full candidate", () => {
  const withPrefix = hodlSeedFinalWordContext([...BASE_23, "ti"].join(" "), 24);
  assert.deepEqual(withPrefix.matchingCandidates, withPrefix.candidates.filter((word) => word.startsWith("ti")));
  assert.ok(withPrefix.matchingCandidates.includes("title"));
  assert.equal(withPrefix.selected, "", "a bare prefix is not a selection");
  const full = hodlSeedFinalWordContext([...BASE_23, "title"].join(" "), 24);
  assert.equal(full.selected, "title");
});

test("seed analysis bypasses extended keys and flags excess and unknown words", () => {
  const xpub = `xpub${"A".repeat(108)}`;
  assert.ok(xpub.length > 80, "fixture: the pasted key must look extended");
  const bypassed = hodlAnalyzeSeedInput(inputOf(xpub), 24);
  assert.equal(bypassed.extendedKey, true);
  assert.deepEqual(bypassed.invalidRanges, []);
  const excess = hodlAnalyzeSeedInput(inputOf(Array(25).fill("abandon").join(" ")), 24);
  assert.equal(excess.excessCount, 1);
  assert.deepEqual(excess.invalidRanges.length, 1, "only the 25th word is excess");
  const unknown = hodlAnalyzeSeedInput(inputOf([...BASE_23, "zzzz"].join(" ")), 24);
  assert.deepEqual(unknown.invalidWords, [{ index: 23, word: "zzzz" }]);
});

test("seed analysis treats the word under the caret as a viable prefix", () => {
  const value = [...BASE_11, "ab"].join(" ");
  const focused = inputOf(value);
  globalThis.document.activeElement = focused;
  try {
    const analysis = hodlAnalyzeSeedInput(focused, 12);
    assert.deepEqual(analysis.invalidWords, [], "ab is a viable prefix while focused");
    assert.deepEqual(analysis.invalidRanges, []);
  } finally {
    globalThis.document.activeElement = null;
  }
  const blurred = hodlAnalyzeSeedInput(inputOf(value), 12);
  assert.deepEqual(blurred.invalidWords, [{ index: 11, word: "ab" }], "the same text is invalid once focus leaves");
});

test("a wrong-checksum final word is flagged once it can no longer become a candidate", () => {
  const wrong = hodlAnalyzeSeedInput(inputOf(Array(24).fill("abandon").join(" ")), 24);
  assert.equal(wrong.checksumInvalid, true);
  const lastStart = wrong.tokens[23].start;
  assert.deepEqual(wrong.invalidRanges, [[lastStart, wrong.tokens[23].end]], "the final word carries the highlight");
  const valid = hodlAnalyzeSeedInput(inputOf([...BASE_11, "about"].join(" ")), 12);
  assert.equal(valid.checksumInvalid, false);
  assert.deepEqual(valid.invalidRanges, []);
});

test("the checksum highlight is suppressed while the final word can still grow into a candidate", () => {
  // Find a base whose candidates include a word with a strict prefix that is
  // itself a BIP39 word but not a candidate (e.g. act/action): typing the
  // prefix must not raise the checksum error, because one more character can
  // still complete the phrase.
  let found = null;
  outer: for (const pivot of scureEnglish.slice(0, 600)) {
    const base = [...BASE_23.slice(0, 22), pivot];
    const context = hodlSeedFinalWordContext(base.join(" "), 24);
    if (!context) continue;
    for (const candidate of context.candidates) {
      for (let length = 1; length < candidate.length; length++) {
        const prefix = candidate.slice(0, length);
        if (scureEnglish.includes(prefix) && !context.candidates.includes(prefix)) {
          found = { base, candidate, prefix };
          break outer;
        }
      }
    }
  }
  assert.ok(found, "fixture: some base must offer a candidate with a word-shaped strict prefix");
  const { base, candidate, prefix } = found;
  assert.equal(scureValidate([...base, prefix].join(" "), scureEnglish), false, "fixture: the prefix alone is the wrong word");
  const value = [...base, prefix].join(" ");
  const focused = inputOf(value);
  globalThis.document.activeElement = focused;
  try {
    const suppressed = hodlAnalyzeSeedInput(focused, 24);
    assert.equal(suppressed.checksumInvalid, false, `${prefix} can still become ${candidate}`);
  } finally {
    globalThis.document.activeElement = null;
  }
  const committed = hodlAnalyzeSeedInput(inputOf(value), 24);
  assert.equal(committed.checksumInvalid, true, "the same wrong word is flagged once the caret leaves");
});

test("BIP39 passphrase analysis enforces listed words and single-space gaps", () => {
  let analysis = hodlAnalyzeBip39Passphrase("");
  assert.deepEqual(analysis, { tokens: [], invalidRanges: [], incomplete: false, completeWords: 0, trailingSeparator: false });
  analysis = hodlAnalyzeBip39Passphrase("abandon ability");
  assert.equal(analysis.completeWords, 2);
  assert.deepEqual(analysis.invalidRanges, []);
  analysis = hodlAnalyzeBip39Passphrase("abandon  ability");
  assert.deepEqual(analysis.invalidRanges, [[7, 9]], "a double-space gap is invalid");
  analysis = hodlAnalyzeBip39Passphrase(" abandon");
  assert.deepEqual(analysis.invalidRanges, [[0, 1]], "a leading gap is invalid");
  analysis = hodlAnalyzeBip39Passphrase("abandon ");
  assert.equal(analysis.trailingSeparator, true);
  assert.deepEqual(analysis.invalidRanges, [], "one trailing space after complete words is allowed");
  analysis = hodlAnalyzeBip39Passphrase("abandon  ");
  assert.deepEqual(analysis.invalidRanges, [[7, 9]], "a double trailing space is invalid");
  analysis = hodlAnalyzeBip39Passphrase("abandon zzz");
  assert.deepEqual(analysis.invalidRanges, [[8, 11]]);
  analysis = hodlAnalyzeBip39Passphrase("Abandon");
  assert.deepEqual(analysis.invalidRanges, [[0, 7]], "passphrase words are lowercase-only");
  // The word under the caret is an in-progress prefix, not an error.
  analysis = hodlAnalyzeBip39Passphrase("abandon aba", 11);
  assert.equal(analysis.incomplete, true);
  assert.deepEqual(analysis.invalidRanges, []);
  analysis = hodlAnalyzeBip39Passphrase("abandon aba");
  assert.deepEqual(analysis.invalidRanges, [[8, 11]], "without a caret the same token is invalid");
});

test("the seed keyboard admits only letters that keep every word viable", () => {
  const partial = inputOf("aban");
  assert.equal(hodlSeedKeyboardCanEnterCharacter(partial, "d", 12), true, "aband is a prefix of abandon");
  assert.equal(hodlSeedKeyboardCanEnterCharacter(partial, "x", 12), false);
  assert.equal(hodlSeedKeyboardCanEnterCharacter(partial, "1", 12), false, "no digits");
  assert.equal(hodlSeedKeyboardCanEnterCharacter(inputOf("aban"), "D", 12), true, "keys are lowercased");
  assert.equal(hodlSeedKeyboardCanEnterCharacter(inputOf("zzzz aban"), "d", 12), false, "an earlier invalid word blocks entry");
  const full = inputOf([...BASE_11, "about"].join(" "));
  assert.equal(hodlSeedKeyboardCanEnterCharacter(full, "a", 12), false, "a 13th word would exceed the cap");
  const extended = inputOf(`xpub${"A".repeat(90)}`);
  assert.equal(hodlSeedKeyboardCanEnterCharacter(extended, "a", 12), false, "extended-key pastes are not seed words");
});

test("the seed keyboard restricts the final word to checksum candidates", () => {
  const value = `${BASE_11.join(" ")} `;
  const candidates = hodlSeedFinalWordContext(BASE_11.join(" "), 12).candidates;
  const viable = "abcdefghijklmnopqrstuvwxyz".split("").find((letter) => candidates.some((word) => word.startsWith(letter)));
  const blocked = "abcdefghijklmnopqrstuvwxyz".split("").find((letter) => !candidates.some((word) => word.startsWith(letter)));
  assert.ok(viable && blocked, "fixture: the 128 candidates neither cover nor exclude every letter");
  assert.equal(hodlSeedKeyboardCanEnterCharacter(inputOf(value), viable, 12), true);
  assert.equal(hodlSeedKeyboardCanEnterCharacter(inputOf(value), blocked, 12), false);
});

test("the seed keyboard admits a space only after a complete word at the end", () => {
  assert.equal(hodlSeedKeyboardCanEnterSpace(inputOf("abandon"), 12), true);
  assert.equal(hodlSeedKeyboardCanEnterSpace(inputOf("abandon "), 12), false, "no doubled spaces");
  assert.equal(hodlSeedKeyboardCanEnterSpace(inputOf("aban"), 12), false, "no space after an incomplete word");
  assert.equal(hodlSeedKeyboardCanEnterSpace(inputOf("zzzz"), 12), false, "no space after an invalid word");
  assert.equal(hodlSeedKeyboardCanEnterSpace(inputOf(""), 12), false, "no leading space");
  assert.equal(hodlSeedKeyboardCanEnterSpace(inputOf([...BASE_11, "about"].join(" ")), 12), false, "the phrase is already at the cap");
  const midCaret = inputOf("abandon ability", 3);
  assert.equal(hodlSeedKeyboardCanEnterSpace(midCaret, 12), false, "spaces are only appended at the end");
  const selection = { value: "abandon", selectionStart: 0, selectionEnd: 3 };
  assert.equal(hodlSeedKeyboardCanEnterSpace(selection, 12), false, "a selection is not a word boundary");
});

test("the passphrase keyboard blocks any keystroke that breaks word-list validity", () => {
  assert.equal(hodlPassphraseBip39CanEnterCharacter(inputOf("abandon"), "x"), false, "abandonx is beyond every word");
  assert.equal(hodlPassphraseBip39CanEnterCharacter(inputOf("aba"), "n"), true, "aban is a prefix of abandon");
  assert.equal(hodlPassphraseBip39CanEnterCharacter(inputOf("abandon", 3), "x"), false, "insertions mid-word are checked too");
  assert.equal(hodlPassphraseBip39CanEnterCharacter(inputOf("abandon"), "X"), false, "uppercase is not lowered here");
  assert.equal(hodlPassphraseBip39CanEnterCharacter(inputOf("abandon"), "1"), false);
  assert.equal(hodlPassphraseBip39CanEnterSpace(inputOf("abandon")), true);
  assert.equal(hodlPassphraseBip39CanEnterSpace(inputOf("abandon ")), false);
  assert.equal(hodlPassphraseBip39CanEnterSpace(inputOf("aba")), false, "no space while a word is incomplete");
  assert.equal(hodlPassphraseBip39CanEnterSpace(inputOf("")), false);
  assert.equal(hodlPassphraseBip39CanEnterSpace(inputOf("abandon zzz")), false, "no space after an invalid word");
});
