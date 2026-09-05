// Dice transcript analysis and the coin-position bookkeeping behind the
// BitBox "sixth die is a coin flip" method. The fairness suite stubs this
// analyzer out; these tests run the app's real code. The rebase math keeps
// "coin-derived" character indexes aligned across edits — a regression
// silently changes which characters count as entropy.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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

const api = new Function(
  `
  var hodlTargetWordCount = 24;
  var hodlDiceCoinPositions = [];
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${[
    "hodlSeedConfig",
    "hodlNormalizeDiceCoinPositions",
    "hodlRebaseDiceCoinPositions",
    "hodlResolveDiceInputEdit",
    "hodlAnalyzeDiceInput",
    "hodlBinarySelectionOffset",
    "hodlDPlusSeparator",
  ].map(loadSlice).join("\n")}
  function hodlDPlusRolls() { throw new Error("the D++ branch is covered by dplus.test.mjs"); }
  return {
    hodlAnalyzeDiceInput,
    hodlNormalizeDiceCoinPositions,
    hodlRebaseDiceCoinPositions,
    hodlResolveDiceInputEdit,
    hodlBinarySelectionOffset,
    hodlDPlusSeparator,
    setCoinPositions: (positions) => { hodlDiceCoinPositions = positions; },
    getCoinPositions: () => hodlDiceCoinPositions,
  };
  `,
)();

const {
  hodlAnalyzeDiceInput,
  hodlNormalizeDiceCoinPositions,
  hodlRebaseDiceCoinPositions,
  hodlResolveDiceInputEdit,
  hodlBinarySelectionOffset,
  hodlDPlusSeparator,
} = api;

test("coldcard/coleman analysis accepts dice, skips separators, rejects the rest", () => {
  for (const method of ["coldcard", "coleman"]) {
    const clean = hodlAnalyzeDiceInput("123456", method, 24, []);
    assert.deepEqual(clean.acceptedRolls, ["1", "2", "3", "4", "5", "6"], method);
    assert.deepEqual(clean.invalidRanges, [], method);
    const separated = hodlAnalyzeDiceInput("1 2,3;4|5\n6", method, 24, []);
    assert.deepEqual(separated.acceptedRolls, ["1", "2", "3", "4", "5", "6"], `${method}: separators are skipped`);
    for (const bad of ["0", "7", "9", "a"]) {
      assert.deepEqual(hodlAnalyzeDiceInput(bad, method, 24, []).invalidRanges, [[0, 1]], `${method}: ${bad}`);
    }
    // Coin letters are only meaningful in BitBox mode.
    for (const coin of ["h", "t", "H", "T"]) {
      assert.deepEqual(hodlAnalyzeDiceInput(coin, method, 24, []).invalidRanges, [[0, 1]], `${method}: ${coin}`);
    }
    // An astral character is one invalid range spanning both UTF-16 units.
    assert.deepEqual(hodlAnalyzeDiceInput("\u{1F600}", method, 24, []).invalidRanges, [[0, 2]], method);
  }
});

test("coin-button positions are excluded from the rolls and counted in range only", () => {
  const analysis = hodlAnalyzeDiceInput("123", "coldcard", 24, [1]);
  assert.deepEqual(analysis.acceptedRolls, ["1", "3"]);
  assert.deepEqual(analysis.invalidRanges, [[1, 2]]);
  assert.equal(analysis.coinDerivedCount, 1);
  assert.equal(hodlAnalyzeDiceInput("12", "coldcard", 24, [5, 99, -1]).coinDerivedCount, 0);
});

test("bitbox analysis enforces four low dice then a sixth die per word", () => {
  assert.equal(hodlAnalyzeDiceInput("1111", "bitbox", 12, []).diceInWord, 4);
  // Faces 5 and 6 are rerolled away on the first five dice of a word.
  assert.deepEqual(hodlAnalyzeDiceInput("11115", "bitbox", 12, []).invalidRanges, [[4, 5]]);
  assert.deepEqual(hodlAnalyzeDiceInput("11116", "bitbox", 12, []).invalidRanges, [[4, 5]]);
  const five = hodlAnalyzeDiceInput("11114", "bitbox", 12, []);
  assert.equal(five.diceInWord, 5);
  assert.equal(five.coinTurn, true, "the sixth roll doubles as the coin flip");
  assert.equal(five.complete, false);
  for (const sixth of ["1", "6"]) {
    const analysis = hodlAnalyzeDiceInput(`11114${sixth}`, "bitbox", 12, []);
    assert.equal(analysis.words, 1, `sixth roll ${sixth}`);
    assert.equal(analysis.diceInWord, 0, sixth);
    assert.equal(analysis.coinTurn, false, sixth);
  }
  // Coin letters never complete a word: the derivation parser
  // (hodlBitBoxRolls) and the input sanitizer both keep digits only, so the
  // analyzer must not disagree with them on a completed word.
  for (const coin of ["h", "t", "H", "T"]) {
    const analysis = hodlAnalyzeDiceInput(`11114${coin}`, "bitbox", 12, []);
    assert.equal(analysis.words, 0, `coin letter ${coin}`);
    assert.deepEqual(analysis.invalidRanges, [[5, 6]], coin);
    assert.equal(analysis.coinTurn, true, `${coin}: still waiting on the sixth die`);
    assert.equal(analysis.complete, false, coin);
  }
  // Anything else on the sixth roll is invalid.
  assert.deepEqual(hodlAnalyzeDiceInput("11114x", "bitbox", 12, []).invalidRanges, [[5, 6]]);
  // A full lookup-table run completes; anything after it is excess.
  const word = "111141";
  const full = hodlAnalyzeDiceInput(word.repeat(11), "bitbox", 12, []);
  assert.equal(full.words, 11);
  assert.equal(full.complete, true);
  const extra = hodlAnalyzeDiceInput(`${word.repeat(11)}1`, "bitbox", 12, []);
  assert.equal(extra.complete, true, "excess rolls do not un-complete the transcript");
  assert.deepEqual(extra.invalidRanges, [[66, 67]], "rolls past the lookup table are flagged");
});

test("coin positions normalize to sorted unique non-negative integers", () => {
  assert.deepEqual(hodlNormalizeDiceCoinPositions([5, 3, 5, -1, 2.5, "a", 0]), [0, 3, 5]);
  assert.deepEqual(hodlNormalizeDiceCoinPositions(null), []);
});

test("coin positions rebase across insertions and deletions", () => {
  const rebase = (positions, start, end, insertedLength, markInserted = false) => {
    api.setCoinPositions(positions);
    hodlRebaseDiceCoinPositions(start, end, insertedLength, markInserted);
    return api.getCoinPositions();
  };
  assert.deepEqual(rebase([2, 5, 9], 3, 3, 2), [2, 7, 11], "insertion shifts later positions");
  assert.deepEqual(rebase([2, 5, 9], 1, 4, 0), [2, 6], "a deletion drops the positions it covered");
  assert.deepEqual(rebase([2, 5], 1, 1, 3, true), [1, 2, 3, 5, 8], "pasted coin-derived text is marked");
  assert.deepEqual(rebase([0, 1, 2, 3], 0, 2, 0), [0, 1], "deleting the prefix rebases the rest");
});

test("edit resolution trusts only beforeinput-consistent edits", () => {
  assert.deepEqual(
    hodlResolveDiceInputEdit("13", "123", { value: "13", start: 1, end: 1, inputType: "insertText" }),
    { start: 1, end: 1, insertedLength: 1 },
  );
  assert.deepEqual(
    hodlResolveDiceInputEdit("abc", "aXc", { value: "abc", start: 1, end: 2, inputType: "insertText" }),
    { start: 1, end: 2, insertedLength: 1 },
    "a selection replaced by one character",
  );
  assert.deepEqual(
    hodlResolveDiceInputEdit("123", "13", { value: "123", start: 2, end: 2, inputType: "deleteContentBackward" }),
    { start: 1, end: 2, insertedLength: 0 },
  );
  assert.deepEqual(
    hodlResolveDiceInputEdit("123", "13", { value: "123", start: 1, end: 1, inputType: "deleteContentForward" }),
    { start: 1, end: 2, insertedLength: 0 },
  );
  // deleteByCut and friends cannot be located, so the tracker must fall back.
  assert.equal(hodlResolveDiceInputEdit("123", "13", { value: "123", start: 1, end: 1, inputType: "deleteByCut" }), null);
  assert.equal(hodlResolveDiceInputEdit("123", "13", null), null);
  assert.equal(
    hodlResolveDiceInputEdit("123", "13", { value: "stale", start: 1, end: 1, inputType: "deleteContentBackward" }),
    null,
    "a pending record from another value is ignored",
  );
  assert.equal(
    hodlResolveDiceInputEdit("abc", "axc", { value: "abc", start: 1, end: 1, inputType: "insertText" }),
    null,
    "prefix/suffix verification rejects inconsistent edits",
  );
});

test("grouped-binary caret offsets skip the every-11-bits separators", () => {
  assert.equal(hodlBinarySelectionOffset(0, 0), 0);
  assert.equal(hodlBinarySelectionOffset(0, 128), 0);
  assert.equal(hodlBinarySelectionOffset(5, 128), 5);
  assert.equal(hodlBinarySelectionOffset(11, 128), 12, "one separator before bit 11");
  assert.equal(hodlBinarySelectionOffset(22, 128), 24);
  assert.equal(hodlBinarySelectionOffset(128, 128), 139, "eleven separators in a 128-bit transcript");
  assert.equal(hodlBinarySelectionOffset(11, 11), 11, "a single group has no separator");
  assert.equal(hodlBinarySelectionOffset(11, 12), 12);
});

test("the D++ transcript separator lands on word boundaries only", () => {
  const seed24 = { partialWords: 23 };
  assert.equal(hodlDPlusSeparator(0, seed24), "");
  assert.equal(hodlDPlusSeparator(1, seed24), "");
  assert.equal(hodlDPlusSeparator(3, seed24), " ");
  assert.equal(hodlDPlusSeparator(66, seed24), " ");
  assert.equal(hodlDPlusSeparator(68, seed24), "");
  assert.equal(hodlDPlusSeparator(69, seed24), " ", "the boundary after the last lookup word");
  assert.equal(hodlDPlusSeparator(70, seed24), "", "the final-rolls region is never separated");
  const seed12 = { partialWords: 11 };
  assert.equal(hodlDPlusSeparator(33, seed12), " ");
  assert.equal(hodlDPlusSeparator(34, seed12), "");
});
