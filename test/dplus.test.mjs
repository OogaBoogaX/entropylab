// D++/Direct word selection final-roll parsing for every target word size.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { wordlist as hodlBip39Wordlist } from "@scure/bip39/wordlists/english.js";
import { validateMnemonic as hodlIsValidMnemonic } from "@scure/bip39";
import { t as hodlT } from "../src/js/i18n.js";

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
function loadVariableBeforeFunction(name, terminator) {
  const start = app.search(new RegExp(`var\\s+${name}\\s*=`));
  const end = app.indexOf(`function ${terminator}(`, start);
  assert.ok(start >= 0 && end > start, name);
  return app.slice(start, end);
}

const hodlSha256 = (input) => new Uint8Array(createHash("sha256").update(input).digest());
const api = new Function(
  "hodlBip39Wordlist",
  "hodlIsValidMnemonic",
  "hodlSha256",
  "hodlT",
  `
  var hodlTargetWordCount = 24;
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${loadVariableBeforeFunction("hodlDPlusFinalSpecs", "hodlDPlusStepBits")}
  ${["hodlNote", "hodlNoteKey", "hodlFormatNote", "hodlSeedConfig", "hodlDPlusStepBits", "hodlDPlusStepLabel", "hodlDPlusStepValue", "hodlDPlusFinalSteps", "hodlDPlusStepNoteLabel", "hodlDPlusFinalNote", "hodlDPlusFinalDescription", "hodlDPlusFinalHelp", "hodlDPlusStepChecksumLabel", "hodlDPlusD16Value", "hodlDPlusTokens", "hodlNormalizeMnemonicText", "hodlValidateMnemonic", "hodlTargetLastWords", "hodlComputeTargetLastWords", "hodlBitBoxLookupWord", "hodlDPlusRolls", "hodlValidateTargetMnemonic", "hodlSeedCountStatus"].map(loadSlice).join("\n")}
  var hodlLastWordCache = new Map();
  var hodlBip39WordSet = new Set(hodlBip39Wordlist);
  var hodlBip39WordIndex = new Map(hodlBip39Wordlist.map((word, index) => [word, index]));
  return { hodlDPlusRolls, hodlDPlusFinalSteps, hodlDPlusFinalDescription, hodlDPlusFinalHelp, hodlValidateTargetMnemonic, hodlSeedConfig };
  `,
)(hodlBip39Wordlist, hodlIsValidMnemonic, hodlSha256, hodlT);

const SIZES = [12, 15, 18, 21, 24];

test("D++ final-roll specs cover exactly log2(candidates) bits per size", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const steps = api.hodlDPlusFinalSteps(words);
    const bits = steps.reduce((acc, step) => acc + (step === "d8" ? 3 : step === "d16" ? 4 : 1), 0);
    assert.equal(bits, Math.log2(config.candidates), `${words}-word spec`);
  }
});

test("D++ parses and completes a valid transcript for every target size", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const group = "10E"; // valid D8 (1) + D16 (0) + D16 (E)
    const steps = api.hodlDPlusFinalSteps(words);
    const validFaces = steps.map((step) => (step === "d8" || step === "coin" ? "5" : "0"));
    const value = group.repeat(config.partialWords) + validFaces.join("");
    const parsed = api.hodlDPlusRolls(value, words);
    assert.equal(parsed.waiting, "complete", `${words}: waiting=${parsed.waiting}`);
    assert.equal(parsed.complete, true, `${words}: not complete`);
    assert.equal(parsed.allRolledValid, true, `${words}: not all valid`);
    if (!parsed.finalWord) assert.ok(false, `${words}: no final word`);
    const phrase = [...parsed.wordSlots, parsed.finalWord].join(" ");
    const bad = parsed.wordSlots.filter((w) => !w);
    assert.equal(bad.length, 0, `${words}: empty slots`);
    assert.equal(api.hodlValidateTargetMnemonic(phrase, words).ok, true, `${words}: ${phrase}`);
  }
});

test("D++ reports the next required roll through every phase", () => {
  const value12 = "10E".repeat(11);
  let parsed = api.hodlDPlusRolls(value12, 12);
  assert.equal(parsed.waiting, "checksum-d8");
  parsed = api.hodlDPlusRolls(value12 + "4", 12);
  assert.equal(parsed.waiting, "checksum-d16");
  parsed = api.hodlDPlusRolls("10E".repeat(2), 12);
  assert.equal(parsed.waiting, "d8");
  parsed = api.hodlDPlusRolls("10E1", 12);
  assert.equal(parsed.waiting, "d16-first");
  parsed = api.hodlDPlusRolls("10E1A", 12);
  assert.equal(parsed.waiting, "d16-second");
  parsed = api.hodlDPlusRolls("10E".repeat(11) + "G", 12);
  assert.equal(parsed.waiting, "correction");
  assert.equal(parsed.firstInvalid.final, true);
});

test("D++ canonical hex vectors match the published Keysa workflow", () => {
  const first = api.hodlDPlusRolls("100", 24);
  const last = api.hodlDPlusRolls("8FF", 24);
  assert.equal(first.groups[0].word, "abandon");
  assert.equal(last.groups[0].word, "zoo");
  assert.deepEqual(first.groups[0].faces, ["1", "0", "0"]);
  assert.deepEqual(last.groups[0].faces, ["8", "F", "F"]);
});

test("D++ picks a candidate with the same index the spec maps to", () => {
  const words = 15;
  const config = api.hodlSeedConfig(words);
  const parsed = api.hodlDPlusRolls("10E".repeat(config.partialWords) + "12", words);
  assert.equal(parsed.waiting, "complete");
  // (d8 - 1) * 8 + (d8 - 1) = 0 * 8 + 1 = 1
  assert.equal(parsed.finalWord, parsed.candidates[1]);
  const words21 = 21;
  const config21 = api.hodlSeedConfig(words21);
  const parsed21 = api.hodlDPlusRolls("10E".repeat(config21.partialWords) + "A", words21);
  assert.equal(parsed21.finalWord, parsed21.candidates[0xA]);
  const words18 = 18;
  const config18 = api.hodlSeedConfig(words18);
  const parsed18 = api.hodlDPlusRolls("10E".repeat(config18.partialWords) + "A5", words18);
  // (d16) * 2 + (coin >= 5 ? 1 : 0) = 10 * 2 + 1 = 21
  assert.equal(parsed18.finalWord, parsed18.candidates[21]);
  const words12 = 12;
  const config12 = api.hodlSeedConfig(words12);
  const parsed12 = api.hodlDPlusRolls("10E".repeat(config12.partialWords) + "3A", words12);
  // (d8 - 1) * 16 + (d16) = 2 * 16 + 10 = 42
  assert.equal(parsed12.finalWord, parsed12.candidates[42]);
  assert.equal(api.hodlValidateTargetMnemonic([...parsed12.wordSlots, parsed12.finalWord].join(" "), 12).ok, true);
});

test("D++, BitBox wording and help strings render for every size", () => {
  for (const words of SIZES) {
    assert.ok(api.hodlDPlusFinalDescription(words).length > 0, words);
    assert.ok(api.hodlDPlusFinalHelp(words).length > 0, words);
  }
});
