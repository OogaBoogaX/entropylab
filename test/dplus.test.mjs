// D++/Direct word selection final-roll parsing for every target word size.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { wordlist as Ae } from "@scure/bip39/wordlists/english.js";
import { validateMnemonic as Pn } from "@scure/bip39";

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

const Z = (input) => new Uint8Array(createHash("sha256").update(input).digest());
const api = new Function(
  "Ae",
  "Pn",
  "Z",
  `
  var Pt = 24;
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${loadVariableBeforeFunction("hodlDPlusFinalSpecs", "hodlDPlusStepBits")}
  ${["hodlSeedConfig", "hodlDPlusStepBits", "hodlDPlusStepLabel", "hodlDPlusStepValue", "hodlDPlusFinalSteps", "hodlDPlusFinalDescription", "hodlDPlusFinalHelp", "hodlDPlusStepChecksumLabel", "hodlDPlusD16Value", "hodlDPlusTokens", "hodlConvertDPlusNotation", "hodlDPlusConvertedOffset", "hodlDPlusAllowedCharacters", "hodlDPlusSeparator", "hodlSanitizeDPlusInput", "Rn", "Mt", "hodlTargetLastWords", "hodlComputeTargetLastWords", "mi", "hodlDPlusRolls", "hodlValidateTargetMnemonic", "hodlSeedCountStatus"].map(loadSlice).join("\n")}
  var hodlLastWordCache = new Map();
  var hodlBip39WordSet = new Set(Ae);
  var hodlBip39WordIndex = new Map(Ae.map((word, index) => [word, index]));
  return { hodlDPlusRolls, hodlDPlusFinalSteps, hodlDPlusFinalDescription, hodlDPlusFinalHelp, hodlConvertDPlusNotation, hodlDPlusConvertedOffset, hodlSanitizeDPlusInput, hodlValidateTargetMnemonic, hodlSeedConfig };
  `,
)(Ae, Pn, Z);

const updateButtons = new Function(`
  var ge = "dplus", hodlDPlusNumberedD16 = true;
  ${loadSlice("hodlDPlusD16Value")}
  ${loadSlice("hodlUpdateDiceButtons")}
  return hodlUpdateDiceButtons;
`)();

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
    const parsed = api.hodlDPlusRolls(value, words, false);
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
  let parsed = api.hodlDPlusRolls(value12, 12, false);
  assert.equal(parsed.waiting, "checksum-d8");
  parsed = api.hodlDPlusRolls(value12 + "4", 12, false);
  assert.equal(parsed.waiting, "checksum-d16");
  parsed = api.hodlDPlusRolls("10E".repeat(2), 12, false);
  assert.equal(parsed.waiting, "d8");
  parsed = api.hodlDPlusRolls("10E1", 12, false);
  assert.equal(parsed.waiting, "d16-first");
  parsed = api.hodlDPlusRolls("10E1A", 12, false);
  assert.equal(parsed.waiting, "d16-second");
  parsed = api.hodlDPlusRolls("10E".repeat(11) + "G", 12, false);
  assert.equal(parsed.waiting, "correction");
  assert.equal(parsed.firstInvalid.final, true);
});

test("decimal D16 tokens preserve multi-digit physical rolls", () => {
  const parsed = api.hodlDPlusRolls("1 16 16", 12, true);
  assert.equal(parsed.groups[0].word, "abandon");
  assert.deepEqual(parsed.groups[0].faces, ["1", "16", "16"]);
  assert.equal(parsed.entries.length, 3);
});

test("decimal and hexadecimal D16 transcripts select identical mnemonics", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const steps = api.hodlDPlusFinalSteps(words);
    const hexFinal = steps.map((step) => step === "d16" ? "0" : "1").join("");
    const decimalFinal = steps.map((step) => step === "d16" ? "16" : "1").join(" ");
    const hex = api.hodlDPlusRolls("100".repeat(config.partialWords) + hexFinal, words, false);
    const decimal = api.hodlDPlusRolls(`${Array(config.partialWords).fill("1 16 16").join(" ")} ${decimalFinal}`, words, true);
    assert.equal(decimal.complete, true, `${words}: decimal transcript incomplete`);
    assert.deepEqual(decimal.wordSlots, hex.wordSlots, `${words}: partial words differ`);
    assert.equal(decimal.finalWord, hex.finalWord, `${words}: final word differs`);
  }
});

test("decimal D16 counts values 10 through 16 as one physical roll each", () => {
  for (let face = 10; face <= 16; face++) {
    const parsed = api.hodlDPlusRolls(`1 ${face} 16`, 12, true);
    assert.equal(parsed.entries.length, 3, face);
    assert.equal(parsed.groups[0].complete, true, face);
    assert.equal(parsed.groups[0].valid, true, face);
  }
});

test("incomplete decimal transcripts cannot enable derivation", () => {
  const config = api.hodlSeedConfig(12);
  const parsed = api.hodlDPlusRolls(Array(config.partialWords).fill("1 16 16").join(" "), 12, true);
  assert.equal(parsed.allRolledValid, true);
  assert.equal(parsed.complete, false);
  assert.equal(parsed.waiting, "checksum-d8");
});

test("decimal D16 rejects zero, 17, and hexadecimal letters as whole rolls", () => {
  for (const face of ["0", "17", "A"]) {
    const parsed = api.hodlDPlusRolls(`1 ${face} 16`, 12, true);
    assert.equal(parsed.groups[0].valid, false, face);
    assert.equal(parsed.rejectedD16, 1, face);
    assert.equal(parsed.entries.length, 3, face);
    assert.equal(parsed.firstInvalid.face, face, face);
  }
});

test("switching D16 notation translates the represented rolls", () => {
  assert.equal(api.hodlConvertDPlusNotation("100 2AF", 12, false, true), "1 16 16 2 10 15");
  assert.equal(api.hodlConvertDPlusNotation("1 16 16 2 10 15", 12, true, false), "100 2AF");
  assert.equal(api.hodlConvertDPlusNotation("1 17 16", 12, true, false), null);
});

test("decimal sanitizing preserves a typed delimiter and its caret side", () => {
  const input = {
    value: "1,",
    selectionStart: 2,
    selectionEnd: 2,
    selectionDirection: "none",
    dataset: {},
    setSelectionRange(start, end, direction) {
      this.selectionStart = start;
      this.selectionEnd = end;
      this.selectionDirection = direction;
    },
  };
  assert.equal(api.hodlSanitizeDPlusInput(input, 12, true), true);
  assert.equal(input.value, "1 ");
  assert.equal(input.selectionStart, 2);
  input.value += "16";
  input.selectionStart = input.selectionEnd = input.value.length;
  api.hodlSanitizeDPlusInput(input, 12, true);
  assert.equal(input.value, "1 16");
});

test("decimal D16 keypad keeps multi-digit faces enabled", () => {
  const buttons = ["0", "10", "11", "12", "13", "14", "15", "16"].map((value) => ({
    dataset: { d: value },
    classList: { toggle() {} },
    querySelector() { return null; },
    replaceChildren() {},
    hidden: false,
    disabled: false,
    title: "",
  }));
  const pad = { querySelectorAll() { return buttons; } };
  const form = { querySelector() { return pad; } };
  const input = { closest() { return form; } };
  updateButtons(input, { dplus: { waiting: "d16-first" } });
  assert.equal(buttons[0].disabled, true);
  for (const button of buttons.slice(1)) assert.equal(button.disabled, false, button.dataset.d);
});

test("notation conversion maps caret positions to roll boundaries", () => {
  const decimal = api.hodlConvertDPlusNotation("100", 12, false, true);
  assert.deepEqual([0, 1, 2, 3].map((offset) => api.hodlDPlusConvertedOffset("100", offset, decimal, false, true)), [0, 2, 5, 7]);
  assert.deepEqual([0, 2, 5, 7].map((offset) => api.hodlDPlusConvertedOffset(decimal, offset, "100", true, false)), [0, 1, 2, 3]);
});

test("D++ picks a candidate with the same index the spec maps to", () => {
  const words = 15;
  const config = api.hodlSeedConfig(words);
  const parsed = api.hodlDPlusRolls("10E".repeat(config.partialWords) + "12", words, false);
  assert.equal(parsed.waiting, "complete");
  // (d8 - 1) * 8 + (d8 - 1) = 0 * 8 + 1 = 1
  assert.equal(parsed.finalWord, parsed.candidates[1]);
  const words21 = 21;
  const config21 = api.hodlSeedConfig(words21);
  const parsed21 = api.hodlDPlusRolls("10E".repeat(config21.partialWords) + "A", words21, false);
  assert.equal(parsed21.finalWord, parsed21.candidates[0xA]);
  const words18 = 18;
  const config18 = api.hodlSeedConfig(words18);
  const parsed18 = api.hodlDPlusRolls("10E".repeat(config18.partialWords) + "A5", words18, false);
  // (d16) * 2 + (coin >= 5 ? 1 : 0) = 10 * 2 + 1 = 21
  assert.equal(parsed18.finalWord, parsed18.candidates[21]);
  const words12 = 12;
  const config12 = api.hodlSeedConfig(words12);
  const parsed12 = api.hodlDPlusRolls("10E".repeat(config12.partialWords) + "3A", words12, false);
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
