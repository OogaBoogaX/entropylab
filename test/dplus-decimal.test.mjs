// D++ decimal (numbered) D16 input parsing.
//
// Lock-down coverage for issue #86: when numberedD16 is enabled the tokenizer
// must consume multi-digit values 10-16 as a single roll rather than splitting
// them into single hex digits. Every value here is synthetic and the derived
// mnemonics are not used to hold real funds.
//
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
  ${["hodlSeedConfig", "hodlDPlusStepBits", "hodlDPlusStepLabel", "hodlDPlusStepValue", "hodlDPlusFinalSteps", "hodlDPlusFinalDescription", "hodlDPlusFinalHelp", "hodlDPlusStepChecksumLabel", "hodlDPlusD16Value", "hodlDPlusTokens", "Rn", "Mt", "hodlTargetLastWords", "hodlComputeTargetLastWords", "mi", "hodlDPlusRolls", "hodlValidateTargetMnemonic", "hodlSeedCountStatus"].map(loadSlice).join("\n")}
  var hodlLastWordCache = new Map();
  var hodlBip39WordSet = new Set(Ae);
  var hodlBip39WordIndex = new Map(Ae.map((word, index) => [word, index]));
  return { hodlDPlusRolls, hodlDPlusTokens, hodlDPlusD16Value, hodlDPlusFinalSteps, hodlValidateTargetMnemonic, hodlSeedConfig };
  `,
)(Ae, Pn, Z);

// Synthetic hex group used as a baseline. D8=1 (face "1"), D16=0 (face "0"),
// D16=14 (face "E"). Decimal equivalent is "1 16 14" (hex E = decimal 14,
// hex 0 = decimal 16).
const HEX_GROUP = "10E";
const DECIMAL_GROUP = "1 16 14";
const SIZES = [12, 15, 18, 21, 24];

// Map a hex final-step face to its decimal notation equivalent.
function decimalFinalFace(step, hexFace) {
  if (step === "d8" || step === "coin") return hexFace;
  // D16: "0" → "16" (decimal zero = 16), otherwise the face is unchanged.
  return hexFace === "0" ? "16" : hexFace;
}

function buildTranscript(words, group, numberedD16) {
  const config = api.hodlSeedConfig(words);
  const steps = api.hodlDPlusFinalSteps(words);
  const tokenise = (g) => numberedD16 ? g.split(/\s+/).filter(Boolean) : g.split("");
  const headTokens = tokenise(group);
  const headValue = numberedD16 ? headTokens.join(" ") : headTokens.join("");
  const finalValue = steps
    .map((step) => {
      const hex = step === "d8" || step === "coin" ? "5" : "0";
      return numberedD16 ? decimalFinalFace(step, hex) : hex;
    })
    .join(numberedD16 ? " " : "");
  // Pad each repetition with separators in decimal mode so concatenated groups
  // do not glue together (e.g. "14" + "1" → "141" would be one chunk).
  const headChunk = numberedD16 ? `${headValue} ` : headValue;
  const finalChunk = numberedD16 ? ` ${finalValue}` : finalValue;
  return headChunk.repeat(config.partialWords) + finalChunk;
}

test("issue #86 repro: decimal D++ group '1 16 16' selects BIP39 index 0 (abandon)", () => {
  // Group: D8=1 (face 1), D16=16 (decimal zero), D16=16 (decimal zero).
  // WordIndex = (1-1) * 256 + 0 * 16 + 0 = 0.
  const parsed = api.hodlDPlusRolls("1 16 16", 12, true);
  assert.equal(parsed.groups[0].word, Ae[0], `first group word should be 'abandon' but was '${parsed.groups[0].word}'`);
  assert.equal(parsed.groups[0].valid, true, `first group must be valid (faces=${parsed.groups[0].faces.join("|")})`);
});

test("decimal and hex transcripts of the same rolls select identical complete mnemonics", () => {
  for (const words of SIZES) {
    const hexValue = buildTranscript(words, HEX_GROUP, false);
    const decValue = buildTranscript(words, DECIMAL_GROUP, true);
    const hexParsed = api.hodlDPlusRolls(hexValue, words, false);
    const decParsed = api.hodlDPlusRolls(decValue, words, true);
    assert.equal(hexParsed.complete, true, `${words}: hex transcript did not complete`);
    assert.equal(decParsed.complete, true, `${words}: decimal transcript did not complete`);
    const hexPhrase = [...hexParsed.wordSlots, hexParsed.finalWord].join(" ");
    const decPhrase = [...decParsed.wordSlots, decParsed.finalWord].join(" ");
    assert.equal(decPhrase, hexPhrase, `${words}: phrases differ (hex='${hexPhrase}' dec='${decPhrase}')`);
    assert.equal(api.hodlValidateTargetMnemonic(decPhrase, words).ok, true, `${words}: decimal phrase failed BIP39 validation`);
  }
});

test("decimal D++ tokeniser treats values 10-16 as a single roll", () => {
  // 'acceptedCharacters' is the flattened list of faces the parser kept. In
  // decimal mode each value 10-16 must contribute one entry, not the digits
  // of the decimal number.
  for (const value of ["10", "11", "12", "13", "14", "15", "16"]) {
    const parsed = api.hodlDPlusRolls(value, 12, true);
    // Three groups worth of head rolls would be 33 entries; we want at most 1
    // head entry for a single decimal value, so the very first group can have
    // at most 1 face and the others must be empty.
    const firstGroupFaces = parsed.groups[0].faces.length;
    assert.ok(firstGroupFaces <= 1, `'${value}' produced ${firstGroupFaces} faces in group 0 (${parsed.groups[0].faces.join("|")})`);
  }
});

test("decimal D++ invalid values are rejected unambiguously", () => {
  // Each case fills a complete D++ group (D8 + D16 + D16) with a single
  // invalid token placed in a D16 slot. In hex mode these would currently
  // be tokenised differently, so we test decimal mode specifically.
  const cases = [
    { value: "1 0 5", reason: "decimal 0 is out of range (faces read 1-16)" },
    { value: "1 17 5", reason: "decimal 17 is out of range" },
    { value: "1 5 0", reason: "decimal 0 at the final D16 position" },
    { value: "1 A 5", reason: "hex letter A is not valid in decimal mode" },
    { value: "1 F 5", reason: "hex letter F is not valid in decimal mode" },
  ];
  for (const { value, reason } of cases) {
    const parsed = api.hodlDPlusRolls(value, 12, true);
    assert.equal(parsed.groups[0].valid, false, `${reason} (input='${value}', faces=${parsed.groups[0].faces.join("|")})`);
    // The invalid token must also be reported via the parser's invalid ranges
    // so the UI can highlight it for the user.
    assert.ok(parsed.invalidRanges.length > 0, `${reason}: invalid input must be surfaced in invalidRanges`);
  }
});

test("decimal D++ roll count tracks physical rolls, not decimal digits", () => {
  // '1 16 16' is three physical rolls. Current tokenizer produces five
  // entries and that should NOT happen after the fix.
  const parsed = api.hodlDPlusRolls("1 16 16", 12, true);
  // The acceptedCharacters array is what the parser keeps. Three physical
  // rolls should yield exactly three accepted faces (or fewer if any are
  // invalid in the first slot, which the D8 position would catch — but
  // each value here is a valid D8 or D16).
  assert.equal(parsed.acceptedCharacters.length, 3, `'1 16 16' produced ${parsed.acceptedCharacters.length} accepted faces, expected 3`);
});
