// D20 entropy, both methods.
//
// Security contract
// ----------------
// d20      A roll transcript is read as a base-20 fraction, first roll most
//          significant, expanded to the target bit width. Accepted: at least
//          bits/4 rolls, every face in 1..20. Refused: anything shorter, any
//          face outside 1..20, any other character. Same rolls, same entropy.
// d20hash  The same transcript, normalised to faces joined by "-", SHA-256
//          hashed, the leading target-width bits becoming the entropy. Same
//          acceptance and refusal rules.
//
// The fraction vectors below are fixed by inspection, not by running the code:
// a transcript of all 1s is the fraction zero, all 20s is one short of unity,
// and a leading face f over trailing 1s is the fraction (f-1)/20 exactly.
// SHA-256 is taken from node:crypto, as the existing hashed-dice test does.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { entropyToMnemonic as _n } from "@scure/bip39";
import { wordlist as hodlBip39Wordlist } from "@scure/bip39/wordlists/english.js";
import { t as hodlT } from "../src/js/i18n.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing ${name}`);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) { end = i + 1; break; }
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
const hodlHex = { encode: (bytes) => Buffer.from(bytes).toString("hex") };
const api = new Function(
  "hodlBip39Wordlist", "hodlSha256", "hodlHex", "hodlT",
  `
  var hodlTargetWordCount = 24;
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${["hodlNote", "hodlSeedConfig", "hodlDiceEntropyBits", "hodlDiceEntropy",
     "hodlIanColemanDiceString", "hodlSplitDiceString", "hodlSplitD20String",
     "hodlD20EntropyBits", "hodlD20MinimumRolls", "hodlD20Transcript",
     "hodlD20FractionBytes"].map(loadSlice).join("\n")}
  return { hodlDiceEntropy, hodlSeedConfig, hodlSplitD20String, hodlD20EntropyBits,
           hodlD20MinimumRolls, hodlD20Transcript, hodlD20FractionBytes };
  `,
)(hodlBip39Wordlist, hodlSha256, hodlHex, hodlT);

const SIZES = [12, 15, 18, 21, 24];
const METHODS = ["d20", "d20hash"];
const faces = (list) => list.join(" ");
const repeat = (face, count) => faces(Array.from({ length: count }, () => face));

test("a D20 transcript needs bits/4 rolls, which covers the entropy target", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const minimum = api.hodlD20MinimumRolls(config.bits);
    assert.equal(minimum, config.bits / 4, `${words}: not the bits/4 rule`);
    assert.equal(Number.isInteger(minimum), true, `${words}: fractional roll count`);
    assert.ok(api.hodlD20EntropyBits(minimum) >= config.bits, `${words}: falls short of ${config.bits} bits`);
  }
});

test("the base-20 fraction expands to bits that are fixed by inspection", () => {
  const config = api.hodlSeedConfig(24);
  const n = api.hodlD20MinimumRolls(config.bits);
  const cases = [
    ["all faces 1 is the fraction zero", repeat(1, n), "00".repeat(32)],
    ["all faces 20 is one short of unity", repeat(20, n), "ff".repeat(32)],
    ["a leading 11 over 1s is one half", faces([11, ...Array(n - 1).fill(1)]), "80" + "00".repeat(31)],
    ["a leading 6 over 1s is one quarter", faces([6, ...Array(n - 1).fill(1)]), "40" + "00".repeat(31)],
    ["a leading 16 over 1s is three quarters", faces([16, ...Array(n - 1).fill(1)]), "c0" + "00".repeat(31)],
  ];
  for (const [label, transcript, expected] of cases) {
    const entropy = api.hodlDiceEntropy(transcript, "d20", 24);
    assert.equal(entropy.ok, true, `${label}: refused`);
    assert.equal(entropy.hex, expected, label);
  }
});

test("the hashed D20 transcript is SHA-256 over the faces joined by a hyphen", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const rolls = Array.from({ length: api.hodlD20MinimumRolls(config.bits) }, (_, i) => (i % 20) + 1);
    const entropy = api.hodlDiceEntropy(faces(rolls), "d20hash", words);
    assert.equal(entropy.ok, true, `${words}: refused`);
    assert.equal(api.hodlD20Transcript(rolls), rolls.join("-"), `${words}: transcript not canonical`);
    const reference = createHash("sha256").update(rolls.join("-")).digest("hex");
    assert.equal(entropy.hex, reference.slice(0, config.bytes * 2), `${words}: not the SHA-256 of the transcript`);
  }
});

test("separators and spacing do not change the transcript", () => {
  const n = api.hodlD20MinimumRolls(128);
  const rolls = Array.from({ length: n }, (_, i) => (i % 20) + 1);
  const written = [rolls.join(" "), rolls.join(","), rolls.join("  "), rolls.join(" , ") , rolls.join("\n")];
  for (const method of METHODS) {
    const first = api.hodlDiceEntropy(written[0], method, 12);
    assert.equal(first.ok, true, `${method}: refused`);
    for (const value of written.slice(1)) {
      assert.equal(api.hodlDiceEntropy(value, method, 12).hex, first.hex, `${method}: ${JSON.stringify(value.slice(0, 12))} differs`);
    }
  }
});

test("a transcript short of the minimum is refused, not silently weakened", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const minimum = api.hodlD20MinimumRolls(config.bits);
    for (const method of METHODS) {
      assert.equal(api.hodlDiceEntropy(repeat(7, minimum - 1), method, words).ok, false, `${words}, ${method}: short transcript accepted`);
      assert.equal(api.hodlDiceEntropy(repeat(7, minimum), method, words).ok, true, `${words}, ${method}: exact minimum refused`);
      assert.equal(api.hodlDiceEntropy(repeat(7, minimum + 5), method, words).ok, true, `${words}, ${method}: extra rolls refused`);
    }
  }
});

test("faces outside 1 to 20 are refused", () => {
  const n = api.hodlD20MinimumRolls(256);
  const good = Array.from({ length: n }, () => 7);
  for (const method of METHODS) {
    for (const bad of [0, 21, 99, -3]) {
      const transcript = faces([bad, ...good]);
      assert.equal(api.hodlDiceEntropy(transcript, method, 24).ok, false, `${method}: face ${bad} accepted`);
    }
    for (const junk of ["", "   ", faces(good) + " X", "abc"]) {
      assert.equal(api.hodlDiceEntropy(junk, method, 24).ok, false, `${method}: ${JSON.stringify(junk.slice(0, 10))} accepted`);
    }
  }
});

test("the splitter reads decimal faces and reports what it could not read", () => {
  const parsed = api.hodlSplitD20String("1 20 7,13");
  assert.deepEqual(parsed.rolls, [1, 20, 7, 13]);
  assert.deepEqual(parsed.leftover, []);
  assert.deepEqual(api.hodlSplitD20String("3 21 4").leftover, ["21"]);
  assert.deepEqual(api.hodlSplitD20String("3 0 4").leftover, ["0"]);
  assert.deepEqual(api.hodlSplitD20String("3 X 4").leftover, ["X"]);
});

test("the two D20 methods are deterministic and differ from one another", () => {
  const n = api.hodlD20MinimumRolls(256);
  const rolls = Array.from({ length: n }, (_, i) => ((i * 7) % 20) + 1);
  const transcript = faces(rolls);
  const results = METHODS.map((method) => api.hodlDiceEntropy(transcript, method, 24));
  for (const [index, method] of METHODS.entries()) {
    assert.equal(results[index].ok, true, `${method}: refused`);
    assert.equal(api.hodlDiceEntropy(transcript, method, 24).hex, results[index].hex, `${method}: not deterministic`);
  }
  assert.notEqual(results[0].hex, results[1].hex, "conversion and hash produced the same entropy");
});

test("both D20 methods derive a full mnemonic at every target size", () => {
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    const rolls = Array.from({ length: api.hodlD20MinimumRolls(config.bits) }, (_, i) => (i % 20) + 1);
    for (const method of METHODS) {
      const entropy = api.hodlDiceEntropy(faces(rolls), method, words);
      assert.equal(entropy.ok, true, `${words}, ${method}: not ok`);
      assert.equal(entropy.bytes.length, config.bytes, `${words}, ${method}: wrong byte count`);
      assert.equal(_n(entropy.bytes, hodlBip39Wordlist).split(" ").length, words, `${words}, ${method}`);
    }
  }
});
