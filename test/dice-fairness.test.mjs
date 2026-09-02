// Pearson chi-squared die-fairness math used by the Dice rolls panel.
// Run with: npm run test:dice-fairness
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

const hodlLanczosGamma = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
const hodlLogGamma = new Function("hodlLanczosGamma", `${loadSlice("hodlLogGamma")}; return hodlLogGamma;`)(hodlLanczosGamma);
const hodlLowerRegularizedGamma = new Function("hodlLogGamma", `${loadSlice("hodlLowerRegularizedGamma")}; return hodlLowerRegularizedGamma;`)(hodlLogGamma);
const hodlChiSquaredCdf = new Function("hodlLowerRegularizedGamma", `${loadSlice("hodlChiSquaredCdf")}; return hodlChiSquaredCdf;`)(hodlLowerRegularizedGamma);
const hodlDiceMinimumRolls = new Function(`${loadSlice("hodlDiceMinimumRolls")}; return hodlDiceMinimumRolls;`)();
const hodlDiceFairnessVerdict = new Function(`${loadSlice("hodlDiceFairnessVerdict")}; return hodlDiceFairnessVerdict;`)();
const hodlDiceFairnessAssess = new Function(
  "hodlDiceMinimumRolls",
  "hodlChiSquaredCdf",
  "hodlDiceFairnessVerdict",
  `${loadSlice("hodlDiceFairnessAssess")}; return hodlDiceFairnessAssess;`,
)(hodlDiceMinimumRolls, hodlChiSquaredCdf, hodlDiceFairnessVerdict);

const hodlSeedLengths = {
  12: { words: 12, bits: 128, partialWords: 11 },
  24: { words: 24, bits: 256, partialWords: 23 },
};
function hodlSeedConfig(words = 24) {
  return hodlSeedLengths[words] || hodlSeedLengths[24];
}
const hodlDiceFairnessSamples = new Function(
  "hodlDPlusRolls",
  "hodlSeedConfig",
  "hodlAnalyzeDiceInput",
  "hodlTargetWordCount",
  "hodlDPlusFinalSteps",
  "hodlDPlusD16Value",
  `${loadSlice("hodlDiceFairnessSamples")}; return hodlDiceFairnessSamples;`,
)(
  () => {
    const entries = [];
    entries[hodlSeedConfig(24).partialWords * 3] = { face: "4" };
    return {
      groups: [
        { faces: ["1", "0", "F"], validity: [true, true, true] },
        { faces: ["8", "A", "B"], validity: [true, true, true] },
      ],
      entries,
    };
  },
  hodlSeedConfig,
  (value) => ({ acceptedRolls: [...String(value)].filter((character) => character >= "1" && character <= "6") }),
  24,
  () => ["d8"],
  (face) => {
    const normalized = String(face ?? "").toUpperCase();
    return /^[0-9A-F]$/.test(normalized) ? Number.parseInt(normalized, 16) : null;
  },
);

test("log-gamma matches known values", () => {
  assert.ok(Math.abs(Math.exp(hodlLogGamma(0.5)) - Math.sqrt(Math.PI)) < 1e-12);
  assert.ok(Math.abs(Math.exp(hodlLogGamma(1)) - 1) < 1e-12);
  assert.ok(Math.abs(Math.exp(hodlLogGamma(6)) - 120) < 1e-9);
});

test("chi-squared CDF matches the RPG Stack Exchange d20 90% critical value", () => {
  assert.ok(Math.abs(hodlChiSquaredCdf(27.204, 19) - 0.9) < 0.001);
  assert.ok(Math.abs(hodlChiSquaredCdf(11.070, 5) - 0.95) < 0.001);
  assert.equal(hodlChiSquaredCdf(0, 5), 0);
});

test("minimum rolls follow the five-per-face Pearson rule of thumb", () => {
  assert.equal(hodlDiceMinimumRolls(2), 10);
  assert.equal(hodlDiceMinimumRolls(6), 30);
  assert.equal(hodlDiceMinimumRolls(16), 80);
});

test("uniform d6 rolls look fair once the minimum is reached", () => {
  const rolls = Array.from({ length: 30 }, (_, index) => String((index % 6) + 1));
  const report = hodlDiceFairnessAssess(rolls, ["1", "2", "3", "4", "5", "6"], "D6");
  assert.equal(report.chi, 0);
  assert.equal(report.cdf, 0);
  assert.equal(report.enough, true);
  assert.equal(report.verdict.id, "fair");
  assert.deepEqual(report.counts.map((face) => face.count), [5, 5, 5, 5, 5, 5]);
});

test("a constant face is reported as biased", () => {
  const report = hodlDiceFairnessAssess(Array(30).fill("1"), ["1", "2", "3", "4", "5", "6"], "D6");
  assert.ok(report.chi > 40);
  assert.ok(report.cdf > 0.999);
  assert.equal(report.verdict.id, "biased");
});

test("too few rolls withhold the fairness verdict", () => {
  const report = hodlDiceFairnessAssess(["1", "2", "3", "4", "5", "6"], ["1", "2", "3", "4", "5", "6"], "D6");
  assert.equal(report.enough, false);
  assert.equal(report.remaining, 24);
  assert.equal(report.verdict.id, "need-more");
});

test("hashed-roll samples count accepted d6 faces", () => {
  const [sample] = hodlDiceFairnessSamples("415263 99 415263", "coldcard", 24);
  assert.equal(sample.title, "D6");
  assert.deepEqual(sample.rolls, ["4", "1", "5", "2", "6", "3", "4", "1", "5", "2", "6", "3"]);
});

test("BitBox samples split D4 entropy rolls from the coin / sixth die", () => {
  const [d4, coin] = hodlDiceFairnessSamples("11111H22222T333331444446", "bitbox", 24);
  assert.equal(d4.title, "D4 (1–4)");
  assert.deepEqual(d4.rolls, ["1", "1", "1", "1", "1", "2", "2", "2", "2", "2", "3", "3", "3", "3", "3", "4", "4", "4", "4", "4"]);
  assert.deepEqual(coin.rolls, ["Heads", "Tails", "Heads", "Tails"]);
});

test("D++ samples keep D8 and D16 rolls separate", () => {
  const [d8, d16] = hodlDiceFairnessSamples("10F8AB4", "dplus", 24);
  assert.equal(d8.title, "D8");
  assert.deepEqual(d8.rolls, ["1", "8", "4"]);
  assert.equal(d16.title, "D16 (0–F)");
  assert.deepEqual(d16.rolls, ["0", "F", "A", "B"]);
});

const hodlDiceFairnessSamples18 = new Function(
  "hodlDPlusRolls",
  "hodlSeedConfig",
  "hodlAnalyzeDiceInput",
  "hodlTargetWordCount",
  "hodlDPlusFinalSteps",
  "hodlDPlusD16Value",
  `${loadSlice("hodlDiceFairnessSamples")}; return hodlDiceFairnessSamples;`,
)(
  () => {
    const entries = [];
    entries[hodlSeedConfig(18).partialWords * 3] = { face: "F" };
    entries[hodlSeedConfig(18).partialWords * 3 + 1] = { face: "6" };
    return { groups: [], entries };
  },
  hodlSeedConfig,
  () => ({ acceptedRolls: [] }),
  18,
  () => ["d16", "coin"],
  (face) => {
    const normalized = String(face ?? "").toUpperCase();
    return /^[0-9A-F]$/.test(normalized) ? Number.parseInt(normalized, 16) : null;
  },
);

test("D++ 18-word final coin flip joins the fairness samples", () => {
  const [d8, d16, coin] = hodlDiceFairnessSamples18("", "dplus", 18);
  assert.deepEqual(d8.rolls, []);
  assert.deepEqual(d16.rolls, ["F"]);
  assert.equal(coin.title, "Coin");
  assert.deepEqual(coin.rolls, ["Tails"]);
  assert.deepEqual(coin.labels, ["Heads", "Tails"]);
});

test("fairness UI stays collapsed until the Die Distribution / Fairness Analysis text button expands it", () => {
  assert.match(app, /id="dice-fairness-toggle"/);
  assert.match(app, /class="dice-fairness-toggle"/);
  assert.match(app, /data-dice-fairness-glyph/);
  assert.match(app, /hodlT\("dice.fairness.toggle"\)/);
  assert.match(app, /function hodlSetDiceFairnessOpen\(open\)/);
  assert.match(app, /panel\.hidden = !open/);
  assert.match(app, /showDiceFairness: false/);
});
