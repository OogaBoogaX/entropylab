// Hashed dice (COLDCARD/Keystone): recommended roll counts and entropy sizes.
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
const hodlHex = { encode: (bytes) => Buffer.from(bytes).toString("hex") };
const api = new Function(
  "hodlBip39Wordlist",
  "hodlSha256",
  "hodlHex",
  "hodlT",
  `
  var hodlTargetWordCount = 24;
  ${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
  ${["hodlNote", "hodlSeedConfig", "hodlDiceEntropyBits", "hodlDiceEntropy", "hodlIanColemanDiceString", "hodlSplitDiceString" ].map(loadSlice).join("\n")}
  return { hodlDiceEntropy, hodlSeedConfig, hodlDiceEntropyBits };
  `,
)(hodlBip39Wordlist, hodlSha256, hodlHex, hodlT);

const SIZES = [12, 15, 18, 21, 24];
const METHODS = ["coldcard", "coleman"];

test("hashed-dice recommendations cover the entropy target", () => {
  const expected = { 12: 50, 15: 62, 18: 75, 21: 87, 24: 100 };
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    assert.equal(config.hashRolls, expected[words], `${words}: recommendation off`);
    assert.ok(api.hodlDiceEntropyBits(config.hashRolls) >= config.bits, `${words}: recommendation falls short of ${config.bits} bits`);
    // The 24-word recommendation is rounded up to 100; other lengths retain
    // the minimum whole-roll count needed for their entropy target.
    if (words !== 24) assert.ok(api.hodlDiceEntropyBits(config.hashRolls - 1) < config.bits, `${words}: shorter input still reaches ${config.bits} bits`);
  }
});

test("24-word hashed dice warn below 100 rolls and hash every entered roll", () => {
  for (const method of METHODS) {
    for (const count of [1, 99, 100, 101]) {
      const rolls = "123456".repeat(Math.ceil(count / 6)).slice(0, count);
      const entropy = api.hodlDiceEntropy(rolls, method, 24);
      assert.equal(entropy.ok, true, `${method}, ${count}: valid transcript rejected`);
      assert.equal(entropy.warnings.length, count < 100 ? 1 : 0, `${method}, ${count}: warning boundary`);
      if (count < 100) assert.deepEqual(entropy.warnings[0].vars, { have: count, need: 100, words: 24, bits: (count * Math.log2(6)).toFixed(1) });
      // Node's SHA-256 is the independent reference for the existing
      // original-digit / 6-to-0 transcript contract.
      const transcript = method === "coleman" ? rolls.replaceAll("6", "0") : rolls;
      assert.equal(entropy.hex, createHash("sha256").update(transcript).digest("hex"));
    }
    for (const value of ["", "123X456", "1".repeat(100) + "X"]) {
      assert.equal(api.hodlDiceEntropy(value, method, 24).ok, false, `${method}: invalid transcript accepted`);
    }
  }
});

test("hashed dice derive a full mnemonic for every target size and method", () => {
  for (const words of SIZES) {
    for (const method of METHODS) {
      const config = api.hodlSeedConfig(words);
      const rolls = "1".repeat(config.hashRolls);
      const entropy = api.hodlDiceEntropy(rolls, method, words);
      assert.equal(entropy.ok, true, `${words}, ${method}: not ok`);
      assert.equal(entropy.bytes.length, config.bytes, `${words}, ${method}`);
      const mnemonic = _n(entropy.bytes, hodlBip39Wordlist);
      assert.equal(mnemonic.split(" ").length, words, `${words}, ${method}: ${mnemonic}`);
    }
  }
});
