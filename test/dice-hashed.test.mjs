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

test("hashed-dice recommendation exactly reaches the entropy bits", () => {
  const expected = { 12: 50, 15: 62, 18: 75, 21: 87, 24: 99 };
  for (const words of SIZES) {
    const config = api.hodlSeedConfig(words);
    assert.equal(config.hashRolls, expected[words], `${words}: recommendation off`);
    assert.ok(api.hodlDiceEntropyBits(config.hashRolls - 1) < config.bits, `${words}: shorter input still reaches ${config.bits} bits`);
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
