// SeedQR / CompactSeedQR payload encoding.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { wordlist as hodlBip39Wordlist } from "@scure/bip39/wordlists/english.js";

const root = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(join(root, "..", path), "utf8");
const app = read("src/js/app.js");
assert.equal(hodlBip39Wordlist.length, 2048);
assert.equal(hodlBip39Wordlist[0], "abandon");
assert.equal(hodlBip39Wordlist[2047], "zoo");

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

const hodlSeedQrDigits = new Function("hodlBip39Wordlist", `${loadSlice("hodlSeedQrDigits")}; return hodlSeedQrDigits;`)(hodlBip39Wordlist);

function compactBytesFromMnemonic(mnemonic) {
  const words = mnemonic.trim().split(/\s+/);
  const bits = words.map((word) => hodlBip39Wordlist.indexOf(word).toString(2).padStart(11, "0")).join("");
  const checksumBits = words.length === 12 ? 4 : 8;
  const entropyBits = bits.slice(0, -checksumBits);
  const bytes = [];
  for (let i = 0; i < entropyBits.length; i += 8) bytes.push(Number.parseInt(entropyBits.slice(i, i + 8), 2));
  return bytes;
}

const SPEC_12 = "vacuum bridge buddy supreme exclude milk consider tail expand wasp pattern nuclear";
const SPEC_DIGITS = "192402220235174306311124037817700641198012901210";
const ABANDON_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("SeedQR digits match the SeedSigner 12-word vector", () => {
  assert.equal(hodlSeedQrDigits(SPEC_12), SPEC_DIGITS);
});

test("SeedQR digits pad 12-word abandon to 48 numeric characters", () => {
  const digits = hodlSeedQrDigits(ABANDON_12);
  assert.equal(digits.length, 48);
  assert.equal(digits, "000000000000000000000000000000000000000000000003");
  assert.match(digits, /^\d+$/);
});

test("SeedQR digits omit 18-word phrases", () => {
  const words = Array(17).fill("abandon").concat("agent").join(" ");
  assert.equal(hodlSeedQrDigits(words), "");
});

test("CompactSeedQR bytes are BIP39 entropy without checksum", () => {
  assert.deepEqual(compactBytesFromMnemonic(ABANDON_12), Array(16).fill(0));
  const bytes = compactBytesFromMnemonic(SPEC_12);
  assert.equal(bytes.length, 16);
  const hex = bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const hodlCompactSeedQrBytes = new Function("hodlHex", `${loadSlice("hodlCompactSeedQrBytes")}; return hodlCompactSeedQrBytes;`)({
    decode(value) {
      const out = [];
      for (let i = 0; i < value.length; i += 2) out.push(Number.parseInt(value.slice(i, i + 2), 16));
      return out;
    },
  });
  assert.deepEqual(hodlCompactSeedQrBytes(hex), bytes);
  assert.equal(hodlCompactSeedQrBytes("00".repeat(24)), null);
});

test("SeedQR digits for 24 words are 96 numeric characters", () => {
  const mnemonic = `${Array(23).fill("abandon").join(" ")} art`;
  const digits = hodlSeedQrDigits(mnemonic);
  assert.equal(digits.length, 96);
  assert.match(digits, /^\d+$/);
  assert.equal(digits.slice(0, 4), "0000");
});
