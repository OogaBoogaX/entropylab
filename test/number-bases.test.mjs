import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { t as hodlT } from "../src/js/i18n.js";

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
  "hodlHex",
  `var hodlTargetWordCount=24; var hodlBip39Wordlist=Array.from({length:2048},(_,index)=>String(index));
${loadVariable("hodlSeedLengths", "hodlEntropyFormats")}
${loadVariable("hodlEntropyFormats", "hodlBip39WordSet")}
${loadSlice("hodlSeedConfig")}
${loadSlice("hodlNormalizeEntropyFormat")}
${loadSlice("hodlEntropyFormatConfig")}
${loadSlice("hodlNormalizeEntropyCharacter")}
${loadSlice("hodlFilterNumberBase")}
${loadSlice("hodlEntropyDigitEntries")}
${loadSlice("hodlEntropyDigits")}
${loadSlice("hodlNumberBaseBits")}
${loadSlice("hodlNumberBasePreviewWords")}
${loadSlice("hodlBinaryPreviewWords")}
${loadSlice("hodlNumberBaseCalculationRows")}
${loadSlice("hodlBinaryCalculationRows")}
${loadSlice("hodlNumberBaseBinaryConversionMarkup")}
${loadSlice("hodlNumberBaseValueFromBytes")}
${loadSlice("hodlBinaryDigits")}
${loadSlice("hodlGroupedBinary")}
${loadSlice("hodlAnalyzeEntropyInput")}
${loadSlice("hodlNote")}
${loadSlice("hodlNumberBaseEntropy")}
return {hodlEntropyFormats,hodlEntropyFormatConfig,hodlFilterNumberBase,hodlAnalyzeEntropyInput,hodlNumberBaseEntropy,hodlNumberBaseValueFromBytes,hodlNumberBaseCalculationRows,hodlBinaryCalculationRows,hodlNumberBaseBinaryConversionMarkup};`,
)({ encode: (bytes) => Buffer.from(bytes).toString("hex") });

const hexToBits = (hex) => [...hex].map((digit) => Number.parseInt(digit, 16).toString(2).padStart(4, "0")).join("");
function encodeInFormat(hex, format, words) {
  const meta = api.hodlEntropyFormatConfig(format, words);
  const bits = hexToBits(hex);
  let value = "";
  for (let index = 0; index < meta.fullDigits; index++) {
    const start = index * meta.bitsPerDigit;
    value += meta.alphabet[Number.parseInt(bits.slice(start, start + meta.bitsPerDigit), 2)];
  }
  if (meta.remainderBits) {
    const finalBits = bits.slice(meta.fullDigits * meta.bitsPerDigit);
    value += meta.binaryRemainder ? finalBits : meta.alphabet[Number.parseInt(finalBits, 2)];
  }
  return value;
}

test("number-base character counts preserve exact BIP39 entropy lengths", () => {
  assert.deepEqual(
    ["bin", "base4", "base8", "hex", "base32", "base64"].map((format) => api.hodlEntropyFormatConfig(format, 12).digits),
    [128, 64, 43, 32, 28, 23],
  );
  assert.deepEqual(
    ["bin", "base4", "base8", "hex", "base32", "base64"].map((format) => api.hodlEntropyFormatConfig(format, 15).digits),
    [160, 80, 54, 40, 32, 30],
  );
  assert.deepEqual(
    ["bin", "base4", "base8", "hex", "base32", "base64"].map((format) => api.hodlEntropyFormatConfig(format, 18).digits),
    [192, 96, 64, 48, 40, 32],
  );
  assert.deepEqual(
    ["bin", "base4", "base8", "hex", "base32", "base64"].map((format) => api.hodlEntropyFormatConfig(format, 21).digits),
    [224, 112, 75, 56, 48, 39],
  );
  assert.deepEqual(
    ["bin", "base4", "base8", "hex", "base32", "base64"].map((format) => api.hodlEntropyFormatConfig(format, 24).digits),
    [256, 128, 86, 64, 52, 46],
  );
});

test("all six formats decode to the same entropy bytes", () => {
  const vectors = [
    [12, "000102030405060708090a0b0c0d0e0f"],
    [15, "000102030405060708090a0b0c0d0e0f10111213"],
    [18, "000102030405060708090a0b0c0d0e0f1011121314151617"],
    [21, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b"],
    [24, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"],
  ];
  for (const [words, hex] of vectors) {
    for (const format of ["bin", "base4", "base8", "hex", "base32", "base64"]) {
      const encoded = encodeInFormat(hex, format, words);
      const result = api.hodlNumberBaseEntropy(encoded, format, words);
      assert.equal(result.ok, true, `${words} words, ${format}`);
      assert.equal(result.hex, hex, `${words} words, ${format}`);
    }
  }
});

test("Base 8 uses a mixed-radix final character and Base32 switches to coin flips", () => {
  const base8 = api.hodlEntropyFormatConfig("base8", 12);
  assert.equal(base8.remainderBits, 2);
  assert.equal(base8.finalCharacters, "0123");
  assert.equal(api.hodlAnalyzeEntropyInput(`${"0".repeat(42)}4`, "base8", 12).finalInvalid, true);
  const octalError = api.hodlNumberBaseEntropy(`${"0".repeat(42)}4`, "base8", 12).error;
  assert.equal(octalError.key, "error.hexFinalMixed");
  assert.match(hodlT(octalError.key, octalError.vars), /final Octal character contributes only 2 bits and must be one of 0, 1, 2, 3/);

  const base32 = api.hodlEntropyFormatConfig("base32", 24);
  assert.equal(base32.remainderBits, 1);
  assert.equal(base32.finalCharacters, "01");
  assert.equal(api.hodlAnalyzeEntropyInput(`${"0".repeat(51)}2`, "base32", 24).finalInvalid, true);
  assert.equal(api.hodlNumberBaseEntropy(`${"0".repeat(51)}1`, "base32", 24).ok, true);

  assert.equal(api.hodlEntropyFormatConfig("base8", 24).finalCharacters, "01");
  assert.equal(api.hodlEntropyFormatConfig("base32", 12).digits, 28);
  assert.equal(api.hodlEntropyFormatConfig("base32", 12).finalCharacters, "01");
  assert.equal(api.hodlAnalyzeEntropyInput(`${"0".repeat(25)}010`, "base32", 12).ready, true);
  assert.equal(api.hodlAnalyzeEntropyInput(`${"0".repeat(25)}02`, "base32", 12).finalInvalid, true);
  assert.equal(api.hodlEntropyFormatConfig("base32", 18).digits, 40);
  assert.equal(api.hodlEntropyFormatConfig("base32", 18).finalCharacters, "01");
  assert.equal(api.hodlEntropyFormatConfig("base8", 18).remainderBits, 0);
});

test("complete entropy can be synchronized into every number base", () => {
  for (const [words, hex] of [[12, "000102030405060708090a0b0c0d0e0f"], [15, "000102030405060708090a0b0c0d0e0f10111213"], [21, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b"]]) {
    const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
    for (const format of ["bin", "base4", "base8", "hex", "base32", "base64"]) {
      const value = api.hodlNumberBaseValueFromBytes(bytes, format, words);
      assert.equal(value.replace(/\s/g, ""), encodeInFormat(hex, format, words), `${words} words, ${format}`);
      assert.equal(api.hodlNumberBaseEntropy(value, format, words).hex, hex, `${words} words, ${format}`);
    }
  }
});

test("binary calculation rows expose BIP39 place values and word numbers", () => {
  const rows = api.hodlBinaryCalculationRows("00000000001", 12);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].index, 1);
  assert.deepEqual(rows[0].terms.map(({ place, bit, value }) => [place, bit, value]), [[1024, "0", 0], [512, "0", 0], [256, "0", 0], [128, "0", 0], [64, "0", 0], [32, "0", 0], [16, "0", 0], [8, "0", 0], [4, "0", 0], [2, "0", 0], [1, "1", 1]]);
});

test("Base 4 calculation rows use the same normalized 11-bit BIP39 mapping", () => {
  const rows = api.hodlNumberBaseCalculationRows("333333", "base4", 12);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].index, 2047);
  assert.deepEqual(rows[0].terms.map(({ place, bit, value }) => [place, bit, value]), [[1024, "1", 1024], [512, "1", 512], [256, "1", 256], [128, "1", 128], [64, "1", 64], [32, "1", 32], [16, "1", 16], [8, "1", 8], [4, "1", 4], [2, "1", 2], [1, "1", 1]]);
});

test("hex conversion displays each source digit and its binary value", () => {
  const markup = api.hodlNumberBaseBinaryConversionMarkup("A", api.hodlEntropyFormatConfig("hex", 12));
  assert.match(markup, />A<\/strong><b>\u2192<\/b><span>1010<\/span>/);
});

test("Crockford Base32 normalizes its documented aliases", () => {
  assert.equal(api.hodlFilterNumberBase("o i-l", "base32"), "0 11");
  assert.equal(api.hodlFilterNumberBase("u!", "base32"), "");
});

test("Base64 uses the RFC 4648 alphabet followed by individual remaining bits", () => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  assert.equal(api.hodlEntropyFormats.base64.alphabet, alphabet);
  assert.equal(api.hodlFilterNumberBase("AaZz09+/=", "base64"), "AaZz09+/");
  assert.equal(api.hodlEntropyFormatConfig("base64", 12).digits, 23);
  assert.equal(api.hodlEntropyFormatConfig("base64", 12).finalCharacters, "01");
  assert.equal(api.hodlEntropyFormatConfig("base64", 18).remainderBits, 0);
  assert.equal(api.hodlEntropyFormatConfig("base64", 24).digits, 46);
  assert.equal(api.hodlEntropyFormatConfig("base64", 24).finalCharacters, "01");
  assert.equal(api.hodlAnalyzeEntropyInput(`${"A".repeat(42)}000A`, "base64", 24).finalInvalid, true);
  const bytes = Uint8Array.from(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
  const standard = Buffer.from(bytes).toString("base64").replace(/=+$/, "");
  assert.equal(api.hodlNumberBaseValueFromBytes(bytes, "base64", 12), `${standard.slice(0, -1)}${hexToBits(Buffer.from(bytes).toString("hex")).slice(-2)}`);
});
