import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { classifyQrPayload } from "../src/js/qr-payload.js";
import { bip39English, indicesFromEntropy } from "../src/js/bip39.js";
import { randomBytes } from "node:crypto";

// The app's SeedQR encoder, re-implemented from its few lines (app.js
// hodlSeedQrDigits): each word becomes its 4-digit, zero-padded index.
const seedQrDigits = (mnemonic) => {
  const words = String(mnemonic ?? "").trim().split(/\s+/).filter(Boolean);
  if (words.length !== 12 && words.length !== 24) return "";
  let digits = "";
  for (const word of words) {
    const index = bip39English.indexOf(word);
    if (index < 0) return "";
    digits += String(index).padStart(4, "0");
  }
  return digits;
};

const bytesOf = (text) => new TextEncoder().encode(text);

// BIP39 test vectors: all-zero entropy, 128 and 256 bits.
const ABANDON_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ABANDON_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

// An independent base58check encoder, so the WIF fixtures come from the
// specification rather than from the module under test.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const base58Encode = (bytes) => {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  const digits = [];
  for (let i = zeros; i < bytes.length; i += 1) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j += 1) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) out += B58[digits[i]];
  return out;
};

const sha256 = (bytes) => createHash("sha256").update(bytes).digest();

const wifFor = (key, { testnet = false, compressed = true } = {}) => {
  const parts = [Buffer.from([testnet ? 0xef : 0x80]), Buffer.from(key)];
  if (compressed) parts.push(Buffer.from([0x01]));
  const payload = Buffer.concat(parts);
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  return base58Encode(Buffer.concat([payload, checksum]));
};

const KEY_ONE = new Uint8Array(32);
KEY_ONE[31] = 1;

test("the WIF fixtures match the published vectors", () => {
  assert.equal(wifFor(KEY_ONE), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
  assert.equal(wifFor(KEY_ONE, { compressed: false }), "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
});

test("a 12-word Standard SeedQR keeps its indices, including a leading-zero group", () => {
  const digits = seedQrDigits(ABANDON_12);
  assert.equal(digits, "0000".repeat(11) + "0003");
  const result = classifyQrPayload(bytesOf(digits));
  assert.equal(result.format, "standard-seedqr");
  assert.equal(result.words, 12);
  assert.deepEqual(Array.from(result.indices), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
});

test("a 24-word Standard SeedQR round-trips", () => {
  const digits = seedQrDigits(ABANDON_24);
  assert.equal(digits, "0000".repeat(23) + "0102");
  const result = classifyQrPayload(bytesOf(digits));
  assert.equal(result.format, "standard-seedqr");
  assert.equal(result.words, 24);
  assert.equal(result.indices.length, 24);
  for (let i = 0; i < 23; i += 1) assert.equal(result.indices[i], 0);
  assert.equal(result.indices[23], 102);
});

test("a Standard SeedQR with a bad checksum is unknown", () => {
  const digits = "0000".repeat(11) + "0004";
  assert.deepEqual(classifyQrPayload(bytesOf(digits)), { format: "unknown", length: 48 });
});

test("a Standard SeedQR group over 2047 is unknown", () => {
  const digits = "0000".repeat(11) + "2048";
  assert.equal(classifyQrPayload(bytesOf(digits)).format, "unknown");
});

test("a Standard SeedQR with the wrong digit count is unknown", () => {
  const digits = "0000".repeat(11);
  assert.equal(classifyQrPayload(bytesOf(digits)).format, "unknown");
  // SeedQR defines 12 and 24 words only: a 60-digit (15-word) payload is
  // refused by its length, before any checksum.
  assert.equal(classifyQrPayload(bytesOf("0000".repeat(15))).format, "unknown");
});

test("16 zero bytes are a 12-word CompactSeedQR", () => {
  const result = classifyQrPayload(new Uint8Array(16));
  assert.equal(result.format, "compact-seedqr");
  assert.equal(result.words, 12);
  assert.deepEqual(Array.from(result.indices), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
});

test("32 zero bytes are a 24-word CompactSeedQR", () => {
  const result = classifyQrPayload(new Uint8Array(32));
  assert.equal(result.format, "compact-seedqr");
  assert.equal(result.words, 24);
  assert.equal(result.indices.length, 24);
  for (let i = 0; i < 23; i += 1) assert.equal(result.indices[i], 0);
  assert.equal(result.indices[23], 102);
});

test("16 ASCII digits are not read as CompactSeedQR entropy", () => {
  assert.equal(classifyQrPayload(bytesOf("1234567890123456")).format, "unknown");
});

test("16 or 32 bytes of text are not read as CompactSeedQR entropy", () => {
  // Hex text, a password or a label (gates on b3f2e6a and ba2a83d: MiniMax,
  // DeepSeek red team), in any language.
  assert.equal(classifyQrPayload(bytesOf("0123456789abcdef0123456789abcdef")).format, "unknown");
  assert.equal(classifyQrPayload(bytesOf("correct horse ba")).format, "unknown");
  const accented = new TextEncoder().encode("contraseña 1234");
  assert.equal(accented.length, 16);
  assert.equal(classifyQrPayload(accented).format, "unknown");
  // Bytes that are not valid UTF-8 text are raw entropy.
  const binary = bytesOf("correct horse ba");
  binary[7] = 0x80;
  assert.equal(classifyQrPayload(binary).format, "compact-seedqr");
  // So is text with a control character in it.
  const controlled = bytesOf("correct horse ba");
  controlled[3] = 0x01;
  assert.equal(classifyQrPayload(controlled).format, "compact-seedqr");
});

test("a compressed mainnet WIF is classified", () => {
  const text = wifFor(KEY_ONE);
  const result = classifyQrPayload(bytesOf(text));
  assert.equal(result.format, "wif");
  assert.equal(result.network, "mainnet");
  assert.equal(result.compressed, true);
  assert.equal("text" in result, false, "the classifier must not build a string");
  assert.deepEqual(Array.from(result.bytes), Array.from(bytesOf(text)));
  result.bytes.fill(0);
});

test("an uncompressed mainnet WIF is classified", () => {
  const text = wifFor(KEY_ONE, { compressed: false });
  const result = classifyQrPayload(bytesOf(text));
  assert.equal(result.format, "wif");
  assert.equal(result.network, "mainnet");
  assert.equal(result.compressed, false);
  assert.deepEqual(Array.from(result.bytes), Array.from(bytesOf(text)));
  result.bytes.fill(0);
});

test("a testnet WIF is classified", () => {
  const text = wifFor(KEY_ONE, { testnet: true });
  const result = classifyQrPayload(bytesOf(text));
  assert.equal(result.format, "wif");
  assert.equal(result.network, "testnet");
  assert.equal(result.compressed, true);
  assert.deepEqual(Array.from(result.bytes), Array.from(bytesOf(text)));
  result.bytes.fill(0);
});

test("a WIF with a corrupted checksum is unknown", () => {
  const text = wifFor(KEY_ONE);
  const corrupted = text.slice(0, 10) + (text[10] === "a" ? "b" : "a") + text.slice(11);
  assert.equal(classifyQrPayload(bytesOf(corrupted)).format, "unknown");
});

test("a WIF result carries the payload bytes, never text", () => {
  const text = wifFor(KEY_ONE);
  const payload = bytesOf(text);
  const result = classifyQrPayload(payload);
  assert.equal(result.format, "wif");
  assert.equal("text" in result, false, "the classifier must not build a string");
  assert.ok(result.bytes instanceof Uint8Array);
  assert.deepEqual(Array.from(result.bytes), Array.from(payload));
  assert.notEqual(result.bytes, payload, "the caller owns a fresh copy");
  // The caller zeroes its own payload; the result's copy is independent.
  payload.fill(0);
  assert.deepEqual(Array.from(result.bytes), Array.from(bytesOf(text)));
  result.bytes.fill(0);
});

test("a mini key or a hex key is not classified as a WIF", () => {
  const mini = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
  assert.notEqual(classifyQrPayload(bytesOf(mini)).format, "wif");
  const hexKey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
  assert.notEqual(classifyQrPayload(bytesOf(hexKey)).format, "wif");
});

test("classifyWif never builds a string", () => {
  const source = readFileSync(new URL("../src/js/qr-payload.js", import.meta.url), "utf8");
  const start = source.indexOf("const classifyWif = (bytes) => {");
  assert.ok(start >= 0, "classifyWif is defined");
  const end = source.indexOf("\n};", start);
  assert.ok(end > start, "classifyWif has an end");
  const body = source.slice(start, end);
  for (const forbidden of ["fromCharCode", "TextDecoder", "join(", "`"]) {
    assert.equal(body.includes(forbidden), false, `classifyWif must not contain ${forbidden}`);
  }
});

test("a 12-word phrase is classified as words", () => {
  const result = classifyQrPayload(bytesOf(ABANDON_12));
  assert.equal(result.format, "words");
  assert.equal(result.words, 12);
  assert.deepEqual(Array.from(result.indices), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
});

test("an uppercase phrase is unknown", () => {
  assert.equal(classifyQrPayload(bytesOf(ABANDON_12.replace("about", "About"))).format, "unknown");
});

test("a double-spaced phrase is unknown", () => {
  assert.equal(classifyQrPayload(bytesOf(ABANDON_12.replace("abandon abandon", "abandon  abandon"))).format, "unknown");
});

test("a phrase with an unknown word is unknown", () => {
  assert.equal(classifyQrPayload(bytesOf(ABANDON_12.replace("about", "abandonx"))).format, "unknown");
});

test("an unknown payload is not echoed", () => {
  const secret = bytesOf("correct horse battery staple");
  const result = classifyQrPayload(secret);
  assert.deepEqual(result, { format: "unknown", length: secret.length });
});

// A words QR is matched byte for byte: decoding it made the scan path's only
// string copies of the mnemonic (red-team sweep 0eed735, qr-payload #3).
test("a words QR classifies without decoding the payload to text", () => {
  const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const decode = TextDecoder.prototype.decode, seen = [];
  TextDecoder.prototype.decode = function (input, options) {
    const text = decode.call(this, input, options);
    seen.push(text);
    return text;
  };
  let result;
  try {
    result = classifyQrPayload(new TextEncoder().encode(words));
  } finally {
    TextDecoder.prototype.decode = decode;
  }
  assert.equal(result.format, "words");
  assert.deepEqual([...result.indices], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
  assert.ok(!seen.some((text) => text.includes("abandon")), "no decoded copy of the words");
  for (const bad of [words.replace("about", "About"), words.replace(" about", "  about"), words + " ", words.replace("about", "abouT"), "\ufeff" + words]) {
    assert.notEqual(classifyQrPayload(new TextEncoder().encode(bad)).format, "words", JSON.stringify(bad.slice(-8)));
  }
});

test("the byte-level word match finds every word at its own index", () => {
  // Random valid phrases of each length; their indices come from bip39.js,
  // and the words from the published list.
  let seen = 0;
  for (let round = 0; round < 300; round += 1) {
    const entropy = randomBytes([16, 20, 24, 28, 32][round % 5]);
    const expected = [...indicesFromEntropy(entropy)];
    const result = classifyQrPayload(new TextEncoder().encode(expected.map((index) => bip39English[index]).join(" ")));
    assert.equal(result.format, "words", `round ${round}`);
    assert.deepEqual([...result.indices], expected, `round ${round}`);
    seen += expected.length;
  }
  assert.ok(seen > 4000, "the rounds cover the list widely");
  // The first and last words of the list, which a sort slip would lose first,
  // found through the matcher itself (BIP39 vectors: all-zero and all-ones
  // entropy; #1478 gate, Kimi, GLM, MiniMax).
  const ends = (phrase) => [...classifyQrPayload(new TextEncoder().encode(phrase)).indices];
  assert.deepEqual(ends("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), [...Array(11).fill(0), bip39English.indexOf("about")]);
  assert.deepEqual(ends("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"), [...Array(11).fill(2047), bip39English.indexOf("wrong")]);
});

// Text with a tab or line break is text, not CompactSeedQR entropy (red-team
// sweep 0eed735, qr-payload #5).
test("16 or 32 bytes of text ending in a line break are not read as a CompactSeedQR", () => {
  for (const text of ["my password!123\n", "my password!12\r\n", "tab\tseparated!!!", "x".repeat(31) + "\n"]) {
    const bytes = new TextEncoder().encode(text);
    assert.ok([16, 32].includes(bytes.length), `fixture length ${bytes.length}`);
    assert.notEqual(classifyQrPayload(bytes).format, "compact-seedqr", JSON.stringify(text));
  }
});
