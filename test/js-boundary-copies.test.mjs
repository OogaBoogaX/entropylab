// RT-JSBOUNDARY-1: the JS side must not leave a second, mutable copy of a
// secret behind after a WASM call. The facades already zero the buffers they
// build for input; these tests retain the *output* temporaries — every array
// Uint8Array.prototype.slice or Uint8Array.from produces during the call —
// and require them all zero once the call returns, on success, on refusal and
// on a failure thrown between the WASM call and the result, while the
// caller-owned output is unchanged.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { wasmReady } from "../src/js/entropylab-wasm.js";
import { base58checkDecode, base58checkEncode } from "../src/js/base58.js";
import { bech32mDecode, bech32mEncode, toWords } from "../src/js/bech32.js";
import { encodeSpscan } from "../src/js/bip352.js";
import { entropyToMnemonic, mnemonicToEntropy } from "../src/js/bip39.js";
import { descriptorDerive } from "../src/js/addresses.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";

await wasmReady;

// Both intercepted methods are how the facades copy bytes out of WASM
// (`heap().slice`) and how they build the word copy handed back in
// (`Uint8Array.from(words)`). Keeping the produced arrays is the only way to
// check a temporary the caller never sees.
const retained = (fn) => {
  const seen = [];
  const slice = Uint8Array.prototype.slice;
  const from = Uint8Array.from;
  Uint8Array.prototype.slice = function (...args) {
    const copy = Reflect.apply(slice, this, args);
    seen.push(copy);
    return copy;
  };
  Uint8Array.from = function (...args) {
    const copy = Reflect.apply(from, this, args);
    seen.push(copy);
    return copy;
  };
  try {
    return { value: fn(), seen };
  } catch (error) {
    return { error, seen };
  } finally {
    Uint8Array.prototype.slice = slice;
    Uint8Array.from = from;
  }
};

const assertZeroed = (seen, label) => {
  assert.ok(seen.length > 0, `${label}: no temporary was retained, so the wipe is not exercised`);
  for (const [index, bytes] of seen.entries()) {
    assert.ok(bytes.every((byte) => byte === 0), `${label}: temporary ${index + 1} of ${seen.length} (${bytes.length} bytes) still holds the secret`);
  }
};

// Runs `fn` with one global replaced by a thrower, so the cleanup path is
// entered by a failure between the WASM call and the returned value.
const failing = (target, name, message, fn) => {
  const original = target[name];
  target[name] = () => {
    throw new Error(message);
  };
  try {
    return fn();
  } finally {
    target[name] = original;
  }
};

test("Base58Check leaves no unzeroed copy of the encoded WIF", () => {
  const payload = new Uint8Array(34);
  payload[0] = 0x80;
  payload.fill(0x11, 1, 33);
  payload[33] = 0x01;
  const { value: text, seen } = retained(() => base58checkEncode(payload));
  assert.equal(typeof text, "string");
  assert.deepEqual(base58checkDecode(text), payload, "the caller-owned result is unchanged");
  assertZeroed(seen, "WIF encode");
  assert.deepEqual(payload, Uint8Array.from([0x80, ...new Uint8Array(32).fill(0x11), 0x01]), "the caller's payload must not be zeroed");
});

test("bech32m encoding leaves no unzeroed copy of the key-expression bytes", () => {
  const secret = new Uint8Array(65).fill(0x22);
  const words = [0, ...toWords(secret)];
  const { value: text, seen } = retained(() => bech32mEncode("spscan", words));
  assert.match(text, /^spscan1/);
  assert.deepEqual(bech32mDecode(text).words, words, "the encoded string still carries the caller's words");
  assertZeroed(seen, "spscan encode");
});

test("bech32m encoding zeroes its word copy when the call refuses", () => {
  const { error, seen } = retained(() => bech32mEncode("x".repeat(84), [0, 1, 2]));
  assert.match(error.message, /bech32m encoding failed/);
  assertZeroed(seen, "refused encode");
});

test("bech32m decoding zeroes the byte copy behind the returned words", () => {
  const secret = new Uint8Array(66).fill(0x33);
  const words = [0, ...toWords(secret)];
  const text = bech32mEncode("sp", words);
  const { value: decoded, seen } = retained(() => bech32mDecode(text));
  assert.equal(decoded.prefix, "sp");
  assert.deepEqual(decoded.words, words);
  assertZeroed(seen, "sp decode");
});

test("the spscan key expression keeps no copy of the toWords array", () => {
  const scan = new Uint8Array(32).fill(0x07);
  // The generator point's compressed encoding, hex-decoded here so the
  // fixture is the published BIP-340 value rather than one produced by the
  // code under test.
  const generator = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const spendPub = Uint8Array.from({ length: 33 }, (_, index) => Number.parseInt(generator.slice(index * 2, index * 2 + 2), 16));
  const arrays = [];
  const unshift = Array.prototype.unshift;
  Array.prototype.unshift = function (...args) {
    arrays.push(this);
    return Reflect.apply(unshift, this, args);
  };
  let text;
  try {
    text = encodeSpscan(scan, spendPub, "mainnet");
  } finally {
    Array.prototype.unshift = unshift;
  }
  assert.match(text, /^spscan1/);
  assert.equal(arrays.length, 1, "the key expression must prepend the version in place");
  assert.equal(arrays[0].length, 105, "65 payload bytes are 104 five-bit words plus the prepended version");
  assert.ok(arrays[0].every((word) => word === 0), "the toWords array still holds the scan key");
  assert.deepEqual(scan, new Uint8Array(32).fill(0x07), "the caller's key must not be zeroed");
});

test("BIP39 encoding zeroes the mnemonic byte copy", () => {
  const entropy = new Uint8Array(16).fill(0x42);
  const { value: phrase, seen } = retained(() => entropyToMnemonic(entropy));
  assert.equal(phrase.split(" ").length, 12);
  assert.deepEqual(mnemonicToEntropy(phrase), entropy, "the caller-owned phrase still decodes");
  assertZeroed(seen, "mnemonic encode");
});

test("descriptor derivation zeroes the record bytes a private descriptor produces", () => {
  // BIP32 test vector 1's master xprv, so the descriptor carries real private
  // material rather than a synthetic string.
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const { value, seen } = retained(() => descriptorDerive(`wpkh(${xprv}/0/*)`, 0, "mainnet"));
  assert.match(value.address, /^bc1/);
  assert.equal(seen.length, 1, "the derived record arrives as one byte copy");
  assertZeroed(seen, "descriptor derive");
});

test("descriptor derivation zeroes the record when decoding throws", () => {
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const { error, seen } = failing(TextDecoder.prototype, "decode", "decoder blew up", () =>
    retained(() => descriptorDerive(`wpkh(${xprv}/0/*)`, 0, "mainnet"))
  );
  assert.match(error.message, /decoder blew up/);
  assertZeroed(seen, "descriptor derive, decoder failure");
});

test("PSBT inspection zeroes the JSON copy when parsing throws", () => {
  const b64 = readFileSync(new URL("fixtures/psbt/p2wpkh-1in-2out.b64", import.meta.url), "utf8").trim();
  const bytes = Uint8Array.from(atob(b64), (char) => char.charCodeAt(0));
  const { error, seen } = failing(JSON, "parse", "parser blew up", () =>
    retained(() => psbtInspectDoc(bytes))
  );
  assert.match(error.message, /parser blew up/);
  assertZeroed(seen, "PSBT inspect, parse failure");
});

test("PSBT inspection zeroes the JSON byte copy that carried the document", () => {
  const b64 = readFileSync(new URL("fixtures/psbt/p2wpkh-1in-2out.b64", import.meta.url), "utf8").trim();
  const bytes = Uint8Array.from(atob(b64), (char) => char.charCodeAt(0));
  const { value: doc, seen } = retained(() => psbtInspectDoc(bytes));
  assert.ok(doc.tx && Array.isArray(doc.inputs));
  assert.equal(seen.length, 1, "the inspection document arrives as one JSON byte copy");
  assertZeroed(seen, "PSBT inspect");
  assert.deepEqual(bytes, Uint8Array.from(atob(b64), (char) => char.charCodeAt(0)), "the caller's PSBT bytes must not be zeroed");
});
