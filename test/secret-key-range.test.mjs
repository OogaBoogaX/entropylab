// #546: a private key's range check must not copy the key into JavaScript.
//
// Security contract: a private key is accepted exactly when its 32 bytes are
// a number from 1 to n - 1 (n, the secp256k1 group order), and checking it
// turns the key into neither a BigInt nor text. Strings and BigInts cannot be
// wiped, so a check that builds one leaves a copy of every key it sees; the
// check runs in WebAssembly instead (libsecp256k1), on a buffer that is zeroed
// when freed. Every place that range-checks a private key is covered: the
// secp256k1 facade, a BIP32 node, a BIP-85 child key, and the Key Station and
// PSBT key checks (hodlAssertPrivateKey).
//
// Expected values: the group order n from SEC 2 (secp256k1 parameters), and
// @noble/curves as the reference library for values on both sides of n.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { HDKey } from "../src/js/hdkey.js";
import { isValidSecp256k1Secret } from "../src/js/bip85.js";
import { hex } from "../src/js/coders.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

// SEC 2, section 2.4.1.
const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const bytes32 = (value) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex"));
const BOUNDARIES = [
  ["zero", 0n, false],
  ["one", 1n, true],
  ["two", 2n, true],
  ["2^255", 1n << 255n, true],
  ["n - 2^128 (below n in the upper half)", N - (1n << 128n), true],
  ["n - 2", N - 2n, true],
  ["n - 1", N - 1n, true],
  ["n", N, false],
  ["n + 1", N + 1n, false],
  ["n + 2^128 (above n in the upper half)", N + (1n << 128n), false],
  ["2^256 - 1", (1n << 256n) - 1n, false],
];
// Values around n and spread over the range, compared with the reference.
const sample = [];
for (let delta = -40n; delta <= 40n; delta++) sample.push(bytes32(N + delta));
for (let i = 0; i < 200; i++) {
  const digest = createHash("sha256").update(`secret-key-range ${i}`).digest();
  // Every fourth value keeps the order's first 16 bytes, so the comparison
  // is decided in the low half.
  if (i % 4 === 0) digest.set(bytes32(N).subarray(0, 16));
  sample.push(Uint8Array.from(digest));
}

const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
const hexEncodes = [];
const spyHex = { ...hex, encode: (value) => (hexEncodes.push(value), hex.encode(value)) };
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
const app = await loadAppFunctions(["hodlAssertPrivateKey"], { stubs: { hodlHex: spyHex } });
delete globalThis.document;
delete globalThis.window;

const accepts = (check) => (key) => {
  try {
    return check(key) !== false;
  } catch {
    return false;
  }
};
const CHECKS = [
  ["the secp256k1 facade", (key) => secp256k1.utils.isValidSecretKey(key)],
  ["a BIP32 node", (key) => new HDKey({ privateKey: key, chainCode: new Uint8Array(32) })],
  ["a BIP-85 child key", (key) => isValidSecp256k1Secret(key)],
  ["the Key Station and PSBT key check", (key) => app.hodlAssertPrivateKey(key)],
];

for (const [name, check] of CHECKS) {
  test(`${name} accepts exactly 1 to n - 1`, () => {
    const valid = accepts(check);
    for (const [label, value, expected] of BOUNDARIES) assert.equal(valid(bytes32(value)), expected, label);
    for (const key of sample) assert.equal(valid(key), noble.utils.isValidSecretKey(key), hex.encode(key));
    for (const length of [0, 31, 33, 64]) assert.equal(valid(new Uint8Array(length).fill(1)), false, `${length} bytes`);
  });

  // BigInt is swapped for a counting proxy while the check runs; the key
  // reaches no BigInt and no hex encoder.
  test(`${name} turns the key into neither a BigInt nor text`, () => {
    const real = globalThis.BigInt;
    let bigints = 0;
    hexEncodes.length = 0;
    globalThis.BigInt = new Proxy(real, { apply: (target, self, args) => (bigints++, Reflect.apply(target, self, args)) });
    try {
      for (const value of [1n, N - 1n, N, 0n]) accepts(check)(bytes32(value));
    } finally {
      globalThis.BigInt = real;
    }
    assert.equal(bigints, 0, "the check built a BigInt");
    assert.deepEqual(hexEncodes, [], "the check encoded the key as hex");
  });
}

test("the facade check leaves no copy of the key in WebAssembly memory", async () => {
  const { heap } = await import("../src/js/entropylab-wasm.js");
  const key = bytes32(N - 12345n);
  assert.equal(secp256k1.utils.isValidSecretKey(key), true);
  // The stack is zeroed once the task settles.
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(Buffer.from(heap()).indexOf(Buffer.from(key)), -1);
});
