// Tests for the libsecp256k1 WASM facade (src/js/secp256k1.js, loaded by
// src/js/entropylab-wasm.js).
// Run with `npm test` (part of the default and CI suites).
//
// Two layers of assurance:
//  1. Fixed, independently published constants (generator point, 2G).
//  2. Differential checks against @noble/curves (pinned, previously the
//     implementation): the migration must be byte-for-byte behavior
//     preserving, including RFC 6979 extra-entropy semantics used for
//     Bitcoin Core-style low-r grinding.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";
import { secp256k1, secp256k1Ready } from "../src/js/secp256k1.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// Fixed inputs; nothing here is secret.
const KEY1 = new Uint8Array(32).fill(0).map((_, i) => (i === 31 ? 1 : 0)); // 0x01
const MSG = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const KEY = new Uint8Array(32).map((_, i) => (i * 13 + 5) & 0xff);
const G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G_COMPRESSED = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

test("secp256k1Ready resolves (WASM initialized synchronously under Node)", async () => {
  await secp256k1Ready;
});

test("committed WASM artifact is intact (sha256 in module header matches payload)", () => {
  const source = readFileSync(join(root, "src/js/entropylab-wasm-b64.js"), "utf8");
  const declared = source.match(/wasm sha256: ([0-9a-f]{64})/);
  assert.ok(declared, "module header carries the wasm sha256");
  const b64 = source.match(/export const ENTROPYLAB_WASM_B64 =\s*"([A-Za-z0-9+/=]+)";/);
  assert.ok(b64, "module exports the base64 payload");
  const actual = createHash("sha256").update(Buffer.from(b64[1], "base64")).digest("hex");
  assert.equal(actual, declared[1]);
});

test("committed WASM carries no build-host paths (remapped at build time)", () => {
  const source = readFileSync(join(root, "src/js/entropylab-wasm-b64.js"), "utf8");
  const payload = Buffer.from(source.match(/"([A-Za-z0-9+/=]+)"/)[1], "base64").toString("latin1");
  for (const banned of ["/home/", "/Users/", ".cargo/", ".rustup/"]) {
    assert.equal(payload.includes(banned), false, `build fingerprints the build host: ${banned}`);
  }
});

test("getPublicKey(1) is the generator point, compressed and uncompressed", () => {
  assert.equal(bytesToHex(secp256k1.getPublicKey(KEY1, true)), G_COMPRESSED);
  const uncompressed = secp256k1.getPublicKey(KEY1, false);
  assert.equal(uncompressed.length, 65);
  assert.equal(uncompressed[0], 4);
  assert.equal(bytesToHex(uncompressed.slice(1, 33)), G_COMPRESSED.slice(2));
});

test("getPublicKey rejects invalid private keys", () => {
  assert.throws(() => secp256k1.getPublicKey(new Uint8Array(32), true)); // zero
  assert.throws(() => secp256k1.getPublicKey(new Uint8Array(31), true)); // wrong length
});

test("sign is byte-identical to noble for plain RFC 6979 and extra entropy", () => {
  const cases = [
    { extraEntropy: false },
    { extraEntropy: new Uint8Array(32) }, // 32 zero bytes are mixed in
    { extraEntropy: (() => { const b = new Uint8Array(32); b[0] = 7; return b; })() }, // Core grind counter
  ];
  for (const options of cases) {
    const got = secp256k1.sign(MSG, KEY, { prehash: false, ...options });
    const want = noble.sign(MSG, KEY, { prehash: false, ...options });
    assert.equal(bytesToHex(got), bytesToHex(want));
    assert.equal(got.length, 64); // compact r || s, low-S
  }
});

test("sign refuses random extra entropy and unhashed messages", () => {
  assert.throws(() => secp256k1.sign(MSG, KEY, { prehash: false, extraEntropy: true }), /extraEntropy/);
  assert.throws(() => secp256k1.sign(new Uint8Array(5), KEY, {}), /prehash/);
  assert.throws(() => secp256k1.sign(MSG, new Uint8Array(32), { prehash: false }));
});

test("verify round-trips and rejects tampering", () => {
  const sig = secp256k1.sign(MSG, KEY, { prehash: false });
  const pubkey = secp256k1.getPublicKey(KEY, true);
  assert.equal(secp256k1.verify(sig, MSG, pubkey, { prehash: false }), true);
  const wrong = MSG.slice();
  wrong[0] ^= 1;
  assert.equal(secp256k1.verify(sig, wrong, pubkey, { prehash: false }), false);
});

test("verify high-S policy matches noble (lowS: false accepts via normalization)", () => {
  const sig = secp256k1.sign(MSG, KEY, { prehash: false });
  const pubkey = secp256k1.getPublicKey(KEY, true);
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const s = BigInt("0x" + bytesToHex(sig.slice(32)));
  const highS = n - s;
  const malleated = new Uint8Array([...sig.slice(0, 32), ...hexToBytes(highS.toString(16).padStart(64, "0"))]);
  const der = secp256k1.Signature.fromBytes(malleated).toBytes("der");
  assert.equal(secp256k1.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: false }), true);
  assert.equal(secp256k1.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: true }), false);
  // noble agrees on both policy settings.
  assert.equal(noble.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: false }), true);
  assert.equal(noble.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: true }), false);
});

test("verify never throws on malformed input", () => {
  const pubkey = secp256k1.getPublicKey(KEY, true);
  assert.equal(secp256k1.verify(new Uint8Array(3), MSG, pubkey, { prehash: false }), false);
  assert.equal(secp256k1.verify(new Uint8Array(64), MSG, pubkey, { prehash: false }), false);
  assert.equal(secp256k1.verify(secp256k1.sign(MSG, KEY, { prehash: false }), MSG, new Uint8Array(33), { prehash: false }), false);
});

test("Signature strict DER <-> compact round-trip, lax encodings rejected", () => {
  const sig = secp256k1.sign(MSG, KEY, { prehash: false });
  const der = secp256k1.Signature.fromBytes(sig).toBytes("der");
  const back = secp256k1.Signature.fromBytes(der, "der").toBytes("compact");
  assert.equal(bytesToHex(back), bytesToHex(sig));
  // agrees with noble's strict DER parser
  assert.equal(bytesToHex(noble.Signature.fromBytes(der, "der").toBytes("compact")), bytesToHex(sig));
  assert.throws(() => secp256k1.Signature.fromBytes(new Uint8Array([0x30, 0]), "der"));
  assert.throws(() => secp256k1.Signature.fromBytes(sig.slice(0, 63)));
});

test("Point: add and multiply match published constants and noble", () => {
  const G = secp256k1.Point.fromBytes(hexToBytes(G_COMPRESSED));
  const twoG = G.add(G);
  assert.equal(bytesToHex(twoG.toBytes(true)), TWO_G_COMPRESSED);
  assert.equal(bytesToHex(secp256k1.Point.BASE.multiply(2n).toBytes(true)), TWO_G_COMPRESSED);
  const fiveG = secp256k1.Point.BASE.multiply(2n).add(secp256k1.Point.BASE.multiply(3n));
  assert.equal(bytesToHex(fiveG.toBytes(true)), bytesToHex(noble.Point.BASE.multiply(5n).toBytes(true)));
  // uncompressed round-trip
  assert.equal(fiveG.toBytes(false).length, 65);
  assert.equal(bytesToHex(secp256k1.Point.fromBytes(fiveG.toBytes(false)).toBytes(true)), bytesToHex(fiveG.toBytes(true)));
});

test("Point rejects non-curve encodings", () => {
  const junk = new Uint8Array(33); // 0x00 prefix and zero x is not a point
  assert.throws(() => secp256k1.Point.fromBytes(junk));
  const badPrefix = hexToBytes(G_COMPRESSED);
  badPrefix[0] = 0x07;
  assert.throws(() => secp256k1.Point.fromBytes(badPrefix));
});
