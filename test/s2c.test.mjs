// Shared ECDSA sign-to-contract (anti-exfil) relation: the Nonce Inspector's
// Jade check and the AEXB-v1 verifier both use these helpers.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";

import { s2cCommittedNonce, s2cHostCommitment, s2cSignatureMatches } from "../src/js/s2c.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady } from "../src/js/hashes.js";

await secp256k1Ready;
await hashesReady;

const hex = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const toHex = (bytes) => Buffer.from(bytes).toString("hex");
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(Buffer.from(bytes)).digest());
const concat = (...arrays) => {
  const out = new Uint8Array(arrays.reduce((sum, arr) => sum + arr.length, 0));
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
};
const taggedHash = (tag, ...chunks) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concat(tagHash, tagHash, ...chunks));
};
const bigOf = (bytes) => BigInt(`0x${toHex(bytes)}`);

// The same Jade fixture shape as test/psbt-anti-exfil.test.mjs: a 32-byte host
// nonce rho and a 33-byte compressed signer opening R0.
const host = hex("11".repeat(32));
const opening = hex("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");

// Pinned against secp256k1-zkp by test/psbt-anti-exfil.test.mjs, so the
// reference tweak below does not come from the module under test.
const TWEAK_HEX = "52be4b29692b2aa0d852edd9a5451e8ca2e6759b41c4bf0dc290f99cf145bea2";

test("the reference tweak reproduces the pinned secp256k1-zkp vector", () => {
  assert.equal(toHex(taggedHash("s2c/ecdsa/point", opening, host)), TWEAK_HEX);
});

const tweak = bigOf(hex(TWEAK_HEX));
const committed = noble.Point.fromBytes(opening).add(noble.Point.BASE.multiply(tweak)).toBytes(true);
const r = committed.slice(1);

test("the host commitment is TaggedHash(\"s2c/ecdsa/data\", rho)", () => {
  const expected = taggedHash("s2c/ecdsa/data", host);
  assert.equal(expected.length, 32);
  assert.equal(toHex(s2cHostCommitment(host)), toHex(expected));
});

test("the committed nonce is R0 + tweak*G in compressed form", () => {
  assert.equal(toHex(s2cCommittedNonce(opening, host)), toHex(committed));
});

test("an honest transcript matches", () => {
  assert.equal(s2cSignatureMatches(r, opening, host), true);
});

test("a wrong host nonce, a tampered r or a foreign opening does not match", () => {
  assert.equal(s2cSignatureMatches(r, opening, hex("bb".repeat(32))), false, "different host nonce");
  const tampered = Uint8Array.from(r);
  tampered[31] ^= 1;
  assert.equal(s2cSignatureMatches(tampered, opening, host), false, "r one ulp off");
  const foreign = noble.Point.BASE.multiply(4n).toBytes(true);
  assert.equal(s2cSignatureMatches(r, foreign, host), false, "a different opening point");
});

test("an invalid opening is refused instead of throwing", () => {
  // A zero tweak or a tweak >= n is refused by the same guard, but neither can
  // be built without a tagged-hash preimage; the invalid-opening path is the
  // reachable half of that guard.
  const zero = new Uint8Array(33);
  assert.equal(s2cCommittedNonce(zero, host), null);
  assert.equal(s2cSignatureMatches(r, zero, host), false);
  const uncompressed = Uint8Array.from([0x04, ...new Uint8Array(32)]);
  assert.equal(s2cCommittedNonce(uncompressed, host), null);
  assert.equal(s2cSignatureMatches(r, uncompressed, host), false);
});
