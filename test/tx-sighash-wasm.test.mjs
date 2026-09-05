// Tests for the transaction parser and BIP143 sighash in the WASM module
// (src/js/tx.js over rust-bitcoin's Transaction/SighashCache).
// Run with `npm test`.
//
// Two layers of assurance:
//  1. The published BIP143 test vectors (bitcoin/bips bip-0143, native
//     P2WPKH and P2SH-P2WPKH examples, SIGHASH_ALL) — independent of any
//     implementation.
//  2. Differential round-trips: serializeTx(parseRawTx(x)) === x, and the
//     signed BIP143 example transaction parses with its witness intact.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRawTx, serializeTx, extractEcdsaSignatures } from "../src/js/tx.js";
import { wasmExports, withInput, withOutput } from "../src/js/entropylab-wasm.js";
import { hex } from "../src/js/coders.js";

// BIP143 "Native P2WPKH" example, unsigned transaction and its data.
const BIP143_P2WPKH_UNSIGNED = hex.decode(
  "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffff" +
  "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff" +
  "02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac" +
  "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
);
// scriptCodes are the raw scripts (the WASM adds the CTxOut-style length
// prefix, as the app's hodlPushScript did); the BIP143 document shows them
// with the prefix (0x19) already attached.
const BIP143_P2WPKH_SCRIPTCODE = hex.decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
const BIP143_P2WPKH_SIGHASH = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";

// BIP143 "P2SH-P2WPKH" example.
const BIP143_WRAPPED_UNSIGNED = hex.decode(
  "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff" +
  "02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac" +
  "0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
);
const BIP143_WRAPPED_SCRIPTCODE = hex.decode("76a91479091972186c449eb1ded22b78e40d009bdf008988ac");
const BIP143_WRAPPED_SIGHASH = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";

// BIP143 "Native P2WPKH" signed transaction (witness-carrying).
const BIP143_P2WPKH_SIGNED = hex.decode(
  "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000049" +
  "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffff" +
  "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff" +
  "02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac" +
  "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac" +
  "000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01" +
  "21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
);

const sighashV0 = (raw, index, scriptCode, amount) =>
  withInput(raw, (p) => withInput(scriptCode, (sc) => withOutput(32, (o) => wasmExports().el_sighash_segwit_v0(p, raw.length, index, sc, scriptCode.length, amount, o))));

test("BIP143 published vector: native P2WPKH sighash", () => {
  const digest = sighashV0(BIP143_P2WPKH_UNSIGNED, 1, BIP143_P2WPKH_SCRIPTCODE, 600000000n);
  assert.equal(hex.encode(digest), BIP143_P2WPKH_SIGHASH);
});

test("BIP143 published vector: P2SH-P2WPKH sighash", () => {
  const digest = sighashV0(BIP143_WRAPPED_UNSIGNED, 0, BIP143_WRAPPED_SCRIPTCODE, 1000000000n);
  assert.equal(hex.encode(digest), BIP143_WRAPPED_SIGHASH);
});

test("the unsigned BIP143 vectors parse and re-serialize byte-identically", () => {
  for (const raw of [BIP143_P2WPKH_UNSIGNED, BIP143_WRAPPED_UNSIGNED]) {
    const parsed = parseRawTx(raw);
    assert.equal(parsed.segwit, false);
    assert.deepEqual(Array.from(serializeTx(parsed)), Array.from(raw));
  }
  const parsed = parseRawTx(BIP143_P2WPKH_UNSIGNED);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.locktime, 0x11);
  // Transaction versions are signed i32: wire ffffffff is version -1, and the
  // serializer writes the same four bytes back (issue #336).
  const negative = new Uint8Array(BIP143_P2WPKH_UNSIGNED);
  negative.set([0xff, 0xff, 0xff, 0xff], 0);
  const negParsed = parseRawTx(negative);
  assert.equal(negParsed.version, -1);
  assert.deepEqual(Array.from(serializeTx(negParsed)), Array.from(negative));
  // Version 2 keeps its positive sign, and i32::MIN stays exact.
  negative.set([0, 0, 0, 128], 0);
  assert.equal(parseRawTx(negative).version, -2147483648);
  assert.equal(parsed.inputs.length, 2);
  assert.equal(parsed.inputs[0].sequence, 0xffffffee); // wire bytes eeffffff, little-endian
  assert.equal(parsed.outputs[0].amount, 112340000n);
  assert.equal(hex.encode(parsed.outputs[0].script), "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac");
});

test("the signed BIP143 transaction parses with its witness intact", () => {
  const parsed = parseRawTx(BIP143_P2WPKH_SIGNED);
  assert.equal(parsed.segwit, true);
  assert.equal(parsed.inputs[0].witness.length, 0);
  assert.equal(parsed.inputs[1].witness.length, 2);
  const sigs = extractEcdsaSignatures(parsed);
  assert.equal(sigs.length, 2);
  // the witness signature in input 1 commits to the published sighash byte
  const witnessSig = sigs.find((s) => s.input === 1);
  assert.equal(witnessSig.sighash, 1);
  assert.equal(witnessSig.pubkey.length, 33);
});

test("a witness-heavy transaction is sized from its decode, not an estimate (issue #339)", () => {
  // 100,000 empty witness items: one wire byte each but four flat bytes each,
  // so the old 2x + 64 KiB estimate under-allocated and the decoder answered
  // "Transaction ended early" for a transaction that decodes fine.
  const items = 100_000;
  const raw = new Uint8Array([
    ...hex.decode("02000000" + "0001" + "01" + "11".repeat(32) + "00000000" + "00" + "ffffffff" + "01" + "0000000000000000" + "0151"),
    ...hex.decode("fe" + "a0860100"), // compact-size 100,000
    ...new Uint8Array(items),
    ...hex.decode("00000000"),
  ]);
  const parsed = parseRawTx(raw);
  assert.equal(parsed.segwit, true);
  assert.equal(parsed.inputs[0].witness.length, items);
  // Truncation and trailing bytes keep their distinct messages.
  assert.throws(() => parseRawTx(raw.slice(0, -5)), /ended early/);
  assert.throws(() => parseRawTx(new Uint8Array([...raw, 0])), /trailing bytes/);
});

test("non-canonical transactions are rejected", () => {
  // trailing bytes
  assert.throws(() => parseRawTx(new Uint8Array([...BIP143_WRAPPED_UNSIGNED, 0])), /trailing/);
  // segwit marker with a flag other than 0x01
  const bad = Uint8Array.from(BIP143_P2WPKH_SIGNED);
  bad[5] = 2;
  assert.throws(() => parseRawTx(bad), /witness flag/);
  // segwit marker with all-empty witnesses (rust-bitcoin: "witness flag set
  // but no witnesses present")
  const emptyWitness = hex.decode(
    "01000000000101" + "11".repeat(32) + "00000000" + "00" + "ffffffff" + "01" + "e803000000000000" + "016a" + "00" + "00000000"
  );
  assert.throws(() => parseRawTx(emptyWitness));
  // non-minimal compact size (0xfd-prefixed small count)
  const nonMinimal = hex.decode(
    "01000000" + "fd0100" + "11".repeat(32) + "00000000" + "00" + "ffffffff" + "01" + "e803000000000000" + "016a" + "00000000"
  );
  assert.throws(() => parseRawTx(nonMinimal));
});

test("serializeTx rejects out-of-u64-range amounts instead of wrapping (issue #338)", () => {
  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{ txid: new Uint8Array(32), vout: 0, scriptSig: new Uint8Array(), sequence: 0xffffffff }],
    outputs: [{ amount: 0n, script: new Uint8Array([0x51]) }],
  };
  const withAmount = (amount) => ({ ...tx, outputs: [{ amount, script: new Uint8Array([0x51]) }] });
  // In-range boundaries serialize: 0, MAX_MONEY, and u64::MAX.
  for (const amount of [0n, 2100000000000000n, 0xffffffffffffffffn, "0", "18446744073709551615"]) {
    assert.doesNotThrow(() => serializeTx(withAmount(amount)), String(amount));
  }
  // u64::MAX lands as eight 0xff bytes (no wrap to zero).
  const max = serializeTx(withAmount(0xffffffffffffffffn));
  assert.deepEqual(Array.from(max.slice(47, 55)), Array(8).fill(0xff));
  // Negative and oversized values must throw, not alias modulo 2^64.
  for (const amount of [-1n, 0x10000000000000000n, 0x10000000000000001n, "-1", "18446744073709551616"]) {
    assert.throws(() => serializeTx(withAmount(amount)), /out of the unsigned 64-bit range/, String(amount));
  }
});
