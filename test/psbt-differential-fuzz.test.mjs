// Differential fuzz of PSBT decoding: the app's decoder (psbtInspectDoc in
// src/js/psbt-wasm.js, rust-bitcoin 0.32 in WASM) against @scure/btc-signer's
// Transaction.fromPSBT (pinned, an independent implementation). Each
// iteration copies one of the repo's valid fixtures (test/fixtures/psbt/*.b64)
// and changes one consensus field of its unsigned transaction — the version,
// the locktime, one output amount, or one byte of one output script — in
// place, so the PSBT framing stays intact. Proprietary and other key-value
// maps are never touched. Then:
//
//   - both decoders reject it: pass;
//   - both accept it: the unsigned transaction's txid, the output count, and
//     every output amount and script must be byte-identical;
//   - one accepts and the other rejects: fail, naming the side that accepted.
//
// "Accept" is each side's parse verdict: for the app, psbtInspectDoc returns
// and rust-bitcoin's own Psbt::deserialize accepted the bytes
// (rustBitcoinError is null); for scure, fromPSBT returns. scure runs with the
// flags it uses itself when it only needs to decode a transaction it did not
// build (the nonWitnessUtxo parse in @scure/btc-signer's transaction.ts):
// unknown output scripts, unknown inputs, non-standard versions, and skipped
// script sanity checks. Those are policy checks on building and signing, not
// on the bytes; the app's inspector reports the same concerns as problems
// rather than refusing to decode.
//
// The txid compared is the unsigned transaction's — the PSBT's identity under
// BIP174. The app side serializes the decoded fields with src/js/tx.js and
// hashes with src/js/hashes.js; the scure side hashes its own serialization
// with @noble/hashes. (scure's Transaction.id hashes any finalScriptSig in,
// which is the finalized transaction's txid, not the PSBT's.)
//
// Offline and deterministic: fixtures come from the repo, the PRNG exists only
// in this file, and the seed is fixed and never reseeded from the clock.
//
// Run with `node --test test/psbt-differential-fuzz.test.mjs` or `npm test`.
// PSBT_FUZZ_ITERATIONS=5000 widens a local run; CI runs the default.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Transaction } from "@scure/btc-signer";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { serializeTx } from "../src/js/tx.js";
import { sha256 } from "../src/js/hashes.js";
import { fuzzEnv, mulberry32, replayLine, withReplay } from "./fuzz-kit.mjs";

// --- deterministic randomness ------------------------------------------------

const FUZZ_SEED = 0x5eed0174;
const DEFAULT_ITERATIONS = 100;
const PSBT_ENV = fuzzEnv("PSBT_FUZZ", { defaultSeed: FUZZ_SEED, defaultIterations: DEFAULT_ITERATIONS });
const ITERATIONS = PSBT_ENV.iterations;
const TEST_NAME = "psbtInspectDoc and @scure/btc-signer agree on mutated PSBTs";

// --- fixtures and their unsigned-transaction layout --------------------------

const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "psbt");
const fixtures = readdirSync(dir)
  .filter((name) => name.endsWith(".b64"))
  .sort()
  .map((file) => ({ name: file.slice(0, -4), bytes: new Uint8Array(Buffer.from(readFileSync(join(dir, file), "utf8").trim(), "base64")) }));

const compactSize = (bytes, at) => {
  const first = bytes[at];
  if (first < 0xfd) return [first, 1];
  if (first === 0xfd) return [bytes[at + 1] | (bytes[at + 2] << 8), 3];
  if (first === 0xfe) return [(bytes[at + 1] | (bytes[at + 2] << 8) | (bytes[at + 3] << 16) | (bytes[at + 4] << 24)) >>> 0, 5];
  throw new Error("compact size over 32 bits in a fixture");
};

// Framing only: finds the byte offsets of the fields the mutator may change
// inside PSBT_GLOBAL_UNSIGNED_TX. The decoders under test do the parsing.
const unsignedTxLayout = (name, psbt) => {
  assert.deepEqual([...psbt.subarray(0, 5)], [0x70, 0x73, 0x62, 0x74, 0xff], `${name}: PSBT magic`);
  let at = 5;
  for (;;) {
    const [keyLength, keySize] = compactSize(psbt, at);
    at += keySize;
    if (keyLength === 0) break;
    const keyAt = at;
    at += keyLength;
    const [valueLength, valueSize] = compactSize(psbt, at);
    at += valueSize;
    if (keyLength === 1 && psbt[keyAt] === 0x00) return txLayout(name, psbt, at, valueLength);
    at += valueLength;
  }
  throw new Error(`${name} has no PSBT_GLOBAL_UNSIGNED_TX: a PSBT v2 fixture needs the mutator extended to its v2 fields`);
};
const txLayout = (name, bytes, start, length) => {
  let at = start;
  const version = at;
  at += 4;
  const [inputs, inputsSize] = compactSize(bytes, at);
  at += inputsSize;
  for (let i = 0; i < inputs; i++) {
    at += 36;
    const [scriptLength, scriptSize] = compactSize(bytes, at);
    at += scriptSize + scriptLength + 4;
  }
  const [outputs, outputsSize] = compactSize(bytes, at);
  at += outputsSize;
  const outputAt = [];
  for (let i = 0; i < outputs; i++) {
    const value = at;
    at += 8;
    const [scriptLength, scriptSize] = compactSize(bytes, at);
    at += scriptSize;
    outputAt.push({ value, script: at, scriptLength });
    at += scriptLength;
  }
  const locktime = at;
  at += 4;
  assert.equal(at, start + length, `${name}: the layout must cover the unsigned transaction exactly`);
  return { version, locktime, outputs: outputAt };
};

// --- mutations ---------------------------------------------------------------

const writeU32 = (bytes, at, value) => {
  for (let k = 0; k < 4; k++) bytes[at + k] = (value >>> (8 * k)) & 0xff;
};
const writeU64 = (bytes, at, value) => {
  for (let k = 0; k < 8; k++) bytes[at + k] = Number((value >> BigInt(8 * k)) & 0xffn);
};
const mutate = (fixture, rand) => {
  const rint = (n) => Math.floor(rand() * n);
  const pick = (items) => items[rint(items.length)];
  const randomU32 = (edges) => (rint(4) === 0 ? pick(edges) : rint(2 ** 32) >>> 0);
  const randomU64 = () =>
    rint(4) === 0
      ? pick([0n, 1n, 546n, 2_100_000_000_000_000n, 2_100_000_000_000_001n, 2n ** 63n, 2n ** 64n - 1n])
      : Array.from({ length: 8 }, () => BigInt(rint(256))).reduce((n, byte) => (n << 8n) | byte, 0n);
  const bytes = Uint8Array.from(fixture.bytes);
  const layout = unsignedTxLayout(fixture.name, bytes);
  const kinds = ["version", "locktime"];
  if (layout.outputs.length) kinds.push("output amount");
  if (layout.outputs.some((output) => output.scriptLength > 0)) kinds.push("output script byte");
  const kind = pick(kinds);
  if (kind === "version") {
    const value = randomU32([0, 1, 2, 3, 0x7fffffff, 0x80000000, 0xffffffff]);
    writeU32(bytes, layout.version, value);
    return { bytes, change: `version = 0x${value.toString(16)}` };
  }
  if (kind === "locktime") {
    const value = randomU32([0, 1, 499_999_999, 500_000_000, 0xfffffffe, 0xffffffff]);
    writeU32(bytes, layout.locktime, value);
    return { bytes, change: `locktime = ${value}` };
  }
  if (kind === "output amount") {
    const output = rint(layout.outputs.length), value = randomU64();
    writeU64(bytes, layout.outputs[output].value, value);
    return { bytes, change: `output ${output} amount = ${value}` };
  }
  const scripted = layout.outputs.map((output, index) => ({ ...output, index })).filter((output) => output.scriptLength > 0);
  const output = pick(scripted), offset = rint(output.scriptLength), flip = 1 + rint(255);
  bytes[output.script + offset] ^= flip;
  return { bytes, change: `output ${output.index} script byte ${offset} ^= 0x${flip.toString(16)}` };
};

// --- the two decoders --------------------------------------------------------

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => new Uint8Array(Buffer.from(text, "hex"));
const reversedHex = (bytes) => hex(Uint8Array.from(bytes).reverse());

const SCURE_DECODE_ONLY = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };

const entropyLab = (bytes) => {
  let doc;
  try {
    doc = psbtInspectDoc(bytes);
  } catch (error) {
    return { error: error.message };
  }
  if (doc.rustBitcoinError) return { error: `rust-bitcoin Psbt::deserialize: ${doc.rustBitcoinError}` };
  const tx = {
    version: doc.tx.version,
    locktime: doc.tx.locktime,
    inputs: doc.tx.inputs.map((input) => ({ txid: fromHex(input.txid).reverse(), vout: input.vout, scriptSig: fromHex(input.scriptSig), sequence: input.sequence })),
    outputs: doc.tx.outputs.map((output) => ({ amount: BigInt(output.value), script: fromHex(output.scriptPubKey) })),
  };
  return {
    txid: reversedHex(sha256(sha256(serializeTx(tx)))),
    outputs: tx.outputs.map((output) => ({ amount: output.amount, script: hex(output.script) })),
  };
};

const scure = (bytes) => {
  let tx;
  try {
    tx = Transaction.fromPSBT(bytes, SCURE_DECODE_ONLY);
  } catch (error) {
    return { error: error.message };
  }
  return {
    txid: reversedHex(nobleSha256(nobleSha256(tx.unsignedTx))),
    outputs: Array.from({ length: tx.outputsLength }, (_, index) => {
      const output = tx.getOutput(index);
      return { amount: output.amount, script: hex(output.script) };
    }),
  };
};

// --- the run -----------------------------------------------------------------

test("the fixtures load and every one decodes identically on both sides before mutation", () => {
  assert.ok(fixtures.length >= 5, `expected the committed PSBT fixtures, found ${fixtures.length}`);
  for (const fixture of fixtures) {
    unsignedTxLayout(fixture.name, fixture.bytes);
    const left = entropyLab(fixture.bytes), right = scure(fixture.bytes);
    assert.equal(left.error, undefined, `${fixture.name}: the app rejects an unmutated fixture: ${left.error}`);
    assert.equal(right.error, undefined, `${fixture.name}: @scure/btc-signer rejects an unmutated fixture: ${right.error}`);
    assert.deepEqual(left, right, `${fixture.name}: unmutated fixture decodes differently`);
  }
});

test(TEST_NAME, () => {
  assert.ok(Number.isSafeInteger(ITERATIONS) && ITERATIONS > 0, `PSBT_FUZZ_ITERATIONS must be a positive integer, got ${process.env.PSBT_FUZZ_ITERATIONS}`);
  try {
    const rand = mulberry32(PSBT_ENV.seed);
    const rint = (n) => Math.floor(rand() * n);
    const pick = (items) => items[rint(items.length)];
    for (let i = 0; i < ITERATIONS; i++) {
      const fixture = pick(fixtures);
      const { bytes, change } = mutate(fixture, rand);
      const where = `iteration ${i}, fixture ${fixture.name}, ${change}`;
      const left = entropyLab(bytes), right = scure(bytes);
      if (left.error || right.error) {
        assert.ok(left.error && right.error,
          `${where}: only ${left.error ? "@scure/btc-signer" : "psbtInspectDoc (rust-bitcoin)"} accepted\n  psbtInspectDoc:    ${left.error ?? "accepted"}\n  @scure/btc-signer: ${right.error ?? "accepted"}`);
      } else {
        assert.equal(left.txid, right.txid, `${where}: unsigned txid differs\n  psbtInspectDoc:    ${left.txid}\n  @scure/btc-signer: ${right.txid}`);
        assert.equal(left.outputs.length, right.outputs.length, `${where}: output count differs`);
        left.outputs.forEach((output, index) => {
          assert.equal(output.amount, right.outputs[index].amount, `${where}: output ${index} amount differs\n  psbtInspectDoc:    ${output.amount}\n  @scure/btc-signer: ${right.outputs[index].amount}`);
          assert.equal(output.script, right.outputs[index].script, `${where}: output ${index} script differs\n  psbtInspectDoc:    ${output.script}\n  @scure/btc-signer: ${right.outputs[index].script}`);
        });
      }
    }
  } catch (error) {
    throw withReplay(error, replayLine("PSBT_FUZZ", PSBT_ENV.seed, ITERATIONS, TEST_NAME, "test/psbt-differential-fuzz.test.mjs"));
  }
});
