// Differential fuzz of the signature hash: the app's rust-bitcoin sighash (in
// WASM) against @scure/btc-signer's (pinned, an independent implementation),
// for legacy, BIP143, and BIP341 spends and every standard sighash type.
// tx-sighash-wasm.test.mjs pins the published BIP143 SIGHASH_ALL vectors;
// this suite covers the other types and the other two algorithms.
//
// The app computes legacy, BIP143, and BIP341 digests in psbt-wasm, where
// psbtInspectDoc uses them to verify a PSBT's signatures; it does not export
// them. So each case builds one unsigned transaction with scure, takes
// scure's digest for one input, signs that digest with @noble/curves, and
// hands the PSBT to psbtInspectDoc:
//
//   - the signature must verify: the app's digest equals scure's;
//   - the same signature relabelled with another sighash type must not
//     verify, which proves the app computed a digest and checked it rather
//     than skipping the input;
//   - for BIP143, entropylab-wasm's el_sighash_segwit_v0 (SIGHASH_ALL, the
//     digest the app's RFC 6979 comparison uses) must equal scure's digest
//     byte for byte.
//
// Both sides hash the same scriptCode: the P2SH redeem script, P2WSH witness
// script, or tapleaf script the PSBT carries. Scripts are generated opcode
// soups, OP_CODESEPARATOR included, so they reach the scriptCode rules the
// published vectors never touch: legacy sighash skips OP_CODESEPARATOR when
// it serializes the scriptCode (Bitcoin Core's SerializeScriptCode), BIP143
// and BIP341 do not. scure hashes the whole script it is given; consensus
// hashes from the last OP_CODESEPARATOR executed before the signature check
// (psbt-consensus-scriptcode.test.mjs pins that). So the P2SH and P2WSH soups
// open with an OP_CHECKSIG, which checks a signature before any separator
// runs: the whole script is then a scriptCode consensus really hashes, and
// the two digests are comparable. (The tapleaf soups need no prefix: their
// PSBTs carry no leaf script, so the app can only verify the default
// no-separator position, which is what scure computes.) SIGHASH_SINGLE on a
// BIP341 input always has a matching output: BIP341 defines no digest
// otherwise (scure refuses to make one, and the app does not accuse what it
// cannot compute). Legacy and BIP143 SINGLE without a matching output are
// generated as they come; both have defined digests.
//
// Offline and deterministic: keys, scripts, and the Schnorr auxiliary bytes
// come from the seeded PRNG below, which exists only in this file.
//
// Run with `node --test test/sighash-differential-fuzz.test.mjs` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Transaction } from "@scure/btc-signer";
import { tapLeafHash } from "@scure/btc-signer/payment.js";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { wasmExports, withInput, withOutput } from "../src/js/entropylab-wasm.js";
import { fuzzEnv, mulberry32, replayLine, withReplay } from "./fuzz-kit.mjs";

// --- deterministic randomness ------------------------------------------------

const FUZZ_SEED = 0x5eed0341;
const DEFAULT_CASES = 64;
const SIGHASH_ENV = fuzzEnv("SIGHASH_FUZZ", { defaultSeed: FUZZ_SEED, defaultIterations: DEFAULT_CASES });
const ITERATIONS = SIGHASH_ENV.iterations;
const TEST_NAME = "rust-bitcoin (WASM) and @scure/btc-signer sign the same legacy, BIP143, and BIP341 digests";
let rand = mulberry32(SIGHASH_ENV.seed);
const rint = (n) => Math.floor(rand() * n);
const pick = (items) => items[rint(items.length)];
const randomBytes = (n) => Uint8Array.from({ length: n }, () => rint(256));
const randomKey = () => {
  for (;;) {
    const key = randomBytes(32);
    if (secp256k1.utils.isValidSecretKey(key)) return key;
  }
};
const randomAmount = () => BigInt(rint(2 ** 30)) * BigInt(1 + rint(2 ** 20)) % 2_100_000_000_000_001n;
const randomSequence = () => pick([0xffffffff, 0xfffffffe, 0xfffffffd, 0, rint(2 ** 32) >>> 0]);

// --- scripts -----------------------------------------------------------------

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const cat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const hash160 = (bytes) => ripemd160(sha256(bytes));
const p2pkh = (pub) => cat([0x76, 0xa9, 0x14], hash160(pub), [0x88, 0xac]);
const p2wpkh = (pub) => cat([0x00, 0x14], hash160(pub));
const p2sh = (redeem) => cat([0xa9, 0x14], hash160(redeem), [0x87]);
const p2wsh = (witnessScript) => cat([0x00, 0x20], sha256(witnessScript));
const p2tr = (xonly) => cat([0x51, 0x20], xonly);
const OP_CODESEPARATOR = 0xab;
// Pushes and a handful of opcodes, OP_CODESEPARATOR among them.
const randomScript = () => {
  const out = [];
  for (let n = 1 + rint(10); n > 0; n--) {
    const roll = rint(6);
    if (roll === 0) {
      const data = randomBytes(1 + rint(40));
      out.push(data.length, ...data);
    } else if (roll === 1) out.push(OP_CODESEPARATOR);
    else out.push(pick([0x00, 0x51, 0x52, 0x75, 0x76, 0x87, 0xa9, 0xac, 0xad, 0xae]));
  }
  return Uint8Array.from(out);
};
// A soup whose whole script is a scriptCode: see the header.
const signableScript = () => Uint8Array.of(0xac, ...randomScript());
const randomOutputScript = () => (rint(2) ? p2wpkh(secp256k1.getPublicKey(randomKey(), true)) : randomScript());

const FAMILIES = {
  legacy: { kinds: ["p2pkh", "p2sh"], types: [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] },
  bip143: { kinds: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2sh-p2wsh"], types: [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] },
  bip341: { kinds: ["key path", "script path"], types: [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] },
};
const SCURE_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };

// --- one case ----------------------------------------------------------------

// The signed input's prevout, the fields its PSBT input carries, and how to
// get scure's digest for it once the transaction is complete.
const spendFor = (kind, key) => {
  const pub = secp256k1.getPublicKey(key, true), amount = randomAmount();
  switch (kind) {
    case "p2pkh": {
      const script = p2pkh(pub);
      return { legacy: true, script, amount, fields: {}, digest: (tx, idx, type) => tx.preimageLegacy(idx, script, type) };
    }
    case "p2sh": {
      const redeem = signableScript();
      return { legacy: true, script: p2sh(redeem), amount, fields: { redeemScript: redeem }, digest: (tx, idx, type) => tx.preimageLegacy(idx, redeem, type) };
    }
    case "p2wpkh":
      return { script: p2wpkh(pub), amount, fields: {}, scriptCode: p2pkh(pub) };
    case "p2sh-p2wpkh":
      return { script: p2sh(p2wpkh(pub)), amount, fields: { redeemScript: p2wpkh(pub) }, scriptCode: p2pkh(pub) };
    case "p2wsh": {
      const witnessScript = signableScript();
      return { script: p2wsh(witnessScript), amount, fields: { witnessScript }, scriptCode: witnessScript };
    }
    case "p2sh-p2wsh": {
      const witnessScript = signableScript();
      return { script: p2sh(p2wsh(witnessScript)), amount, fields: { redeemScript: p2wsh(witnessScript), witnessScript }, scriptCode: witnessScript };
    }
    case "key path":
      return { taproot: true, script: p2tr(schnorr.getPublicKey(key)), amount, fields: {} };
    case "script path":
      return { taproot: true, leaf: randomScript(), script: p2tr(schnorr.getPublicKey(randomKey())), amount, fields: {} };
  }
  throw new Error(`unknown kind ${kind}`);
};

const buildCase = (index) => {
  const family = Object.keys(FAMILIES)[index % 3];
  const kind = pick(FAMILIES[family].kinds), type = pick(FAMILIES[family].types);
  const inputs = 1 + rint(4);
  let outputs = 1 + rint(4);
  const idx = rint(inputs);
  if (family === "bip341" && (type & 3) === 3 && idx >= outputs) outputs = idx + 1;
  const key = randomKey(), spend = spendFor(kind, key);
  const tx = new Transaction({ ...SCURE_OPTS, version: pick([1, 2, 3, rint(2 ** 31)]), lockTime: rint(2 ** 32) >>> 0 });
  const prevouts = [];
  for (let j = 0; j < inputs; j++) {
    const signed = j === idx;
    const script = signed ? spend.script : p2wpkh(secp256k1.getPublicKey(randomKey(), true));
    const amount = signed ? spend.amount : randomAmount();
    prevouts.push({ script, amount });
    if (signed && spend.legacy) {
      // A legacy claim comes from the full previous transaction.
      const vout = rint(3);
      const prev = new Transaction({ ...SCURE_OPTS, version: 2 });
      prev.addInput({ txid: randomBytes(32), index: rint(4), sequence: 0xffffffff });
      for (let k = 0; k <= vout; k++) prev.addOutput(k === vout ? { script, amount } : { script: randomOutputScript(), amount: randomAmount() });
      tx.addInput({ txid: prev.id, index: vout, sequence: randomSequence(), nonWitnessUtxo: prev.toBytes(true, false), ...spend.fields });
    } else {
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence: randomSequence(), witnessUtxo: { script, amount }, ...(signed ? spend.fields : {}) });
    }
  }
  for (let k = 0; k < outputs; k++) tx.addOutput({ script: randomOutputScript(), amount: randomAmount() });

  const scripts = prevouts.map((prevout) => prevout.script), amounts = prevouts.map((prevout) => prevout.amount);
  const digestFor = (sighash) =>
    spend.digest ? spend.digest(tx, idx, sighash)
      : spend.taproot ? tx.preimageWitnessV1(idx, scripts, sighash, amounts, -1, spend.leaf, spend.leaf ? 0xc0 : undefined)
        : tx.preimageWitnessV0(idx, spend.scriptCode, sighash, spend.amount);
  const digest = digestFor(type);
  const aux = randomBytes(32);
  // Relabel with a type whose digest must differ: ALL <-> NONE, and DEFAULT
  // as ALL (the sighash byte is inside the BIP341 message).
  const other = type === 0x01 ? 0x02 : 0x01;
  let sign, signature;
  if (spend.taproot) {
    signature = schnorr.sign(digest, key, aux);
    const withType = (sighash) => (sighash === 0x00 ? signature : cat(signature, [sighash]));
    const xonly = schnorr.getPublicKey(key);
    sign = (sighash) => (spend.leaf ? { tapScriptSig: [[{ pubKey: xonly, leafHash: tapLeafHash(spend.leaf, 0xc0) }, withType(sighash)]] } : { tapKeySig: withType(sighash) });
  } else {
    signature = secp256k1.sign(digest, key, { prehash: false, format: "der" });
    sign = (sighash) => ({ partialSig: [[secp256k1.getPublicKey(key, true), cat(signature, [sighash])]] });
  }
  const psbtWith = (sighash) => {
    const copy = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
    copy.updateInput(idx, sign(sighash), true);
    return copy.toPSBT();
  };
  return {
    label: `case ${index}: ${family} ${kind}, sighash 0x${type.toString(16).padStart(2, "0")}, input ${idx} of ${inputs}, ${outputs} output${outputs === 1 ? "" : "s"}`,
    family, tx, idx, spend, digest, outputs, type,
    signed: psbtWith(type),
    relabelled: psbtWith(other),
    otherType: other,
  };
};

// The app's verdict on the signed input: its signature problems, if any.
const signatureProblems = (psbt, idx) => {
  const doc = psbtInspectDoc(psbt);
  assert.equal(doc.rustBitcoinError, null, `rust-bitcoin rejected the generated PSBT: ${doc.rustBitcoinError}`);
  return doc.problems.filter((problem) => problem.scope === `input ${idx}` && /sig/.test(problem.code));
};

const elSighashSegwitV0All = (raw, idx, scriptCode, amount) =>
  withInput(raw, (p) => withInput(scriptCode, (sc) => withOutput(32, (o) => wasmExports().el_sighash_segwit_v0(p, raw.length, idx, sc, scriptCode.length, amount, o))));

test(TEST_NAME, () => {
  let ran = 0;
  const seen = new Set();
  try {
    for (let i = 0; i < ITERATIONS; i++) {
      const c = buildCase(i);
      seen.add(c.family);
      // A SIGHASH_SINGLE signature whose input has no corresponding output is
      // consensus-valid (legacy: the constant-one digest; BIP-143: a zero
      // hashOutputs) and must still verify — but it commits to no output, so
      // the inspector names it with a dedicated warning (audit C3-8). Expect
      // exactly that warning on those cases, and it nowhere else.
      const singleNoOutput = signatureProblems(c.signed, c.idx).filter((problem) => problem.code === "sighash_single_no_output");
      if (c.family !== "bip341" && (c.type & 0x1f) === 0x03 && c.idx >= c.outputs) {
        assert.equal(singleNoOutput.length, 1, `${c.label}: SIGHASH_SINGLE with no corresponding output was not named`);
      } else {
        assert.equal(singleNoOutput.length, 0, `${c.label}: the SIGHASH_SINGLE warning fired on a digestible signature`);
      }
      const verdict = signatureProblems(c.signed, c.idx).filter((problem) => problem.code !== "sighash_single_no_output");
      assert.deepEqual(verdict, [],
        `${c.label}: the app does not verify a signature over scure's digest ${hex(c.digest)}\n  ${verdict.map((problem) => `${problem.code}: ${problem.message}`).join("\n  ")}`);
      const relabelled = signatureProblems(c.relabelled, c.idx).filter((problem) => /_sig_invalid$/.test(problem.code));
      assert.ok(relabelled.length > 0, `${c.label}: relabelled as 0x${c.otherType.toString(16).padStart(2, "0")}, the signature still verifies, so the app did not check this input`);
      if (c.family === "bip143") {
        const wasm = elSighashSegwitV0All(c.tx.unsignedTx, c.idx, c.spend.scriptCode, c.spend.amount);
        const scure = c.tx.preimageWitnessV0(c.idx, c.spend.scriptCode, 0x01, c.spend.amount);
        assert.equal(hex(wasm), hex(scure), `${c.label}: el_sighash_segwit_v0 (SIGHASH_ALL) differs\n  entropylab-wasm:   ${hex(wasm)}\n  @scure/btc-signer: ${hex(scure)}`);
      }
      ran += 1;
    }
    assert.deepEqual([...seen].sort(), ["bip143", "bip341", "legacy"], "every sighash algorithm was exercised");
    assert.equal(ran, ITERATIONS, "every case ran to the end");
  } catch (error) {
    throw withReplay(error, replayLine("SIGHASH_FUZZ", SIGHASH_ENV.seed, ITERATIONS, TEST_NAME, "test/sighash-differential-fuzz.test.mjs"));
  }
});
