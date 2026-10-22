// PSBT finalization differential against @scure/btc-signer (pinned, the
// oracle: its finalize()/extract() plus BIP174/BIP371 semantics — never the
// app compared to itself). Each case builds a PSBT with @scure covering
// p2pkh, p2wpkh, p2sh-p2wpkh, p2wsh 2-of-3, p2tr key path, and p2tr script
// path with 2 leaves; 1–4 inputs, random amounts/sequences/locktime, mixed
// sighash types; every input is signed with @noble/curves.
//
// App surface: src/js/psbt-wasm.js exports only psbtInspectDoc and
// psbtBuildBytes — there is no finalize or extract entry point, and per the
// ledger's rule ("use only entry points already exported; skip any case
// whose needed entry point is not exported") the app side of every case is
// the full round-trip psbtBuildBytes(psbtInspectDoc(finalizedPsbt)): the
// app must accept the finalized PSBT (rust-bitcoin parse verdict null),
// re-serialize it without losing or corrupting the final scripts, and
// leave no stale signature fields (PSBT_IN_PARTIAL_SIG, PSBT_IN_TAP_KEY_SIG,
// PSBT_IN_TAP_SCRIPT_SIG) in any finalized input map. Extraction itself is
// @scure's, applied identically to the original and the app's bytes, so
// any difference is the app's re-serialization. The incompleteness
// invariant (remove one signature → refuse) is asserted on the @scure
// side, and honestly on the app side: the app's inspector deliberately
// accepts partially signed PSBTs (they are the cosigner workflow's normal
// input) and no refusal entry point is exported, so what is asserted is
// what the app does — it inspects the one-signature-short PSBT without a
// rust-bitcoin error, and its re-serialization is still not finalizable:
// the app must not complete it. @scure/btc-signer exposes no
// public raw-transaction parser, so "re-parses strictly" is enforced as
// Transaction.fromPSBT with its default (strict) flags on the app's bytes.
// The fee invariant is pinned field by field against the generator's own
// amounts: each input's amount where the inspect document decodes that
// input's UTXO record (PSBT_IN_WITNESS_UTXO's decoded.value, or
// PSBT_IN_NON_WITNESS_UTXO's decoded.prevout.value), doc.totalIn, the
// decoded output values, and doc.fee.sats — so two inputs with swapped
// amounts, or a fee read from the wrong field, fail the run.
//
// Every shape must run: @scure/btc-signer builds and finalizes all six
// today, so any refusal fails the run and names the shape. (Round 4: a
// skip allowance let a generator bug or a @scure upgrade that broke one
// shape void that kind's coverage while the suite stayed green.) A refusal
// recognized by message is reported as the oracle refusing that shape;
// anything else buildCase throws fails as itself. The p2tr script path
// is built with @scure's own p2tr payment (internal key + a two-leaf tree
// in its TaprootScriptTree shape: { script, leafVersion } leaves, 0xc0
// being BIP341's base tapscript leaf version), so the tweaked output key,
// the merkle root and the leaf control blocks are the oracle's own
// construction.
//
// Offline and deterministic: keys, amounts and Schnorr auxiliary bytes come
// from the seeded PRNG below, which exists only in this file.
//
// Run with `node --test test/psbt-finalization-differential.test.mjs`,
// `npm test`, or test:ci.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Transaction } from "@scure/btc-signer";
import { p2tr as scureP2TR, tapLeafHash } from "@scure/btc-signer/payment.js";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { psbtInspectDoc, psbtBuildBytes } from "../src/js/psbt-wasm.js";

// --- deterministic randomness ------------------------------------------------

const FUZZ_SEED = 0x5eed0501;
const CASES = 48;
const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};
const rand = mulberry32(FUZZ_SEED);
const rint = (n) => Math.floor(rand() * n);
const pick = (items) => items[rint(items.length)];
const randomBytes = (n) => Uint8Array.from({ length: n }, () => rint(256));
const randomKey = () => {
  for (;;) {
    const key = randomBytes(32);
    if (secp256k1.utils.isValidSecretKey(key)) return key;
  }
};
const randomAmount = () => BigInt(1 + rint(10 ** 8)) * 10000n;
const randomSequence = () => pick([0xffffffff, 0xfffffffe, 0xfffffffd, rint(2 ** 32) >>> 0]);

// --- scripts and hashes ------------------------------------------------------

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const cat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const hash160 = (bytes) => ripemd160(sha256(bytes));
const p2pkh = (pub) => cat([0x76, 0xa9, 0x14], hash160(pub), [0x88, 0xac]);
const p2wpkh = (pub) => cat([0x00, 0x14], hash160(pub));
const p2sh = (redeem) => cat([0xa9, 0x14], hash160(redeem), [0x87]);
const p2wsh = (witnessScript) => cat([0x00, 0x20], sha256(witnessScript));
const p2tr = (xonly) => cat([0x51, 0x20], xonly);
// The txid hashes the serialization WITHOUT the witness (BIP141); hashing
// extract()'s full bytes would give the wtxid for every segwit input.
// @scure's Transaction.id is sha256d(toBytes(true)) reversed: scriptSig in,
// witness out.
const txidOf = (raw) => Transaction.fromRaw(raw, SCURE_OPTS).id;

// --- PSBT framing: signature fields in the input maps ------------------------

const compactSize = (bytes, at) => {
  const first = bytes[at];
  if (first < 0xfd) return [first, 1];
  if (first === 0xfd) return [bytes[at + 1] | (bytes[at + 2] << 8), 3];
  if (first === 0xfe) return [(bytes[at + 1] | (bytes[at + 2] << 8) | (bytes[at + 3] << 16) | (bytes[at + 4] << 24)) >>> 0, 5];
  throw new Error("compact size over 32 bits in a generated PSBT");
};

// Walks the global map then the per-input maps (framing only; the decoders
// under test do the parsing) and returns, per input, the entries of its
// map as { type, key, value } (key is the whole key, type byte included).
// PSBT_IN_PARTIAL_SIG is 0x02 (BIP174); PSBT_IN_TAP_KEY_SIG is 0x13 and
// PSBT_IN_TAP_SCRIPT_SIG 0x14 (BIP371). BIP174's 0x0c and 0x0d are the
// PSBT_IN_HASH160 and PSBT_IN_HASH256 preimage fields, not signatures.
const inputMapEntries = (psbt, inputCount) => {
  assert.deepEqual([...psbt.subarray(0, 5)], [0x70, 0x73, 0x62, 0x74, 0xff], "PSBT magic");
  let at = 5;
  const maps = [];
  while (maps.length < 1 + inputCount) {
    const entries = [];
    for (;;) {
      const [keyLength, keySize] = compactSize(psbt, at);
      at += keySize;
      if (keyLength === 0) break;
      const key = psbt.subarray(at, at + keyLength);
      at += keyLength;
      const [valueLength, valueSize] = compactSize(psbt, at);
      at += valueSize;
      entries.push({ type: key[0], key, value: psbt.subarray(at, at + valueLength) });
      at += valueLength;
    }
    maps.push(entries);
  }
  return maps.slice(1);
};
const isSigField = ({ type }) => type === 0x02 || type === 0x13 || type === 0x14;
const stalePerInput = (psbt, inputCount) => inputMapEntries(psbt, inputCount).map((entries) => entries.filter(isSigField).map(({ type }) => type));
// Every signature-class record of each input map, key and value, as sorted
// hex: what a cosigner has already contributed.
const sigRecordsPerInput = (psbt, inputCount) =>
  inputMapEntries(psbt, inputCount).map((entries) => entries.filter(isSigField).map(({ key, value }) => `${hex(key)}:${hex(value)}`).sort());

// --- case generation ---------------------------------------------------------

const KINDS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2wsh 2-of-3", "p2tr key path", "p2tr script path"];
const SIGHASH_TYPES = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
const SCURE_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };
// The only errors that may skip a case: @scure/btc-signer refusing to
// build or finalize a shape (a documented limitation of the oracle, not a
// bug in this generator). Refusals are recognized by message fragment, so
// a generator bug — or a @scure upgrade that rewords its errors — fails
// the run instead of silently skipping coverage.
// ("not supported" was dropped in round 2: no case needs it, and it is broad
// enough to hide a generator bug or a @scure change as a silent skip.)
const SCURE_REFUSALS = ["Unknown input", "Unknown output", "Cannot finalize", "Cannot extract"];

const buildCase = (index) => {
  const kind = KINDS[index % KINDS.length];
  const inputs = 1 + rint(4);
  const outputs = inputs + 1 + rint(2); // every input index has a matching output, so SIGHASH_SINGLE is always defined
  const tx = new Transaction({ ...SCURE_OPTS, version: 2, lockTime: rint(2 ** 32) >>> 0 });
  const prevouts = [];
  const signers = [];
  for (let j = 0; j < inputs; j++) {
    const sequence = randomSequence();
    const amount = randomAmount();
    if (kind === "p2pkh") {
      const key = randomKey(), pub = secp256k1.getPublicKey(key, true), script = p2pkh(pub);
      prevouts.push({ script, amount });
      signers.push({ key, pub, script, type: pick(SIGHASH_TYPES) });
      // A legacy claim comes from the full previous transaction.
      const vout = rint(3);
      const prev = new Transaction({ ...SCURE_OPTS, version: 2 });
      prev.addInput({ txid: randomBytes(32), index: rint(4), sequence: 0xffffffff });
      for (let k = 0; k <= vout; k++) prev.addOutput(k === vout ? { script, amount } : { script: p2wpkh(secp256k1.getPublicKey(randomKey(), true)), amount: randomAmount() });
      tx.addInput({ txid: prev.id, index: vout, sequence, nonWitnessUtxo: prev.toBytes(true, false) });
    } else if (kind === "p2wpkh") {
      const key = randomKey(), pub = secp256k1.getPublicKey(key, true), script = p2wpkh(pub);
      prevouts.push({ script, amount });
      signers.push({ key, pub, type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount } });
    } else if (kind === "p2sh-p2wpkh") {
      const key = randomKey(), pub = secp256k1.getPublicKey(key, true), redeem = p2wpkh(pub), script = p2sh(redeem);
      prevouts.push({ script, amount });
      signers.push({ key, pub, type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount }, redeemScript: redeem });
    } else if (kind === "p2wsh 2-of-3") {
      const keys = [randomKey(), randomKey(), randomKey()];
      const witnessScript = cat([0x52], ...keys.map((key) => cat([0x21], secp256k1.getPublicKey(key, true))), [0x53, 0xae]);
      const script = p2wsh(witnessScript);
      prevouts.push({ script, amount });
      signers.push({ keys, witnessScript, type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount }, witnessScript });
    } else if (kind === "p2tr key path") {
      const key = randomKey(), xonly = schnorr.getPublicKey(key), script = p2tr(xonly);
      prevouts.push({ script, amount });
      // SIGHASH_DEFAULT (0x00, no sighash byte per BIP371) is in the mix.
      signers.push({ key, xonly, aux: randomBytes(32), type: pick([0x00, ...SIGHASH_TYPES]) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount } });
    } else {
      // p2tr script path with 2 leaves: @scure's own p2tr payment derives
      // the tweaked output key, the merkle root and the leaf control
      // blocks, so the app is diffed against the oracle's construction.
      const internalKey = randomKey(), internalPub = schnorr.getPublicKey(internalKey);
      const leafKey = randomKey(), leafPub = schnorr.getPublicKey(leafKey);
      const leaf = cat([0x20], leafPub, [0xac]);
      const otherLeaf = cat([0x20], schnorr.getPublicKey(randomKey()), [0xac]);
      const payment = scureP2TR(internalPub, [{ script: leaf, leafVersion: 0xc0 }, { script: otherLeaf, leafVersion: 0xc0 }]);
      const script = payment.script;
      prevouts.push({ script, amount });
      signers.push({ leafKey, leafPub, leaf, aux: randomBytes(32), type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount }, tapInternalKey: payment.tapInternalKey, tapMerkleRoot: payment.tapMerkleRoot, tapLeafScript: payment.tapLeafScript });
    }
  }
  const scripts = prevouts.map((prevout) => prevout.script);
  const amounts = prevouts.map((prevout) => prevout.amount);
  const sumIn = amounts.reduce((a, b) => a + b, 0n);
  const fee = 600n + sumIn / 8n;
  let remaining = sumIn - fee;
  const outAmounts = [];
  for (let k = 0; k < outputs; k++) {
    const share = remaining / BigInt(outputs - k);
    const out = k === outputs - 1 ? remaining : 546n + BigInt(rint(Number(share / 3n)));
    outAmounts.push(out);
    remaining -= out;
  }
  // Kept per output so the check below can pin each decoded output, not only
  // their sum (same draws, same order: the fuzz cases are unchanged).
  const outScripts = [];
  for (let k = 0; k < outputs; k++) {
    outScripts.push(p2wpkh(secp256k1.getPublicKey(randomKey(), true)));
    tx.addOutput({ script: outScripts[k], amount: outAmounts[k] });
  }
  const sumOut = outAmounts.reduce((a, b) => a + b, 0n);

  // The signature payload for input j. `degraded` signs only one of the two
  // required multisig signatures, so the p2wsh cases drop exactly one
  // signature rather than a whole input's worth.
  const sigsFor = (j, degraded) => {
    const s = signers[j];
    if (kind === "p2pkh") {
      const sig = secp256k1.sign(tx.preimageLegacy(j, s.script, s.type), s.key, { prehash: false, format: "der" });
      return { partialSig: [[s.pub, cat(sig, [s.type])]] };
    }
    if (kind === "p2wpkh" || kind === "p2sh-p2wpkh") {
      const sig = secp256k1.sign(tx.preimageWitnessV0(j, p2pkh(s.pub), s.type, amounts[j]), s.key, { prehash: false, format: "der" });
      return { partialSig: [[s.pub, cat(sig, [s.type])]] };
    }
    if (kind === "p2wsh 2-of-3") {
      const digest = tx.preimageWitnessV0(j, s.witnessScript, s.type, amounts[j]);
      const partialSig = s.keys.slice(0, degraded ? 1 : 2).map((key) => {
        const sig = secp256k1.sign(digest, key, { prehash: false, format: "der" });
        return [secp256k1.getPublicKey(key, true), cat(sig, [s.type])];
      });
      return { partialSig };
    }
    if (kind === "p2tr key path") {
      // Key path: no leaf hash, only the BIP341 common signature message.
      const sig = schnorr.sign(tx.preimageWitnessV1(j, scripts, s.type, amounts), s.key, s.aux);
      return { tapKeySig: s.type === 0x00 ? sig : cat(sig, [s.type]) };
    }
    // Script path: BIP342 extends the preimage with the tapleaf hash (and
    // the code-separator position, absent here), so the leaf hash — the
    // same value that keys the tapScriptSig map — is passed to @scure.
    const leafHash = tapLeafHash(s.leaf, 0xc0);
    const sig = schnorr.sign(tx.preimageWitnessV1(j, scripts, s.type, amounts, leafHash), s.leafKey, s.aux);
    return { tapScriptSig: [[{ pubKey: s.leafPub, leafHash }, cat(sig, [s.type])]] };
  };
  const signedPsbt = (() => {
    const copy = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
    for (let j = 0; j < inputs; j++) copy.updateInput(j, sigsFor(j, false), true);
    return copy.toPSBT();
  })();
  // Remove one signature: a whole input's worth, or — for the 2-of-3 — one
  // of the two required signatures, so the PSBT is exactly one signature
  // short rather than missing an input's material outright.
  const dropIdx = rint(inputs);
  const incompletePsbt = (() => {
    const copy = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
    for (let j = 0; j < inputs; j++) {
      if (j === dropIdx) {
        if (kind === "p2wsh 2-of-3") copy.updateInput(j, sigsFor(j, true), true); // one signature short
        continue;
      }
      copy.updateInput(j, sigsFor(j, false), true);
    }
    return copy.toPSBT();
  })();
  const fin = Transaction.fromPSBT(signedPsbt, SCURE_OPTS);
  fin.finalize();
  const raw = fin.extract();
  return {
    label: `case ${index}: ${kind}, ${inputs} input${inputs === 1 ? "" : "s"}, ${outputs} outputs`,
    kind, inputs, finalizedPsbt: fin.toPSBT(), raw, txid: txidOf(raw),
    fee: sumIn - sumOut, sumIn, sumOut, amounts, outAmounts, outScripts, incompletePsbt, dropIdx,
  };
};

// --- the app's reported amounts ----------------------------------------------

// The amount the inspect document decodes for input j, from that input's
// own UTXO record: PSBT_IN_WITNESS_UTXO carries it as decoded.value, and
// PSBT_IN_NON_WITNESS_UTXO as decoded.prevout.value (the spent output of
// the embedded previous transaction). Both are satoshi strings. When an
// input carries both records, they must agree.
const docInputAmount = (doc, j) => {
  const entries = doc.inputs[j] ?? [];
  const witness = entries.find((entry) => entry.name === "PSBT_IN_WITNESS_UTXO");
  const nonWitness = entries.find((entry) => entry.name === "PSBT_IN_NON_WITNESS_UTXO");
  const readings = [witness?.decoded?.value, nonWitness?.decoded?.prevout?.value].filter((value) => value !== undefined).map(BigInt);
  assert.ok(readings.length > 0, `input ${j} has no decoded UTXO amount in the inspect document`);
  assert.ok(readings.every((value) => value === readings[0]), `input ${j}'s witness and non-witness UTXO amounts disagree: ${readings.join(" vs ")}`);
  return readings[0];
};

// --- the run -----------------------------------------------------------------

test(`the app round-trips @scure-finalized PSBTs byte-identically, without stale signature fields (seed 0x${FUZZ_SEED.toString(16)}, ${CASES} cases)`, () => {
  const unsupported = new Set();
  let ran = 0;
  let skipped = 0;
  let scriptPathRan = 0;
  let survivalChecked = 0;
  for (let index = 0; index < CASES; index++) {
    const kind = KINDS[index % KINDS.length];
    if (unsupported.has(kind)) {
      skipped += 1;
      continue;
    }
    let c;
    try {
      c = buildCase(index);
    } catch (error) {
      // Only a documented @scure/btc-signer limitation may skip a case,
      // and only when the refusal is recognized by message: anything else
      // — a bug in this generator, or a @scure upgrade that rewords its
      // errors — fails the run here instead of silently skipping
      // coverage. Anything the app side throws below is a test failure,
      // never a skip.
      if (!(error instanceof Error) || !SCURE_REFUSALS.some((fragment) => String(error.message).includes(fragment))) throw error;
      unsupported.add(kind);
      skipped += 1;
      continue;
    }
    if (kind === "p2tr script path") scriptPathRan += 1;
    const where = c.label;

    // (1) The app's round-tripped PSBT must extract to the byte-identical
    // transaction (and txid) as @scure's own finalize().extract().
    const doc = psbtInspectDoc(c.finalizedPsbt);
    assert.equal(doc.rustBitcoinError, null, `${where}: rust-bitcoin rejected the finalized PSBT: ${doc.rustBitcoinError}`);
    const appBytes = psbtBuildBytes(doc);
    // Every map and every field survives, not only what extraction reads: a
    // rebuild that dropped PSBT_IN_TAP_LEAF_SCRIPT or a BIP32 derivation would
    // still extract the same transaction. (So the amounts read from `doc`
    // below are also the amounts of the app's own bytes.)
    assert.deepEqual(appBytes, c.finalizedPsbt, `${where}: the app's round-trip changed the finalized PSBT's bytes`);
    const rawApp = Transaction.fromPSBT(appBytes, SCURE_OPTS).extract();
    assert.deepEqual(rawApp, c.raw, `${where}: the app's round-trip changed the extracted transaction (full serialization, witness included)`);
    assert.equal(txidOf(rawApp), c.txid, `${where}: the app's round-trip changed the txid (witness-stripped serialization)`);

    // (2) Strict re-parse: @scure exposes no raw-transaction parser, so
    // strictness is fromPSBT with its default (strict) flags.
    Transaction.fromPSBT(appBytes);

    // (3) Fee = sum(inputs) − sum(outputs); the generator's amounts are the
    // independent source. Each input's amount is read from that input's own
    // UTXO record, so swapped amounts fail; each decoded output is pinned to
    // the generator's value and script by index, so swapped or misdecoded
    // outputs fail even when the sum still matches; then the document's total
    // input, its output sum and its fee must all match exactly.
    assert.ok(c.fee > 0n, `${where}: generated a non-paying transaction`);
    assert.equal(doc.inputs.length, c.inputs, `${where}: the inspect document has ${doc.inputs.length} input maps`);
    for (let j = 0; j < c.inputs; j++) {
      assert.equal(docInputAmount(doc, j), c.amounts[j], `${where}: the app's decoded amount for input ${j} is not the generator's ${c.amounts[j]} sats`);
    }
    assert.equal(BigInt(doc.totalIn), c.sumIn, `${where}: the app's totalIn is not sum(inputs)`);
    assert.equal(doc.tx.outputs.length, c.outAmounts.length, `${where}: the inspect document has ${doc.tx.outputs.length} outputs`);
    for (let k = 0; k < c.outAmounts.length; k++) {
      assert.equal(BigInt(doc.tx.outputs[k].value), c.outAmounts[k], `${where}: the app's decoded value for output ${k} is not the generator's ${c.outAmounts[k]} sats`);
      assert.equal(doc.tx.outputs[k].scriptPubKey, hex(c.outScripts[k]), `${where}: the app's decoded script for output ${k} is not the generator's`);
    }
    const docSumOut = doc.tx.outputs.reduce((total, output) => total + BigInt(output.value), 0n);
    assert.equal(docSumOut, c.sumOut, `${where}: the app's decoded outputs do not sum to sum(outputs)`);
    assert.equal(doc.fee?.known, true, `${where}: the app reports the fee as unknown`);
    assert.equal(BigInt(doc.fee.sats), c.fee, `${where}: the app's fee is not sum(inputs) − sum(outputs) = ${c.fee} sats`);

    // (4) No stale signature fields may remain in any finalized input map:
    // BIP174's finalizer strips PSBT_IN_PARTIAL_SIG (0x02) and BIP371's
    // PSBT_IN_TAP_KEY_SIG (0x13) / PSBT_IN_TAP_SCRIPT_SIG (0x14) once the
    // final scripts are in. Absence is asserted directly, on BOTH sides —
    // equality with the oracle alone would pass if both retained the same
    // stale field — and the per-input field sets must still match the
    // oracle's as a second check.
    const noStaleFields = Array.from({ length: c.inputs }, () => []);
    const scureStale = stalePerInput(c.finalizedPsbt, c.inputs);
    assert.deepEqual(scureStale, noStaleFields, `${where}: @scure's finalized input maps retain stale signature fields`);
    const appStale = stalePerInput(appBytes, c.inputs);
    assert.deepEqual(appStale, noStaleFields, `${where}: the app's round-trip retained stale signature fields`);
    assert.deepEqual(appStale, scureStale, `${where}: the app's round-trip changed the signature fields of the finalized input maps`);

    // (5) Removing one signature must make @scure refuse with a typed Error
    // (never a raw throw or a WebAssembly.RuntimeError); because finalize or
    // extract throws, no transaction — and no witness bytes — are emitted at
    // all. The app has no refusal path to assert — psbtInspectDoc and
    // psbtBuildBytes accept partially signed PSBTs by design (the cosigner
    // workflow's normal input) and no finalize or extract entry point is
    // exported — so the honest app-side assertion is what the app actually
    // does with the incomplete PSBT: it must inspect it without a
    // rust-bitcoin error, its re-serialization must keep every signature the
    // cosigners already contributed, byte for byte, and it must still be one
    // signature short — the app must not complete it. Each PSBT is parsed
    // OUTSIDE the throws block, so a malformed PSBT fails the run instead of
    // passing as "refused".
    const scureIncomplete = Transaction.fromPSBT(c.incompletePsbt, SCURE_OPTS);
    assert.throws(
      () => {
        scureIncomplete.finalize();
        scureIncomplete.extract();
      },
      (error) => error instanceof Error && !(error instanceof WebAssembly.RuntimeError),
      `${where}: @scure finalized a PSBT whose input ${c.dropIdx} is one signature short`);
    const incompleteDoc = psbtInspectDoc(c.incompletePsbt);
    assert.equal(incompleteDoc.rustBitcoinError, null, `${where}: the app refused to inspect a partially signed PSBT (the cosigner workflow's normal input)`);
    const incompleteBytes = psbtBuildBytes(incompleteDoc);
    assert.deepEqual(incompleteBytes, c.incompletePsbt, `${where}: the app's round-trip changed the one-signature-short PSBT's bytes`);
    // (A one-input PSBT whose only signature was dropped has none left; the
    // run counts the cases where there was something to keep.)
    const contributed = sigRecordsPerInput(c.incompletePsbt, c.inputs);
    if (contributed.some((records) => records.length > 0)) survivalChecked += 1;
    assert.deepEqual(sigRecordsPerInput(incompleteBytes, c.inputs), contributed, `${where}: the app's round-trip changed the signatures a cosigner already contributed`);
    const appIncomplete = Transaction.fromPSBT(incompleteBytes, SCURE_OPTS);
    assert.throws(
      () => {
        appIncomplete.finalize();
        appIncomplete.extract();
      },
      (error) => error instanceof Error && !(error instanceof WebAssembly.RuntimeError),
      `${where}: the app's round-trip completed a PSBT whose input ${c.dropIdx} is one signature short`);

    // (6) The app's round-trip is stable: a second app round-trip must
    // reproduce the same PSBT bytes and extract to the same transaction.
    // The PSBT is already final, so it is extracted as it is, with no catch:
    // @scure 2.4.0's finalize() strips partialSig, and a second finalize()
    // of a non-Taproot input always throws "Not enough partial sign", which
    // would test @scure rather than the app.
    const doc2 = psbtInspectDoc(appBytes);
    const appBytes2 = psbtBuildBytes(doc2);
    assert.deepEqual(appBytes2, appBytes, `${where}: a second app round-trip changed the PSBT bytes`);
    assert.deepEqual(Transaction.fromPSBT(appBytes2, SCURE_OPTS).extract(), c.raw, `${where}: a second app round-trip changed the extracted transaction`);

    ran += 1;
  }
  assert.ok(ran >= CASES / 2, `only ${ran} of ${CASES} cases ran; too many shapes were skipped: ${[...unsupported].join(", ") || "none"}`);
  assert.equal(unsupported.size, 0, `@scure/btc-signer refused a shape, so its coverage would be skipped (${skipped} cases): ${[...unsupported].join(", ")}`);
  for (const kind of ["p2tr key path", "p2tr script path"]) {
    assert.ok(!unsupported.has(kind), `@scure/btc-signer refused the taproot shape "${kind}"; its BIP341/BIP371 coverage would be skipped`);
  }
  assert.equal(scriptPathRan, CASES / KINDS.length, "a p2tr script-path case was skipped: every script-path case must actually be built");
  assert.ok(survivalChecked >= CASES / 4, `only ${survivalChecked} cases left a contributed signature to check in the one-signature-short PSBT`);
});
