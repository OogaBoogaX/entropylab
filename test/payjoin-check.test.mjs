// BIP-78 sender checklist over two psbtInspectDoc results (issue #446).
// Fixtures are built byte for byte and run through the real psbtInspectDoc;
// every expected value below is worked from the BIP-78 rules, never from the
// module under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { checkPayjoinProposal } from "../src/js/payjoin-check.js";

// --- Fixture helpers --------------------------------------------------------

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const le32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const le64 = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const varint = (n) => {
  assert.ok(n < 0xfd, "fixtures stay below the compact-size marker");
  return Uint8Array.of(n);
};
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const sha256d = (bytes) => {
  const first = createHash("sha256").update(bytes).digest();
  return createHash("sha256").update(first).digest();
};

const PAYMENT = 0xaa, SENDER_SPK = 0xbb, CHANGE = 0xcc, RECEIVER_SPK = 0xee;
const spk = (byte) => Uint8Array.of(0x00, 0x14, ...Array(20).fill(byte));
const p2trSpk = (byte) => Uint8Array.of(0x51, 0x20, ...Array(32).fill(byte));
const p2shSpk = (byte) => Uint8Array.of(0xa9, 0x14, ...Array(20).fill(byte), 0x87);
const p2shP2wpkhScriptSig = (byte) => Uint8Array.of(0x16, 0x00, 0x14, ...Array(20).fill(byte));

const txinRaw = (txid, vout, sequence = 0xfffffffd) =>
  concat([txid, le32(vout), varint(0), le32(sequence)]);
const txin = (txidByte, vout, sequence = 0xfffffffd) =>
  txinRaw(Uint8Array.from(Array(32).fill(txidByte)), vout, sequence);
const txout = (sats, script) => concat([le64(sats), varint(script.length), script]);
const tx = (inputs, outputs, { version = 2, locktime = 0 } = {}) =>
  concat([le32(version), varint(inputs.length), ...inputs, varint(outputs.length), ...outputs, le32(locktime)]);

const pair = (key, value) => concat([varint(key.length), key, varint(value.length), value]);
const witnessUtxo = (sats, script) => pair(Uint8Array.of(0x01), concat([le64(sats), varint(script.length), script]));
const finalWitness = (stack = Uint8Array.of(0x01, 0x00)) => pair(Uint8Array.of(0x08), stack);
const finalScriptSig = (script = Uint8Array.of(0x00)) => pair(Uint8Array.of(0x07), script);
const keypath = (fingerprint = [1, 2, 3, 4]) => {
  const key = concat([Uint8Array.of(0x06), Uint8Array.from(Array(33).fill(0x02))]);
  const value = concat([Uint8Array.from(fingerprint), le32(0)]);
  return pair(key, value);
};
const tapKeypath = (fingerprint = [1, 2, 3, 4]) => {
  const key = concat([Uint8Array.of(0x16), Uint8Array.from(Array(32).fill(0x04))]);
  const value = concat([Uint8Array.of(0x00), Uint8Array.from(fingerprint), le32(0)]);
  return pair(key, value);
};
const partialSig = () => {
  const key = concat([Uint8Array.of(0x02), Uint8Array.from(Array(33).fill(0x03))]);
  const value = Uint8Array.from(Array(71).fill(0x30));
  return pair(key, value);
};
const tapKeySig = () => pair(Uint8Array.of(0x13), Uint8Array.from(Array(64).fill(0x01)));
const tapScriptSig = () => {
  const key = concat([Uint8Array.of(0x14), Uint8Array.from(Array(32).fill(0x05)), Uint8Array.from(Array(32).fill(0x06))]);
  const value = Uint8Array.from(Array(64).fill(0x02));
  return pair(key, value);
};
const outputKeypath = (fingerprint = [1, 2, 3, 4]) => {
  const key = concat([Uint8Array.of(0x02), Uint8Array.from(Array(33).fill(0x02))]);
  const value = concat([Uint8Array.from(fingerprint), le32(0)]);
  return pair(key, value);
};
const outputTapKeypath = (fingerprint = [1, 2, 3, 4]) => {
  const key = concat([Uint8Array.of(0x07), Uint8Array.from(Array(32).fill(0x04))]);
  const value = concat([Uint8Array.of(0x00), Uint8Array.from(fingerprint), le32(0)]);
  return pair(key, value);
};

const prevTx = (sats, script, vout = 0) => {
  const outputs = [];
  for (let i = 0; i < vout; i++) outputs.push(txout(0, spk(0x00)));
  outputs.push(txout(sats, script));
  const bytes = tx([txin(0x99, 0)], outputs);
  return { bytes, txid: new Uint8Array(sha256d(bytes)) };
};

const psbt = (txBytes, inputMaps, outputMaps) =>
  concat([
    Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]),
    pair(Uint8Array.of(0x00), txBytes),
    Uint8Array.of(0x00),
    ...inputMaps.map((map) => concat([...map, Uint8Array.of(0x00)])),
    ...outputMaps.map((map) => concat([...map, Uint8Array.of(0x00)])),
  ]);

// Original: one sender input (100k) paying 50k to PAYMENT and 40k change.
const originalBytes = psbt(
  tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
  [[witnessUtxo(100_000, spk(SENDER_SPK)), finalWitness()]],
  [[], []],
);
// Clean proposal: the sender input stripped, a finalized receiver input (30k)
// inserted after it, the payment output grown, change reduced by the +1k fee.
const proposalBytes = psbt(
  tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
  [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
  [[], []],
);

const original = () => psbtInspectDoc(originalBytes);
const proposal = () => psbtInspectDoc(proposalBytes);
const options = (extra = {}) => ({
  paymentScript: hex(spk(PAYMENT)),
  feeOutputIndex: 1,
  maxAdditionalFeeContribution: 1000,
  ...extra,
});

// --- Accepted ---------------------------------------------------------------

test("the clean BIP-78 proposal is accepted", () => {
  const result = checkPayjoinProposal(original(), proposal(), options());
  assert.equal(result.status, "ok");
  assert.deepEqual(result.problems, []);
  assert.deepEqual(result.unchecked, []);
  assert.deepEqual(result.senderInputs, [0]);
  assert.deepEqual(result.receiverInputs, [1]);
  assert.equal(result.senderSpendBefore, "60000");
  assert.equal(result.senderSpendAfter, "61000");
});

test("a non-witness UTXO supplies the sender amount", () => {
  const prev = prevTx(100_000, spk(SENDER_SPK));
  const orig = psbtInspectDoc(psbt(
    tx([txinRaw(prev.txid, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[pair(Uint8Array.of(0x00), prev.bytes), finalWitness()]],
    [[], []],
  ));
  const prop = psbtInspectDoc(psbt(
    tx([txinRaw(prev.txid, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, prop, options());
  assert.equal(result.status, "ok");
  assert.equal(result.senderSpendBefore, "60000");
  assert.equal(result.senderSpendAfter, "61000");
});

// --- Rejected ---------------------------------------------------------------

test("a changed version is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))], { version: 1 }),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "version_changed"));
});

test("a changed locktime is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))], { locktime: 1 }),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "locktime_changed"));
});

test("a missing sender input is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "sender_input_missing");
  assert.ok(problem);
  assert.equal(problem.input, 0);
});

test("a duplicated sender input is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "sender_input_duplicated");
  assert.ok(problem);
  assert.equal(problem.input, 0);
});

test("a changed sender sequence is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0, 0xfffffffe), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "sender_sequence_changed"));
});

test("a finalized sender input is refused", () => {
  for (const fin of [finalWitness(), finalScriptSig()]) {
    const prop = psbtInspectDoc(psbt(
      tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
      [[fin], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
      [[], []],
    ));
    const result = checkPayjoinProposal(original(), prop, options());
    assert.ok(result.problems.some((p) => p.code === "sender_input_finalized"));
  }
});

test("a sender input that still carries a UTXO is refused", () => {
  const prev = prevTx(100_000, spk(SENDER_SPK));
  for (const utxo of [witnessUtxo(100_000, spk(SENDER_SPK)), pair(Uint8Array.of(0x00), prev.bytes)]) {
    const prop = psbtInspectDoc(psbt(
      tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
      [[utxo], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
      [[], []],
    ));
    const result = checkPayjoinProposal(original(), prop, options());
    assert.ok(result.problems.some((p) => p.code === "sender_input_utxo_present"));
  }
});

test("an unfinalized receiver input is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK))]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "receiver_input_not_finalized");
  assert.ok(problem);
  assert.equal(problem.input, 1);
});

test("a receiver input without a UTXO is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "receiver_input_no_utxo");
  assert.ok(problem);
  assert.equal(problem.input, 1);
});

test("input keypaths are refused", () => {
  for (const kp of [keypath(), tapKeypath()]) {
    const prop = psbtInspectDoc(psbt(
      tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
      [[kp], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
      [[], []],
    ));
    const result = checkPayjoinProposal(original(), prop, options());
    assert.ok(result.problems.some((p) => p.code === "input_keypaths"));
  }
});

test("input partial signatures are refused", () => {
  for (const sig of [partialSig(), tapKeySig(), tapScriptSig()]) {
    const prop = psbtInspectDoc(psbt(
      tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
      [[sig], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
      [[], []],
    ));
    const result = checkPayjoinProposal(original(), prop, options());
    assert.ok(result.problems.some((p) => p.code === "input_partial_sig"));
  }
});

test("mixed sequences are refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0, 0xfffffffd), txin(0x22, 1, 0xfffffffe)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "mixed_sequence"));
});

test("mixed input types are refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, p2trSpk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "mixed_input_type"));
});

test("output keypaths are refused", () => {
  for (const kp of [outputKeypath(), outputTapKeypath()]) {
    const prop = psbtInspectDoc(psbt(
      tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
      [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
      [[kp], []],
    ));
    const result = checkPayjoinProposal(original(), prop, options());
    assert.ok(result.problems.some((p) => p.code === "output_keypaths"));
  }
});

test("a missing sender output is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[]],
  ));
  const result = checkPayjoinProposal(original(), prop, {
    paymentScript: hex(spk(PAYMENT)),
    maxAdditionalFeeContribution: 1000,
  });
  const problem = result.problems.find((p) => p.code === "sender_output_missing");
  assert.ok(problem);
  assert.equal(problem.output, 1);
});

test("a decreased sender output is refused", () => {
  const result = checkPayjoinProposal(original(), proposal(), {
    paymentScript: hex(spk(PAYMENT)),
    maxAdditionalFeeContribution: 1000,
  });
  const problem = result.problems.find((p) => p.code === "sender_output_decreased");
  assert.ok(problem);
  assert.equal(problem.output, 1);
});

test("a contribution over the maximum is refused", () => {
  const result = checkPayjoinProposal(original(), proposal(), options({ maxAdditionalFeeContribution: 500 }));
  assert.ok(result.problems.some((p) => p.code === "contribution_over_max"));
});

test("a contribution larger than the fee increase is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(38_000, spk(CHANGE))]),
    [[], [witnessUtxo(29_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "contribution_not_fee"));
});

test("the sender-spend check catches an overpayment the receiver's claim hides", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(30_000, spk(CHANGE))]),
    [[], [witnessUtxo(100_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.equal(result.problems.some((p) => p.code === "contribution_not_fee"), false);
  assert.ok(result.problems.some((p) => p.code === "sender_overpays"));
});

test("a contribution over the added inputs' fee is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(30_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options({ maxAdditionalFeeContribution: 100_000 }));
  assert.ok(result.problems.some((p) => p.code === "contribution_over_added_inputs"));
});

test("a substituted payment output is refused unless substitution is allowed", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(0xff)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const refused = checkPayjoinProposal(original(), prop, options());
  const problem = refused.problems.find((p) => p.code === "payment_output_substituted");
  assert.ok(problem);
  assert.equal(problem.output, 0);

  const allowed = checkPayjoinProposal(original(), prop, options({ allowOutputSubstitution: true }));
  assert.equal(allowed.status, "ok");
});

test("a decreased payment output is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(40_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "payment_output_decreased");
  assert.ok(problem);
  assert.equal(problem.output, 0);
});

test("a sender overpayment is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(30_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "sender_overpays"));
});

test("a decreased fee is refused", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(41_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.ok(result.problems.some((p) => p.code === "fee_decreased"));
});

test("a proposal below the minimum fee rate is refused", () => {
  const result = checkPayjoinProposal(original(), proposal(), options({ minFeeRate: 100 }));
  assert.ok(result.problems.some((p) => p.code === "below_min_fee_rate"));
});

// --- Incomplete -------------------------------------------------------------

test("without a payment script the result is incomplete, never ok", () => {
  const result = checkPayjoinProposal(original(), proposal(), {
    feeOutputIndex: 1,
    maxAdditionalFeeContribution: 1000,
  });
  assert.equal(result.status, "incomplete");
  assert.ok(result.unchecked.includes("payment_output"));
  assert.ok(result.unchecked.includes("sender_spend"));
  assert.notEqual(result.status, "ok");
});

test("a sender input with no amount in the original is incomplete", () => {
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, proposal(), options({ minFeeRate: 100 }));
  assert.equal(result.status, "incomplete");
  assert.ok(result.unchecked.includes("sender_spend"));
  assert.ok(result.unchecked.includes("mixed_input_type"));
  assert.ok(result.unchecked.includes("contribution_not_fee"));
  assert.ok(result.unchecked.includes("contribution_over_added_inputs"));
  assert.ok(result.unchecked.includes("below_min_fee_rate"));
  assert.equal(result.senderSpendBefore, null);
  assert.equal(result.senderSpendAfter, null);
});

// --- Bad input --------------------------------------------------------------

test("a malformed doc is refused", () => {
  const good = proposal();
  for (const bad of [null, {}, { tx: null }, { tx: {} }]) {
    const result = checkPayjoinProposal(bad, good);
    assert.equal(result.status, "problems");
    assert.deepEqual(result.problems, [{ code: "bad_document" }]);
  }
  const result = checkPayjoinProposal(good, null);
  assert.equal(result.status, "problems");
  assert.deepEqual(result.problems, [{ code: "bad_document" }]);
});

// --- Gate fixes (#1316) -----------------------------------------------------

// PSBT_IN_SIGHASH_TYPE is keyless 0x03 with a 4-byte little-endian value.
const sighashType = (type) => pair(Uint8Array.of(0x03), le32(type));

test("a sighash type the receiver added to a sender input is refused (GLM, DeepSeek)", () => {
  for (const type of [0x02, 0x81]) {
    const prop = psbtInspectDoc(psbt(
      tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
      [[sighashType(type)], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
      [[], []],
    ));
    const result = checkPayjoinProposal(original(), prop, options());
    const problem = result.problems.find((p) => p.code === "sender_sighash_changed");
    assert.ok(problem, `sighash ${type} is refused`);
    assert.equal(problem.input, 0);
  }
});

test("a sender sighash type the original already carried is kept", () => {
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, spk(SENDER_SPK)), sighashType(0x01), finalWitness()]],
    [[], []],
  ));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[sighashType(0x01)], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, prop, options());
  assert.equal(result.problems.some((p) => p.code === "sender_sighash_changed"), false);
});

test("a duplicated receiver input is refused (MiniMax)", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1), txin(0x22, 1)], [txout(110_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "duplicate_input");
  assert.ok(problem);
  assert.equal(problem.input, 1);
});

test("two sender outputs to one script are counted, not matched as a set (GLM)", () => {
  // Original: 100k in, 50k payment, two 20k outputs to the same change script.
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(20_000, spk(CHANGE)), txout(20_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, spk(SENDER_SPK)), finalWitness()]],
    [[], [], []],
  ));
  // Proposal drops one change output and moves its 20k into the payment.
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(100_000, spk(PAYMENT)), txout(20_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, prop, { paymentScript: hex(spk(PAYMENT)), maxAdditionalFeeContribution: 1000 });
  // Two outputs to one script cannot be told apart by script alone, so the
  // duplicate is refused outright.
  const problem = result.problems.find((p) => p.code === "original_duplicate_script");
  assert.ok(problem);
  assert.equal(problem.output, 2);
  // The sender-spend check sees it too: 60k before, 80k after.
  assert.ok(result.problems.some((p) => p.code === "sender_overpays"));
});

test("no contribution means no contribution_not_fee, even when the fee drops (DeepSeek)", () => {
  // Change grows by 1k, the payment is unchanged: the fee falls 1k, nothing contributed.
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(41_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.equal(result.problems.some((p) => p.code === "contribution_not_fee"), false);
  assert.ok(result.problems.some((p) => p.code === "fee_decreased"));
});

// --- Round 3 fixes (#1316) --------------------------------------------------

test("the reviewers' duplicate-script drain is refused (GLM)", () => {
  // Original: 100000 in, outputs [P 50000, P 10000, X 19000, X 20000].
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(10_000, spk(PAYMENT)), txout(19_000, spk(CHANGE)), txout(20_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, spk(SENDER_SPK)), finalWitness()]],
    [[], [], [], []],
  ));
  // Proposal: a 41000 receiver input, outputs [P 120000, P 0, X 20000, X 0].
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(120_000, spk(PAYMENT)), txout(0, spk(PAYMENT)), txout(20_000, spk(CHANGE)), txout(0, spk(CHANGE))]),
    [[], [witnessUtxo(41_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], [], [], []],
  ));
  const result = checkPayjoinProposal(orig, prop, { paymentScript: hex(spk(PAYMENT)), maxAdditionalFeeContribution: 1000 });
  const p = result.problems.find((p) => p.code === "original_duplicate_script" && p.output === 1);
  assert.ok(p, "the second payment output is flagged");
  const x = result.problems.find((p) => p.code === "original_duplicate_script" && p.output === 3);
  assert.ok(x, "the second change output is flagged");
  assert.equal(result.status, "problems");
});

test("a fee output split across two outputs is summed (GLM)", () => {
  // Original: 100000 in, [P 50000, C 40000], fee 10000.
  // Proposal: [P 80000, C 20000, C 19000], receiver input 30000.
  // The change script C sums to 39000, so the contribution is 1000.
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(20_000, spk(CHANGE)), txout(19_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], [], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.equal(result.status, "ok");
  assert.deepEqual(result.problems, []);
});

test("a fee output split that over-contributes is refused (GLM)", () => {
  // Same, but the change sums to 38000: the contribution is 2000 > 1000.
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(20_000, spk(CHANGE)), txout(18_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], [], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "contribution_over_max");
  assert.ok(problem);
  assert.equal(problem.output, 1);
});

test("a fee output that is the payment output allows no contribution (GLM)", () => {
  // feeOutputIndex 0 is the payment output, so it is treated as out of range.
  const result = checkPayjoinProposal(original(), proposal(), options({ feeOutputIndex: 0 }));
  const problem = result.problems.find((p) => p.code === "sender_output_decreased");
  assert.ok(problem);
  assert.equal(problem.output, 1);
});

test("a non-witness UTXO that disagrees with the witness claim is refused (GLM)", () => {
  const prev = prevTx(30_000, spk(RECEIVER_SPK));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txinRaw(prev.txid, 0)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [pair(Uint8Array.of(0x00), prev.bytes), witnessUtxo(31_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "utxo_mismatch");
  assert.ok(problem);
  assert.equal(problem.input, 1);
  assert.equal(problem.doc, "proposal");
});

test("a matching non-witness UTXO wins over the witness claim (GLM)", () => {
  const prev = prevTx(30_000, spk(RECEIVER_SPK));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txinRaw(prev.txid, 0)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [pair(Uint8Array.of(0x00), prev.bytes), witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.equal(result.problems.some((p) => p.code === "utxo_mismatch"), false);
  // The fee uses the checked 30000, so the contribution is still 1000.
  assert.equal(result.status, "ok");
});

test("a non-witness UTXO for another outpoint is refused (GLM)", () => {
  const prev = prevTx(30_000, spk(RECEIVER_SPK));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [pair(Uint8Array.of(0x00), prev.bytes), witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "utxo_mismatch");
  assert.ok(problem);
  assert.equal(problem.input, 1);
  assert.equal(problem.doc, "proposal");
});

test("a field the receiver added to a sender input is refused (GLM)", () => {
  // 0x05 is PSBT_IN_WITNESS_SCRIPT; the original sender input has none.
  const witnessScript = pair(Uint8Array.of(0x05), Uint8Array.of(0x51));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[witnessScript], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "sender_input_field_added");
  assert.ok(problem);
  assert.equal(problem.input, 0);
});

test("a tap internal key the receiver added to a sender input is refused (GLM)", () => {
  // 0x17 is PSBT_IN_TAP_INTERNAL_KEY; 32 bytes.
  const tapInternalKey = pair(Uint8Array.of(0x17), Uint8Array.from(Array(32).fill(0x07)));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[tapInternalKey], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  const problem = result.problems.find((p) => p.code === "sender_input_field_added");
  assert.ok(problem);
  assert.equal(problem.input, 0);
});

test("the minimum fee rate uses the proposal's real size (GLM)", () => {
  // Original: 100000 in, [P 50000, C 40000], fee 10000.
  // Proposal: receiver input 30000, [P 50000, C 40000, R 30000], fee 10000.
  // base = 4 + 1 + 2*41 + 1 + 3*31 + 4 = 185; witness = 2 + 2 + 2 = 6;
  // weight = 185*3 + 191 = 746; vsize = ceil(746/4) = 187; +1 sender = 188.
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE)), txout(30_000, spk(RECEIVER_SPK))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness()]],
    [[], [], []],
  ));
  const below = checkPayjoinProposal(original(), prop, { paymentScript: hex(spk(PAYMENT)), minFeeRate: 54 });
  assert.ok(below.problems.some((p) => p.code === "below_min_fee_rate"));
  const ok = checkPayjoinProposal(original(), prop, { paymentScript: hex(spk(PAYMENT)), minFeeRate: 53 });
  assert.equal(ok.problems.some((p) => p.code === "below_min_fee_rate"), false);
  assert.equal(ok.status, "ok");
});

test("an unknown fee is not silently ok (GLM)", () => {
  const doc = JSON.parse(JSON.stringify(proposal()));
  const receiverMap = doc.inputs[1];
  const witness = receiverMap.find((p) => p.key === "01");
  delete witness.decoded.value;
  const result = checkPayjoinProposal(original(), doc, options());
  assert.ok(result.unchecked.includes("fee_decreased"));
  assert.notEqual(result.status, "ok");
});

test("two different non-standard input templates are mixed (GLM)", () => {
  // 0x51 0x14 + 20 bytes and 0x52 0x14 + 20 bytes are both "other", but
  // different templates.
  const senderSpk = Uint8Array.of(0x51, 0x14, ...Array(20).fill(0x01));
  const receiverSpk = Uint8Array.of(0x52, 0x14, ...Array(20).fill(0x02));
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, senderSpk), finalWitness()]],
    [[], []],
  ));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, receiverSpk), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, prop, options());
  assert.ok(result.problems.some((p) => p.code === "mixed_input_type"));
});

test("an odd-length output script is a bad document (GLM)", () => {
  const doc = JSON.parse(JSON.stringify(proposal()));
  doc.tx.outputs[0].scriptPubKey = "001";
  const result = checkPayjoinProposal(original(), doc, options());
  assert.equal(result.status, "problems");
  assert.deepEqual(result.problems, [{ code: "bad_document" }]);
});

// --- Round 4 fixes (#1316) --------------------------------------------------

test("a receiver input whose finals contradict its witness_utxo is refused (Grok)", () => {
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalScriptSig(p2shP2wpkhScriptSig(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(original(), prop, options());
  assert.equal(result.status, "problems");
  const problem = result.problems.find((p) => p.code === "input_type_mismatch");
  assert.ok(problem);
  assert.equal(problem.input, 1);
});

test("a P2SH-P2WPKH sender and a legacy P2SH receiver are mixed (K3.1)", () => {
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, p2shSpk(SENDER_SPK)), finalScriptSig(p2shP2wpkhScriptSig(SENDER_SPK)), finalWitness()]],
    [[], []],
  ));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, p2shSpk(RECEIVER_SPK)), finalScriptSig(Uint8Array.of(0x00))]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, prop, options());
  assert.ok(result.problems.some((p) => p.code === "mixed_input_type"));
});

test("two P2SH-P2WPKH inputs are one type and use the 91 vB size", () => {
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, p2shSpk(SENDER_SPK)), finalScriptSig(p2shP2wpkhScriptSig(SENDER_SPK)), finalWitness()]],
    [[], []],
  ));
  const prop = psbtInspectDoc(psbt(
    tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(35_000, spk(CHANGE))]),
    [[], [witnessUtxo(30_000, p2shSpk(RECEIVER_SPK)), finalScriptSig(p2shP2wpkhScriptSig(RECEIVER_SPK)), finalWitness()]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, prop, options({ maxAdditionalFeeContribution: 10_000 }));
  assert.equal(result.problems.some((p) => p.code === "mixed_input_type"), false);
  assert.equal(result.unchecked.includes("contribution_over_added_inputs"), false);
  assert.equal(result.problems.some((p) => p.code === "contribution_over_added_inputs"), false);
});

test("a sender input with no original finals leaves mixed_input_type unchecked", () => {
  const orig = psbtInspectDoc(psbt(
    tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
    [[witnessUtxo(100_000, spk(SENDER_SPK))]],
    [[], []],
  ));
  const result = checkPayjoinProposal(orig, proposal(), options());
  assert.ok(result.unchecked.includes("mixed_input_type"));
  assert.notEqual(result.status, "ok");
});

test("an odd-length map key is a bad document", () => {
  const doc = JSON.parse(JSON.stringify(proposal()));
  doc.inputs[1][0].key = "001";
  const result = checkPayjoinProposal(original(), doc, options());
  assert.equal(result.status, "problems");
  assert.deepEqual(result.problems, [{ code: "bad_document" }]);
});

// --- Source check -----------------------------------------------------------

test("payjoin-check.js has no randomness, network or DOM", () => {
  const source = readFileSync(new URL("../src/js/payjoin-check.js", import.meta.url), "utf8");
  // Calls and property access, not words: the module's own "bad_document"
  // code and comments about inspect documents are fine.
  for (const forbidden of [/\bMath\.random\b/, /\bgetRandomValues\b/, /\bfetch\s*\(/, /\bdocument\s*[.[]/, /\bwindow\s*[.[]/, /\bglobalThis\s*[.[]/]) {
    assert.doesNotMatch(source, forbidden, `source must not use ${forbidden}`);
  }
});
