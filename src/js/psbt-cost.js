import { psbtInspectDoc } from "./psbt-wasm.js";

const hexByteLength = (hex) => {
  if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error("invalid hexadecimal field");
  return hex.length / 2;
};

const varintSize = (value) => {
  const n = BigInt(value);
  if (n < 253n) return 1;
  if (n <= 0xffffn) return 3;
  if (n <= 0xffffffffn) return 5;
  return 9;
};

const finalFields = (map, name) => map.filter((pair) => pair.name === name);

const finalScripts = (map) => {
  const scriptSigFields = finalFields(map, "PSBT_IN_FINAL_SCRIPTSIG");
  const witnessFields = finalFields(map, "PSBT_IN_FINAL_SCRIPTWITNESS");
  if (scriptSigFields.length > 1 || witnessFields.length > 1) return null;
  const scriptSig = scriptSigFields[0];
  const witness = witnessFields[0];
  if (!scriptSig && !witness) return null;
  if (scriptSig?.decodeError || witness?.decodeError) return null;
  const scriptSigLength = scriptSig ? hexByteLength(scriptSig.value) : 0;
  const witnessItems = witness?.decoded?.items?.map(hexByteLength) ?? [];
  return { scriptSigLength, witness: witnessItems };
};

const finalTxSizes = (doc) => {
  if (doc.rustBitcoinError) return null;
  if (doc.inputs.some((map) => map.some((pair) => pair.decodeError))) return null;

  const inputs = doc.tx.inputs;
  const outputs = doc.tx.outputs;
  const finals = inputs.map((_, i) => finalScripts(doc.inputs[i]));
  if (finals.some((value) => value === null)) return null;

  const hasWitness = finals.some(({ witness }) => witness.length > 0);
  const vinSize = inputs.reduce((size, input, i) => {
    const scriptSigLength = finals[i].scriptSigLength;
    return size + hexByteLength(input.txid) + 4 + varintSize(scriptSigLength) + scriptSigLength + 4;
  }, 0);
  const voutSize = outputs.reduce((size, output) => {
    const scriptLength = hexByteLength(output.scriptPubKey);
    return size + 8 + varintSize(scriptLength) + scriptLength;
  }, 0);
  const baseSize = 4 + varintSize(inputs.length) + vinSize + varintSize(outputs.length) + voutSize + 4;
  const witnessSize = hasWitness
    ? finals.reduce((size, { witness }) =>
        size + varintSize(witness.length) +
        witness.reduce((sum, itemLength) => sum + varintSize(itemLength) + itemLength, 0), 0)
    : 0;
  return {
    baseSize,
    fullSize: baseSize + (hasWitness ? 2 + witnessSize : 0),
  };
};

const sumInputs = (doc) => {
  let total = 0n;
  for (const map of doc.inputs) {
    const amounts = map
      .filter((pair) => pair.name === "PSBT_IN_WITNESS_UTXO")
      .map((pair) => pair.decoded?.value)
      .filter((value) => typeof value === "string");
    const nonWitness = map.find((pair) => pair.name === "PSBT_IN_NON_WITNESS_UTXO");
    if (nonWitness?.decoded?.prevout?.value != null) amounts.push(nonWitness.decoded.prevout.value);
    if (!amounts.length) return null;
    const unique = [...new Set(amounts)];
    if (unique.length !== 1) return null;
    total += BigInt(unique[0]);
  }
  return total;
};

const sumOutputs = (doc) => doc.tx.outputs.reduce((sum, output) => sum + BigInt(output.value), 0n);

/**
 * Derives deterministic inspection facts from a decoded PSBT document.
 * Amounts are returned as decimal strings to preserve satoshi precision.
 * Exact weight/vsize are reported only when every input has a final
 * scriptSig and/or final scriptWitness, so incomplete PSBTs never receive an
 * estimated transaction size.
 */
export const psbtCostFactsFromDoc = (doc) => {
  const inputAmount = sumInputs(doc);
  const outputAmount = sumOutputs(doc);
  // honor inspector's monetary validity (MAX_MONEY, overflow, negative)
  const feeInvalid = Boolean(doc.fee?.error) || (doc.fee?.known && doc.fee?.sats == null);
  const rawFee = inputAmount !== null && inputAmount >= outputAmount ? inputAmount - outputAmount : null;
  const fee = feeInvalid ? null : rawFee;
  const tx = finalTxSizes(doc);
  const finalized = tx !== null;
  const weight = finalized ? BigInt(tx.baseSize * 3 + tx.fullSize) : null;
  const vsize = weight === null ? null : (weight + 3n) / 4n;
  return {
    inputCount: doc.tx.inputs.length,
    outputCount: doc.tx.outputs.length,
    inputAmountSats: inputAmount === null ? null : inputAmount.toString(),
    outputAmountSats: outputAmount.toString(),
    feeSats: fee === null ? null : fee.toString(),
    finalized,
    weight: weight === null ? null : Number(weight),
    vsize: vsize === null ? null : Number(vsize),
    feeRateSatPerVbyte: fee === null || vsize === null || vsize === 0n ? null : Number(fee) / Number(vsize),
  };
};

/** Inspect raw PSBT bytes and derive exact cost facts. */
export const psbtCostFacts = (psbtBytes) => psbtCostFactsFromDoc(psbtInspectDoc(psbtBytes));
