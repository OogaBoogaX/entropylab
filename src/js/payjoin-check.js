// BIP-78 sender checklist over two psbtInspectDoc results.
//
// A receiver input's amount from witness_utxo alone is the receiver's claim;
// a full previous transaction (non_witness_utxo) is checked by the inspector
// against the outpoint and wins, and a disagreement is refused. An inflated
// witness-only claim can still make up to maxAdditionalFeeContribution look
// like fee (the sender's total loss stays capped by sender_overpays). Taproot
// senders are safe because their signatures commit to every input amount.
// Proving segwit v0 claims from the receiver's own signatures is follow-up
// work, needed before any UI shows this result.
//
// A sender runs this before signing a Payjoin Proposal. It decides from the
// sender's own inputs and outputs whether the proposal can be signed, and it
// never reports "ok" while a check could not run. Nothing here holds keys,
// generates randomness, touches the DOM or the network.

const SATS = /^\d+$/;
const HEX = /^[0-9a-fA-F]*$/;

const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

const keyType = (pair) => {
  const byte = Number.parseInt(pair.key.slice(0, 2), 16);
  return Number.isInteger(byte) ? byte : -1;
};
const isKeyless = (pair) => pair.key.length === 2;
const hasKeyless = (map, type) => map.some((pair) => isKeyless(pair) && keyType(pair) === type);
const hasType = (map, types) => map.some((pair) => types.includes(keyType(pair)));
const keylessValue = (map, type) => {
  const pair = map.find((candidate) => isKeyless(candidate) && keyType(candidate) === type);
  return pair ? String(pair.value).toLowerCase() : null;
};

const outpointKey = (input) => `${input.txid.toLowerCase()}:${input.vout}`;

const pairKey = (pair) => `${String(pair.key).toLowerCase()}:${String(pair.value).toLowerCase()}`;
// Key types with their own checks; every other field must already be in the
// original input.
const OWN_CODES = new Set([0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x13, 0x14, 0x16]);

const inputUtxo = (map) => {
  const witness = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x01);
  const nonWitness = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x00);
  const w = witness && isObject(witness.decoded) ? witness.decoded : null;
  const wValue = w && typeof w.value === "string" && SATS.test(w.value) ? BigInt(w.value) : null;
  const wScript = w && typeof w.scriptPubKey === "string" ? w.scriptPubKey.toLowerCase() : null;
  const n = nonWitness && isObject(nonWitness.decoded) ? nonWitness.decoded : null;
  const np = n && isObject(n.prevout) ? n.prevout : null;
  const npValue = np && typeof np.value === "string" && SATS.test(np.value) ? BigInt(np.value) : null;
  const npScript = np && typeof np.scriptPubKey === "string" ? np.scriptPubKey.toLowerCase() : null;
  if (nonWitness && !np) {
    // The full previous transaction does not prove this outpoint, so the
    // witness claim (if any) is all there is, and it is not checked.
    return { value: wValue, script: wScript, mismatch: true };
  }
  if (np) {
    // A checked prevout wins over the receiver's witness claim.
    const mismatch = witness ? wValue !== npValue || wScript !== npScript : false;
    return { value: npValue, script: npScript, mismatch };
  }
  return { value: wValue, script: wScript, mismatch: false };
};

const scriptType = (script) => {
  if (typeof script !== "string") return null;
  const hex = script.toLowerCase();
  if (/^0014[0-9a-f]{40}$/.test(hex)) return "p2wpkh";
  if (/^0020[0-9a-f]{64}$/.test(hex)) return "p2wsh";
  if (/^5120[0-9a-f]{64}$/.test(hex)) return "p2tr";
  if (/^a914[0-9a-f]{40}87$/.test(hex)) return "p2sh";
  if (/^76a914[0-9a-f]{40}88ac$/.test(hex)) return "p2pkh";
  return "other";
};

// Two non-standard templates are different types: a witness v1 program and a
// witness v2 program are not the same script family.
const typeKey = (script) => {
  const type = scriptType(script);
  if (type !== "other") return type;
  const hex = script.toLowerCase();
  return `other:${hex.slice(0, 2)}:${hex.length / 2}`;
};

const INPUT_VSIZE = { p2wpkh: 68, p2sh: 91, p2pkh: 148, p2tr: 58 };

const varintLen = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9);

const hexBytes = (hex) => (typeof hex === "string" && HEX.test(hex) && hex.length % 2 === 0 ? hex.length / 2 : null);

const countTo = (outputs, script) => outputs.filter((output) => output.scriptPubKey.toLowerCase() === script).length;
const sumTo = (outputs, script) =>
  outputs.reduce((sum, output) => (output.scriptPubKey.toLowerCase() === script ? sum + BigInt(output.value) : sum), 0n);

const finalsOf = (map) => {
  const scriptSig = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x07);
  const witnessStack = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x08);
  return scriptSig || witnessStack ? { scriptSig, witnessStack } : null;
};

const txVsize = (txInputs, txOutputs, finalsFor) => {
  let base = 4 + varintLen(txInputs.length);
  let witness = 0;
  let hasWitness = false;
  for (let i = 0; i < txInputs.length; i++) {
    const finals = finalsFor(i);
    if (finals === null) return null;
    const scriptSigLen = finals.scriptSig ? hexBytes(finals.scriptSig.value) : 0;
    if (scriptSigLen === null) return null;
    base += 32 + 4 + varintLen(scriptSigLen) + scriptSigLen + 4;
    if (finals.witnessStack) {
      const witnessLen = hexBytes(finals.witnessStack.value);
      if (witnessLen === null) return null;
      hasWitness = true;
      witness += witnessLen;
    } else {
      witness += 1;
    }
  }
  base += varintLen(txOutputs.length);
  for (const output of txOutputs) {
    const scriptLen = hexBytes(output.scriptPubKey);
    if (scriptLen === null) return null;
    base += 8 + varintLen(scriptLen) + scriptLen;
  }
  base += 4;
  const total = base + (hasWitness ? 2 + witness : 0);
  return Math.ceil((base * 3 + total) / 4);
};

const originalVsize = (original) =>
  txVsize(original.tx.inputs, original.tx.outputs, (i) => finalsOf(original.inputs[i]));

const senderType = (original) => {
  const types = new Set();
  for (const map of original.inputs) {
    const type = scriptType(inputUtxo(map).script);
    if (type === null) return null;
    types.add(type);
  }
  if (types.size !== 1) return null;
  const type = [...types][0];
  return INPUT_VSIZE[type] ? type : null;
};

const toSats = (value) => {
  if (typeof value === "bigint") return value >= 0n ? value : 0n;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && SATS.test(value)) return BigInt(value);
  return 0n;
};

const ceilDiv = (a, b) => (a + b - 1n) / b;

const badDoc = () => ({
  status: "problems",
  problems: [{ code: "bad_document" }],
  unchecked: [],
  senderInputs: [],
  receiverInputs: [],
  senderSpendBefore: null,
  senderSpendAfter: null,
});

const validDoc = (doc) => {
  if (!isObject(doc)) return false;
  const tx = doc.tx;
  if (!isObject(tx)) return false;
  if (!Number.isInteger(tx.version) || !Number.isInteger(tx.locktime)) return false;
  if (!Array.isArray(tx.inputs) || !Array.isArray(tx.outputs)) return false;
  if (!Array.isArray(doc.inputs) || !Array.isArray(doc.outputs)) return false;
  if (doc.inputs.length !== tx.inputs.length || doc.outputs.length !== tx.outputs.length) return false;
  for (const input of tx.inputs) {
    if (!isObject(input)) return false;
    if (typeof input.txid !== "string" || !/^[0-9a-fA-F]{64}$/.test(input.txid)) return false;
    if (!Number.isInteger(input.vout) || input.vout < 0) return false;
    if (!Number.isInteger(input.sequence)) return false;
  }
  for (const output of tx.outputs) {
    if (!isObject(output)) return false;
    if (typeof output.value !== "string" || !SATS.test(output.value)) return false;
    if (typeof output.scriptPubKey !== "string" || !HEX.test(output.scriptPubKey)) return false;
    if (output.scriptPubKey.length % 2 !== 0) return false;
  }
  for (const map of [...doc.inputs, ...doc.outputs]) {
    if (!Array.isArray(map)) return false;
    for (const pair of map) {
      if (!isObject(pair)) return false;
      if (typeof pair.key !== "string" || pair.key.length < 2 || !HEX.test(pair.key)) return false;
    }
  }
  return true;
};

const check = (original, proposal, options) => {
  const problems = [];
  const unchecked = [];
  const problem = (code, extra) => problems.push(extra ? { code, ...extra } : { code });
  const skip = (code) => {
    if (!unchecked.includes(code)) unchecked.push(code);
  };

  const originalIndex = new Map();
  original.tx.inputs.forEach((input, i) => {
    const key = outpointKey(input);
    if (!originalIndex.has(key)) originalIndex.set(key, i);
  });
  const proposalCount = new Map();
  proposal.tx.inputs.forEach((input) => {
    const key = outpointKey(input);
    proposalCount.set(key, (proposalCount.get(key) || 0) + 1);
  });

  const senderInputs = [];
  const receiverInputs = [];
  proposal.tx.inputs.forEach((input, i) => {
    if (originalIndex.has(outpointKey(input))) senderInputs.push(i);
    else receiverInputs.push(i);
  });

  const paymentScript =
    typeof options.paymentScript === "string" && options.paymentScript.length > 0
      ? options.paymentScript.toLowerCase()
      : null;
  let paymentIndex = null;
  if (paymentScript !== null) {
    const found = original.tx.outputs.findIndex((output) => output.scriptPubKey.toLowerCase() === paymentScript);
    if (found >= 0) paymentIndex = found;
  }
  const senderOutputs =
    paymentIndex === null ? [] : original.tx.outputs.map((_, i) => i).filter((i) => i !== paymentIndex);

  if (original.tx.version !== proposal.tx.version) problem("version_changed");
  if (original.tx.locktime !== proposal.tx.locktime) problem("locktime_changed");

  original.tx.inputs.forEach((input, i) => {
    const key = outpointKey(input);
    const count = proposalCount.get(key) || 0;
    if (count === 0) problem("sender_input_missing", { input: i });
    else if (count > 1) {
      const first = proposal.tx.inputs.findIndex((candidate) => outpointKey(candidate) === key);
      problem("sender_input_duplicated", { input: first });
    }
  });

  for (const [key, count] of proposalCount) {
    if (count > 1 && !originalIndex.has(key)) {
      problem("duplicate_input", { input: proposal.tx.inputs.findIndex((candidate) => outpointKey(candidate) === key) });
    }
  }

  // A checked prevout that disagrees with the witness claim is refused.
  original.inputs.forEach((map, i) => {
    if (inputUtxo(map).mismatch) problem("utxo_mismatch", { input: i, doc: "original" });
  });

  for (const i of senderInputs) {
    const input = proposal.tx.inputs[i];
    const originalInput = original.tx.inputs[originalIndex.get(outpointKey(input))];
    if (input.sequence !== originalInput.sequence) problem("sender_sequence_changed", { input: i });
    const map = proposal.inputs[i];
    if (hasKeyless(map, 0x07) || hasKeyless(map, 0x08)) problem("sender_input_finalized", { input: i });
    if (hasKeyless(map, 0x00) || hasKeyless(map, 0x01)) problem("sender_input_utxo_present", { input: i });
    // A sighash type the receiver added or changed could make the sender sign
    // less than the whole transaction (SIGHASH_NONE, ANYONECANPAY).
    const originalMap = original.inputs[originalIndex.get(outpointKey(input))];
    if (keylessValue(map, 0x03) !== keylessValue(originalMap, 0x03)) problem("sender_sighash_changed", { input: i });
    // Any other field the receiver added (redeem/witness script, tap leaf,
    // tap internal key, merkle root, proprietary, unknown) would be used by
    // the sender's signer, so it must already be in the original.
    const originalPairs = new Set(originalMap.map(pairKey));
    if (map.some((pair) => !OWN_CODES.has(keyType(pair)) && !originalPairs.has(pairKey(pair)))) {
      problem("sender_input_field_added", { input: i });
    }
  }

  for (const i of receiverInputs) {
    const map = proposal.inputs[i];
    if (!hasKeyless(map, 0x07) && !hasKeyless(map, 0x08)) problem("receiver_input_not_finalized", { input: i });
    if (!hasKeyless(map, 0x00) && !hasKeyless(map, 0x01)) problem("receiver_input_no_utxo", { input: i });
    if (inputUtxo(map).mismatch) problem("utxo_mismatch", { input: i, doc: "proposal" });
  }

  proposal.inputs.forEach((map, i) => {
    if (hasType(map, [0x06, 0x16])) problem("input_keypaths", { input: i });
    if (hasType(map, [0x02, 0x13, 0x14])) problem("input_partial_sig", { input: i });
  });

  if (new Set(proposal.tx.inputs.map((input) => input.sequence)).size > 1) problem("mixed_sequence");

  const senderTypes = new Set();
  let typeUnknown = false;
  for (const i of senderInputs) {
    const originalMap = original.inputs[originalIndex.get(outpointKey(proposal.tx.inputs[i]))];
    const type = typeKey(inputUtxo(originalMap).script);
    if (type === null) typeUnknown = true;
    else senderTypes.add(type);
  }
  const receiverTypes = new Set();
  for (const i of receiverInputs) {
    const type = typeKey(inputUtxo(proposal.inputs[i]).script);
    if (type === null) typeUnknown = true;
    else receiverTypes.add(type);
  }
  if (typeUnknown) skip("mixed_input_type");
  else if (new Set([...senderTypes, ...receiverTypes]).size > 1) problem("mixed_input_type");

  proposal.outputs.forEach((map, i) => {
    if (hasType(map, [0x02, 0x07])) problem("output_keypaths", { output: i });
  });

  // Two outputs to one script cannot be told apart by script alone, so the
  // per-script sums below would hide a drain of the later one.
  const seenScripts = new Set();
  const reportedDuplicates = new Set();
  original.tx.outputs.forEach((output, i) => {
    const script = output.scriptPubKey.toLowerCase();
    if (seenScripts.has(script) && !reportedDuplicates.has(script)) {
      reportedDuplicates.add(script);
      problem("original_duplicate_script", { output: i });
    }
    seenScripts.add(script);
  });

  // Without feeOutputIndex no contribution is allowed: any decrease of a
  // sender output is sender_output_decreased, and sender_overpays still runs.
  // A fee output that is the payment output would let the receiver take the
  // payment as fee, so it is treated as out of range.
  const feeOutputIndex =
    Number.isInteger(options.feeOutputIndex) &&
    options.feeOutputIndex >= 0 &&
    options.feeOutputIndex < original.tx.outputs.length &&
    options.feeOutputIndex !== paymentIndex
      ? options.feeOutputIndex
      : null;

  const maxContribution = toSats(options.maxAdditionalFeeContribution);
  let contribution = null;
  if (paymentIndex !== null) {
    for (const j of senderOutputs) {
      const script = original.tx.outputs[j].scriptPubKey.toLowerCase();
      const value = BigInt(original.tx.outputs[j].value);
      const sum = sumTo(proposal.tx.outputs, script);
      if (countTo(proposal.tx.outputs, script) === 0) {
        problem("sender_output_missing", { output: j });
        if (j === feeOutputIndex) {
          skip("contribution_over_max");
          skip("contribution_not_fee");
          skip("contribution_over_added_inputs");
        }
      } else if (j === feeOutputIndex) {
        contribution = value > sum ? value - sum : 0n;
        if (contribution > maxContribution) problem("contribution_over_max", { output: feeOutputIndex });
      } else if (sum < value) {
        problem("sender_output_decreased", { output: j });
      }
    }
  }

  const originalAmounts = original.inputs.map((map) => inputUtxo(map).value);
  const originalFeeKnown = originalAmounts.every((value) => value !== null);
  const originalFee = originalFeeKnown
    ? originalAmounts.reduce((sum, value) => sum + value, 0n) -
      original.tx.outputs.reduce((sum, output) => sum + BigInt(output.value), 0n)
    : null;

  const proposalAmounts = proposal.tx.inputs.map((input, i) => {
    const key = outpointKey(input);
    if (originalIndex.has(key)) return originalAmounts[originalIndex.get(key)];
    return inputUtxo(proposal.inputs[i]).value;
  });
  const proposalFeeKnown = proposalAmounts.every((value) => value !== null);
  const proposalFee = proposalFeeKnown
    ? proposalAmounts.reduce((sum, value) => sum + value, 0n) -
      proposal.tx.outputs.reduce((sum, output) => sum + BigInt(output.value), 0n)
    : null;

  if (contribution !== null && contribution > 0n) {
    if (originalFee === null || proposalFee === null) skip("contribution_not_fee");
    else if (contribution > proposalFee - originalFee) problem("contribution_not_fee", { output: feeOutputIndex });
  }

  const addedInputs = Math.max(0, proposal.tx.inputs.length - original.tx.inputs.length);
  const vsize = originalVsize(original);
  const proposalVsize = (() => {
    const finalsFor = (i) => {
      const key = outpointKey(proposal.tx.inputs[i]);
      // A sender input uses the finals of the matching original input; a
      // receiver input uses its own finals from the proposal.
      return originalIndex.has(key)
        ? finalsOf(original.inputs[originalIndex.get(key)])
        : finalsOf(proposal.inputs[i]);
    };
    const size = txVsize(proposal.tx.inputs, proposal.tx.outputs, finalsFor);
    // A new ECDSA signature can be one byte longer than the original's.
    return size === null ? null : size + senderInputs.length;
  })();
  const type = senderType(original);
  const inputVsize = type ? INPUT_VSIZE[type] : null;
  const rateKnown = vsize !== null && originalFee !== null && originalFee >= 0n && inputVsize !== null;

  if (contribution !== null) {
    if (!rateKnown) skip("contribution_over_added_inputs");
    else {
      const bound = ceilDiv(originalFee * BigInt(inputVsize) * BigInt(addedInputs), BigInt(vsize));
      if (contribution > bound) problem("contribution_over_added_inputs", { output: feeOutputIndex });
    }
  }

  if (options.minFeeRate !== undefined) {
    const minFeeRate = options.minFeeRate;
    if (typeof minFeeRate !== "number" || !Number.isFinite(minFeeRate) || minFeeRate < 0) skip("below_min_fee_rate");
    else if (proposalFee === null || proposalVsize === null) skip("below_min_fee_rate");
    else if (proposalVsize > 0 && Number(proposalFee) / proposalVsize < minFeeRate) problem("below_min_fee_rate");
  }

  if (originalFee === null || proposalFee === null) skip("fee_decreased");
  else if (proposalFee < originalFee) problem("fee_decreased");

  let senderSpendBefore = null;
  let senderSpendAfter = null;
  if (paymentIndex === null || !originalFeeKnown) {
    skip("sender_spend");
  } else {
    const senderScripts = new Set(senderOutputs.map((j) => original.tx.outputs[j].scriptPubKey.toLowerCase()));
    const inputSum = originalAmounts.reduce((sum, value) => sum + value, 0n);
    const before = original.tx.outputs.reduce(
      (sum, output) => (senderScripts.has(output.scriptPubKey.toLowerCase()) ? sum + BigInt(output.value) : sum),
      0n,
    );
    const after = proposal.tx.outputs.reduce(
      (sum, output) => (senderScripts.has(output.scriptPubKey.toLowerCase()) ? sum + BigInt(output.value) : sum),
      0n,
    );
    senderSpendBefore = (inputSum - before).toString();
    senderSpendAfter = (inputSum - after).toString();
    if (before - after > maxContribution) problem("sender_overpays");
  }

  if (paymentIndex === null) {
    skip("payment_output");
  } else {
    const script = original.tx.outputs[paymentIndex].scriptPubKey.toLowerCase();
    const value = BigInt(original.tx.outputs[paymentIndex].value);
    const allowSubstitution = options.allowOutputSubstitution === true;
    // BIP-78: "If the output is the payment output and payment output
    // substitution is allowed: Do not make any check". The sender's spend is
    // still bounded by the sender-output checks and sender_overpays.
    if (!allowSubstitution) {
      if (countTo(proposal.tx.outputs, script) === 0) problem("payment_output_substituted", { output: paymentIndex });
      else if (sumTo(proposal.tx.outputs, script) < value) problem("payment_output_decreased", { output: paymentIndex });
    }
  }

  const status = problems.length > 0 ? "problems" : unchecked.length > 0 ? "incomplete" : "ok";
  return { status, problems, unchecked, senderInputs, receiverInputs, senderSpendBefore, senderSpendAfter };
};

export function checkPayjoinProposal(original, proposal, options = {}) {
  if (!validDoc(original) || !validDoc(proposal)) return badDoc();
  try {
    return check(original, proposal, isObject(options) ? options : {});
  } catch {
    return badDoc();
  }
}
