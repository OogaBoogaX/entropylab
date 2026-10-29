// BIP-78 sender checklist over two psbtInspectDoc results.
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

const outpointKey = (input) => `${input.txid.toLowerCase()}:${input.vout}`;

const inputUtxo = (map) => {
  const witness = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x01);
  if (witness) {
    const decoded = isObject(witness.decoded) ? witness.decoded : null;
    return {
      value: decoded && typeof decoded.value === "string" && SATS.test(decoded.value) ? BigInt(decoded.value) : null,
      script: decoded && typeof decoded.scriptPubKey === "string" ? decoded.scriptPubKey.toLowerCase() : null,
    };
  }
  const nonWitness = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x00);
  if (nonWitness) {
    const decoded = isObject(nonWitness.decoded) ? nonWitness.decoded : null;
    const prevout = decoded && isObject(decoded.prevout) ? decoded.prevout : null;
    return {
      value: prevout && typeof prevout.value === "string" && SATS.test(prevout.value) ? BigInt(prevout.value) : null,
      script: prevout && typeof prevout.scriptPubKey === "string" ? prevout.scriptPubKey.toLowerCase() : null,
    };
  }
  return { value: null, script: null };
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

const INPUT_VSIZE = { p2wpkh: 68, p2sh: 91, p2pkh: 148, p2tr: 58 };

const varintLen = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9);

const hexBytes = (hex) => (typeof hex === "string" && HEX.test(hex) && hex.length % 2 === 0 ? hex.length / 2 : null);

const originalVsize = (original) => {
  let base = 4 + varintLen(original.tx.inputs.length);
  let witness = 0;
  let hasWitness = false;
  for (let i = 0; i < original.tx.inputs.length; i++) {
    const map = original.inputs[i];
    const scriptSig = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x07);
    const witnessStack = map.find((pair) => isKeyless(pair) && keyType(pair) === 0x08);
    if (!scriptSig && !witnessStack) return null;
    const scriptSigLen = scriptSig ? hexBytes(scriptSig.value) : 0;
    if (scriptSigLen === null) return null;
    base += 32 + 4 + varintLen(scriptSigLen) + scriptSigLen + 4;
    if (witnessStack) {
      const witnessLen = hexBytes(witnessStack.value);
      if (witnessLen === null) return null;
      hasWitness = true;
      witness += witnessLen;
    } else {
      witness += 1;
    }
  }
  base += varintLen(original.tx.outputs.length);
  for (const output of original.tx.outputs) {
    const scriptLen = hexBytes(output.scriptPubKey);
    if (scriptLen === null) return null;
    base += 8 + varintLen(scriptLen) + scriptLen;
  }
  base += 4;
  const total = base + (hasWitness ? 2 + witness : 0);
  return Math.ceil((base * 3 + total) / 4);
};

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

  for (const i of senderInputs) {
    const input = proposal.tx.inputs[i];
    const originalInput = original.tx.inputs[originalIndex.get(outpointKey(input))];
    if (input.sequence !== originalInput.sequence) problem("sender_sequence_changed", { input: i });
    const map = proposal.inputs[i];
    if (hasKeyless(map, 0x07) || hasKeyless(map, 0x08)) problem("sender_input_finalized", { input: i });
    if (hasKeyless(map, 0x00) || hasKeyless(map, 0x01)) problem("sender_input_utxo_present", { input: i });
  }

  for (const i of receiverInputs) {
    const map = proposal.inputs[i];
    if (!hasKeyless(map, 0x07) && !hasKeyless(map, 0x08)) problem("receiver_input_not_finalized", { input: i });
    if (!hasKeyless(map, 0x00) && !hasKeyless(map, 0x01)) problem("receiver_input_no_utxo", { input: i });
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
    const type = scriptType(inputUtxo(originalMap).script);
    if (type === null) typeUnknown = true;
    else senderTypes.add(type);
  }
  const receiverTypes = new Set();
  for (const i of receiverInputs) {
    const type = scriptType(inputUtxo(proposal.inputs[i]).script);
    if (type === null) typeUnknown = true;
    else receiverTypes.add(type);
  }
  if (typeUnknown) skip("mixed_input_type");
  else if (new Set([...senderTypes, ...receiverTypes]).size > 1) problem("mixed_input_type");

  proposal.outputs.forEach((map, i) => {
    if (hasType(map, [0x02, 0x07])) problem("output_keypaths", { output: i });
  });

  if (paymentIndex !== null) {
    for (const j of senderOutputs) {
      const script = original.tx.outputs[j].scriptPubKey.toLowerCase();
      if (!proposal.tx.outputs.some((output) => output.scriptPubKey.toLowerCase() === script)) {
        problem("sender_output_missing", { output: j });
      }
    }
  }

  const feeOutputIndex =
    Number.isInteger(options.feeOutputIndex) &&
    options.feeOutputIndex >= 0 &&
    options.feeOutputIndex < original.tx.outputs.length
      ? options.feeOutputIndex
      : null;

  if (paymentIndex !== null) {
    for (const j of senderOutputs) {
      if (j === feeOutputIndex) continue;
      const script = original.tx.outputs[j].scriptPubKey.toLowerCase();
      const proposalIndex = proposal.tx.outputs.findIndex((output) => output.scriptPubKey.toLowerCase() === script);
      if (proposalIndex >= 0 && BigInt(proposal.tx.outputs[proposalIndex].value) < BigInt(original.tx.outputs[j].value)) {
        problem("sender_output_decreased", { output: proposalIndex });
      }
    }
  }

  const maxContribution = toSats(options.maxAdditionalFeeContribution);
  let contribution = null;
  let feeProposalIndex = null;
  if (feeOutputIndex !== null) {
    const script = original.tx.outputs[feeOutputIndex].scriptPubKey.toLowerCase();
    feeProposalIndex = proposal.tx.outputs.findIndex((output) => output.scriptPubKey.toLowerCase() === script);
    if (feeProposalIndex >= 0) {
      const before = BigInt(original.tx.outputs[feeOutputIndex].value);
      const after = BigInt(proposal.tx.outputs[feeProposalIndex].value);
      contribution = after < before ? before - after : 0n;
      if (contribution > maxContribution) problem("contribution_over_max", { output: feeProposalIndex });
    } else {
      skip("contribution_over_max");
      skip("contribution_not_fee");
      skip("contribution_over_added_inputs");
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

  if (contribution !== null) {
    if (originalFee === null || proposalFee === null) skip("contribution_not_fee");
    else if (contribution > proposalFee - originalFee) problem("contribution_not_fee", { output: feeProposalIndex });
  }

  const addedInputs = Math.max(0, proposal.tx.inputs.length - original.tx.inputs.length);
  const vsize = originalVsize(original);
  const type = senderType(original);
  const inputVsize = type ? INPUT_VSIZE[type] : null;
  const rateKnown = vsize !== null && originalFee !== null && originalFee >= 0n && inputVsize !== null;

  if (contribution !== null) {
    if (!rateKnown) skip("contribution_over_added_inputs");
    else {
      const bound = ceilDiv(originalFee * BigInt(inputVsize) * BigInt(addedInputs), BigInt(vsize));
      if (contribution > bound) problem("contribution_over_added_inputs", { output: feeProposalIndex });
    }
  }

  if (options.minFeeRate !== undefined) {
    const minFeeRate = options.minFeeRate;
    if (typeof minFeeRate !== "number" || !Number.isFinite(minFeeRate) || minFeeRate < 0) skip("below_min_fee_rate");
    else if (proposalFee === null || !rateKnown) skip("below_min_fee_rate");
    else {
      const estimatedVsize = vsize + inputVsize * addedInputs;
      if (estimatedVsize > 0 && Number(proposalFee) / estimatedVsize < minFeeRate) problem("below_min_fee_rate");
    }
  }

  if (originalFee !== null && proposalFee !== null && proposalFee < originalFee) problem("fee_decreased");

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
    const proposalIndex = proposal.tx.outputs.findIndex((output) => output.scriptPubKey.toLowerCase() === script);
    const allowSubstitution = options.allowOutputSubstitution === true;
    if (proposalIndex < 0) {
      if (!allowSubstitution) problem("payment_output_substituted", { output: paymentIndex });
    } else if (!allowSubstitution) {
      if (BigInt(proposal.tx.outputs[proposalIndex].value) < BigInt(original.tx.outputs[paymentIndex].value)) {
        problem("payment_output_decreased", { output: proposalIndex });
      }
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
