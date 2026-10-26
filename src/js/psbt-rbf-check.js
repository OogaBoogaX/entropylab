// Pure RBF fee-bump safety check.
//
// Answers one question about a replacement transaction: does the bump only
// raise the fee, or does it also change who gets paid? It is deliberately
// DOM-free, network-free and crypto-free: it compares two already-decoded
// transaction descriptions and asks the caller (ownsScript) which scripts
// belong to the user's own key. Ownership is never inferred from the
// transaction itself, and an unknown answer is never treated as safe.
//
// Fail closed: a dropped input, an unverified input amount, an unknown
// ownership answer or any unexpected change can never produce "green".

const TXID_HEX = /^[0-9a-f]{64}$/;
const SCRIPT_HEX = /^(?:[0-9a-f]{2})*$/;

const RED_CODES = new Set(["payment-changed", "payment-removed", "multiple-decreases", "change-redirected"]);
// The only codes a green verdict may carry. Everything else is amber and
// blocks green, so a code added later fails closed until it is listed here.
const GREEN_OK_CODES = new Set(["change-decreased", "input-added"]);

const fail = (message) => {
  throw new TypeError(message);
};

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

const checkInteger = (value, name, min, max) => {
  if (!Number.isInteger(value) || value < min || value > max) fail(`${name} must be an integer between ${min} and ${max}.`);
};

const checkAmount = (value, name) => {
  if (typeof value !== "bigint" || value < 0n) fail(`${name} must be a non-negative bigint.`);
};

const checkInput = (input, name) => {
  if (!isObject(input)) fail(`${name} must be an object.`);
  if (typeof input.txid !== "string" || !TXID_HEX.test(input.txid)) fail(`${name}.txid must be 64 lowercase hex characters.`);
  checkInteger(input.vout, `${name}.vout`, 0, 0xffffffff);
  checkInteger(input.sequence, `${name}.sequence`, 0, 0xffffffff);
  if (input.sighash !== null) checkInteger(input.sighash, `${name}.sighash`, 0, 0xffffffff);
  if (input.amount !== null) checkAmount(input.amount, `${name}.amount`);
  if (typeof input.amountVerified !== "boolean") fail(`${name}.amountVerified must be a boolean.`);
};

const checkOutput = (output, name) => {
  if (!isObject(output)) fail(`${name} must be an object.`);
  if (typeof output.script !== "string" || !SCRIPT_HEX.test(output.script)) fail(`${name}.script must be lowercase hex.`);
  checkAmount(output.amount, `${name}.amount`);
};

const checkTransaction = (tx, name) => {
  if (!isObject(tx)) fail(`${name} must be an object.`);
  checkInteger(tx.version, `${name}.version`, -0x80000000, 0x7fffffff);
  checkInteger(tx.locktime, `${name}.locktime`, 0, 0xffffffff);
  if (!Array.isArray(tx.inputs)) fail(`${name}.inputs must be an array.`);
  if (!Array.isArray(tx.outputs)) fail(`${name}.outputs must be an array.`);
  tx.inputs.forEach((input, index) => checkInput(input, `${name}.inputs[${index}]`));
  tx.outputs.forEach((output, index) => checkOutput(output, `${name}.outputs[${index}]`));
};

const outpointKey = (input) => `${input.txid}:${input.vout}`;

const indexInputs = (tx, name) => {
  const byOutpoint = new Map();
  for (const input of tx.inputs) {
    const key = outpointKey(input);
    // A transaction spending the same outpoint twice is invalid; refuse it
    // rather than silently pick one of the two.
    if (byOutpoint.has(key)) fail(`${name}.inputs spends ${key} more than once.`);
    byOutpoint.set(key, input);
  }
  return byOutpoint;
};

const sumOutputs = (tx) => tx.outputs.reduce((total, output) => total + output.amount, 0n);

export const checkRbfReplacement = ({ original, replacement, ownsScript } = {}) => {
  checkTransaction(original, "original");
  checkTransaction(replacement, "replacement");
  if (ownsScript !== null && ownsScript !== undefined && typeof ownsScript !== "function") {
    fail("ownsScript must be a function or null.");
  }
  const owns = typeof ownsScript === "function" ? ownsScript : null;

  const originalInputs = indexInputs(original, "original");
  const replacementInputs = indexInputs(replacement, "replacement");

  const shared = original.inputs.filter((input) => replacementInputs.has(outpointKey(input)));
  if (shared.length === 0) {
    return {
      verdict: "neutral",
      items: [{ code: "no-shared-inputs" }],
      addedInputs: [],
      droppedInputs: [],
      feeIncrease: null,
      feeComplete: false,
    };
  }

  const droppedInputs = original.inputs
    .filter((input) => !replacementInputs.has(outpointKey(input)))
    .map((input) => ({ txid: input.txid, vout: input.vout }));
  const addedInputs = replacement.inputs
    .filter((input) => !originalInputs.has(outpointKey(input)))
    .map((input) => ({ txid: input.txid, vout: input.vout }));

  const items = [];
  for (const dropped of droppedInputs) items.push({ code: "input-dropped", txid: dropped.txid, vout: dropped.vout });
  for (const added of addedInputs) items.push({ code: "input-added", txid: added.txid, vout: added.vout });

  // Output matching: exact (script, amount) pairs first, then same-script
  // pairs as amount changes, then leftovers as removed / new. Duplicates are
  // matched one for one and never aggregated by address.
  const replacementUsed = new Array(replacement.outputs.length).fill(false);
  const matches = new Array(original.outputs.length).fill(null);
  for (let i = 0; i < original.outputs.length; i++) {
    const before = original.outputs[i];
    for (let j = 0; j < replacement.outputs.length; j++) {
      if (replacementUsed[j]) continue;
      const after = replacement.outputs[j];
      if (after.script === before.script && after.amount === before.amount) {
        replacementUsed[j] = true;
        matches[i] = { index: j, kind: "exact" };
        break;
      }
    }
  }
  for (let i = 0; i < original.outputs.length; i++) {
    if (matches[i]) continue;
    const before = original.outputs[i];
    for (let j = 0; j < replacement.outputs.length; j++) {
      if (replacementUsed[j]) continue;
      if (replacement.outputs[j].script === before.script) {
        replacementUsed[j] = true;
        matches[i] = { index: j, kind: "changed" };
        break;
      }
    }
  }

  const ownership = (script) => {
    if (!owns) return null;
    const answer = owns(script);
    // Anything other than a definite true/false is unknown, never safe.
    return answer === true ? true : answer === false ? false : null;
  };

  let exactCount = 0;
  let removedCount = 0;
  let newCount = 0;
  let decreaseCount = 0;

  for (let i = 0; i < original.outputs.length; i++) {
    const before = original.outputs[i];
    const match = matches[i];
    if (!match) {
      removedCount++;
      const own = ownership(before.script);
      items.push({
        code: own === true ? "change-removed" : "payment-removed",
        script: before.script,
        before: before.amount,
        index: i,
      });
      continue;
    }
    if (match.kind === "exact") {
      exactCount++;
      continue;
    }
    const after = replacement.outputs[match.index];
    const own = ownership(before.script);
    if (after.amount < before.amount) {
      decreaseCount++;
      const code = own === true ? "change-decreased" : own === false ? "payment-changed" : "output-decreased-unverified";
      const item = { code, script: before.script, before: before.amount, after: after.amount, index: i, replacementIndex: match.index };
      if (code === "output-decreased-unverified") item.message = "One output decreased. Check that it is your change.";
      items.push(item);
    } else {
      items.push({
        code: own === true ? "own-output-increased" : "payment-changed",
        script: before.script,
        before: before.amount,
        after: after.amount,
        index: i,
        replacementIndex: match.index,
      });
    }
  }

  for (let j = 0; j < replacement.outputs.length; j++) {
    if (replacementUsed[j]) continue;
    newCount++;
    const after = replacement.outputs[j];
    const own = ownership(after.script);
    items.push({
      code: own === true ? "new-own-output" : "new-output-unverified",
      script: after.script,
      after: after.amount,
      index: j,
    });
  }

  if (decreaseCount > 1) items.push({ code: "multiple-decreases" });

  // A session key proves the decreased or removed output was the user's own
  // change. If the same bump adds an output that key cannot derive, the
  // "fee" may be the change being redirected to someone else (Electrum
  // GHSA-6jp4-8v48-cc5v): say so in red. Without a key nothing changes.
  if (owns !== null
    && items.some((item) => item.code === "change-decreased" || item.code === "change-removed")
    && items.some((item) => item.code === "new-output-unverified")) {
    items.push({ code: "change-redirected" });
  }

  let feeIncrease = null;
  let feeComplete = false;
  if (droppedInputs.length > 0) {
    items.push({ code: "fee-incomplete" });
  } else if (addedInputs.length === 0) {
    feeIncrease = { sats: sumOutputs(original) - sumOutputs(replacement), basis: "outputs" };
    feeComplete = true;
  } else {
    const added = replacement.inputs.filter((input) => !originalInputs.has(outpointKey(input)));
    // A bare witness_utxo claim is not evidence: only an amount that came
    // from a full previous transaction whose txid matched the outpoint counts.
    const verified = added.every((input) => input.amountVerified === true && input.amount !== null);
    if (verified) {
      const addedTotal = added.reduce((total, input) => total + input.amount, 0n);
      feeIncrease = { sats: addedTotal + sumOutputs(original) - sumOutputs(replacement), basis: "verified-amounts" };
      feeComplete = true;
    } else {
      items.push({ code: "fee-incomplete" });
    }
  }
  if (feeIncrease !== null && feeIncrease.sats <= 0n) {
    items.push({ code: "fee-not-increased", sats: feeIncrease.sats });
  }

  if (original.version !== replacement.version) {
    items.push({ code: "version-changed", before: original.version, after: replacement.version });
  }
  if (original.locktime !== replacement.locktime) {
    items.push({ code: "locktime-changed", before: original.locktime, after: replacement.locktime });
  }
  for (const input of original.inputs) {
    const after = replacementInputs.get(outpointKey(input));
    if (!after) continue;
    if (input.sequence !== after.sequence) {
      items.push({ code: "sequence-changed", txid: input.txid, vout: input.vout, before: input.sequence, after: after.sequence });
    }
    // A raw original carries no sighash field (null); an explicit SIGHASH_ALL
    // in the bump PSBT is the same commitment, not a change.
    const beforeSighash = input.sighash === null ? 1 : input.sighash;
    const afterSighash = after.sighash === null ? 1 : after.sighash;
    if (beforeSighash !== afterSighash) {
      items.push({ code: "sighash-changed", txid: input.txid, vout: input.vout, before: input.sighash, after: after.sighash });
    }
  }
  for (const input of replacement.inputs) {
    if (input.sighash !== null && input.sighash !== 0 && input.sighash !== 1) {
      items.push({ code: "sighash-not-all", txid: input.txid, vout: input.vout, sighash: input.sighash });
    }
  }

  const hasRed = items.some((item) => RED_CODES.has(item.code));
  let verdict = "amber";
  if (hasRed) {
    verdict = "red";
  } else if (
    droppedInputs.length === 0
    && decreaseCount === 1
    && newCount === 0
    && removedCount === 0
    && exactCount === original.outputs.length - 1
    && feeComplete
    && feeIncrease !== null
    && feeIncrease.sats > 0n
    && items.every((item) => GREEN_OK_CODES.has(item.code))
  ) {
    verdict = "green";
  }

  return { verdict, items, addedInputs, droppedInputs, feeIncrease, feeComplete };
};
