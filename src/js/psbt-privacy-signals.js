// Structural privacy observations for the PSBT Inspector. Commentary only:
// nothing here changes a verdict, a check or whether Inspect is enabled.
// Pure: no DOM, no network, no randomness.

const INPUT_LIMIT = 10000;
const OUTPUT_LIMIT = 10000;
const MAX_EQUAL_GROUPS = 3;

const noSignals = () => ({ available: false, mixedFinalization: false, originGroups: 0, equalOutputs: [] });

// Exactly the rule of hodlFinalized in app.js: the consensus layer reads only
// the exact one-byte key, so `07aa`/`08aa` lookalikes must not count.
const isFinalized = (entries) =>
  Array.isArray(entries) &&
  entries.some((entry) => entry && (entry.type === 7 || entry.type === 8) && entry.keydata && entry.keydata.length === 0);

const readCompactSize = (bytes, offset) => {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  if (first < 0xfd) return { value: first, next: offset + 1 };
  const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (offset + 1 + size > bytes.length) return null;
  let value = 0;
  for (let i = 0; i < size; i++) value += bytes[offset + 1 + i] * 2 ** (8 * i);
  return { value, next: offset + 1 + size };
};

const fingerprintAt = (bytes, offset) => {
  let out = "";
  for (let i = 0; i < 4; i++) out += bytes[offset + i].toString(16).padStart(2, "0");
  return out;
};

const fingerprintsOf = (entries) => {
  const found = [];
  if (!Array.isArray(entries)) return found;
  for (const entry of entries) {
    if (!entry || !(entry.val instanceof Uint8Array)) continue;
    const val = entry.val;
    if (entry.type === 6) {
      if (val.length < 4) continue;
      found.push(fingerprintAt(val, 0));
    } else if (entry.type === 0x16) {
      const size = readCompactSize(val, 0);
      if (!size) continue;
      const offset = size.next + size.value * 32;
      if (!Number.isSafeInteger(offset) || offset + 4 > val.length) continue;
      found.push(fingerprintAt(val, offset));
    }
  }
  return found;
};

const countOriginGroups = (inputs) => {
  const parent = inputs.map((_, index) => index);
  const find = (index) => {
    while (parent[index] !== index) {
      parent[index] = parent[parent[index]];
      index = parent[index];
    }
    return index;
  };
  const union = (a, b) => {
    const rootA = find(a);
    const rootB = find(b);
    if (rootA !== rootB) parent[rootB] = rootA;
  };
  const owner = new Map();
  const carries = new Array(inputs.length).fill(false);
  inputs.forEach((entries, index) => {
    for (const fingerprint of fingerprintsOf(entries)) {
      carries[index] = true;
      if (owner.has(fingerprint)) union(owner.get(fingerprint), index);
      else owner.set(fingerprint, index);
    }
  });
  const roots = new Set();
  inputs.forEach((_, index) => {
    if (carries[index]) roots.add(find(index));
  });
  return roots.size;
};

// The Inspector's tx.outputs carry `amount` as a bigint; a decimal `value`
// is accepted too so a parser shape change cannot silently disable the
// section. Anything else is ignored, never guessed.
const amountOf = (output) => {
  if (!output || typeof output !== "object") return null;
  if (typeof output.amount === "bigint") return output.amount;
  if (typeof output.amount === "number" && Number.isSafeInteger(output.amount) && output.amount >= 0) return BigInt(output.amount);
  if (typeof output.value === "bigint") return output.value;
  if (typeof output.value === "string" && /^\d+$/.test(output.value)) return BigInt(output.value);
  return null;
};

const countEqualOutputs = (outputs) => {
  const counts = new Map();
  for (const output of outputs) {
    const amount = amountOf(output);
    if (amount === null || amount === 0n) continue;
    counts.set(amount, (counts.get(amount) || 0) + 1);
  }
  const groups = [];
  for (const [amount, count] of counts) {
    if (count >= 2) groups.push({ amount, count });
  }
  groups.sort((a, b) => b.count - a.count || (a.amount < b.amount ? 1 : a.amount > b.amount ? -1 : 0));
  return groups.slice(0, MAX_EQUAL_GROUPS);
};

export function psbtPrivacySignals({ inputs = null, outputs = [] } = {}) {
  if (!Array.isArray(outputs) || outputs.length > OUTPUT_LIMIT) return noSignals();
  if (inputs !== null && (!Array.isArray(inputs) || inputs.length > INPUT_LIMIT)) return noSignals();
  const equalOutputs = countEqualOutputs(outputs);
  if (inputs === null) return { available: false, mixedFinalization: false, originGroups: 0, equalOutputs };
  const finalized = inputs.map(isFinalized);
  const mixedFinalization = finalized.some(Boolean) && finalized.some((value) => !value);
  return { available: true, mixedFinalization, originGroups: countOriginGroups(inputs), equalOutputs };
}
