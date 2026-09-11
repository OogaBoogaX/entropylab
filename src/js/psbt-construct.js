// Unsigned PSBT constructor. User-supplied prevouts and outputs in; a
// BIP-174 v0 document out. Never signs. Amounts and scripts are claims
// the user typed — they are not fetched from a chain.
import { buildOutputScript } from "./script-builder.js";

export const MAX_MONEY_SATS = 21000000n * 100000000n;
export const DEFAULT_SEQUENCE = 0xfffffffd; // RBF-capable, not final

const isHex = (text) => /^(?:[0-9a-f]{2})*$/i.test(text);

const hexToBytes = (hex) => {
  if (!isHex(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const compactSize = (n) => {
  if (n < 0 || !Number.isInteger(n)) throw new Error("compact-size length must be a non-negative integer.");
  if (n < 253) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  if (n <= 0xffffffff) {
    const out = new Uint8Array(5);
    out[0] = 0xfe;
    for (let i = 0; i < 4; i++) out[1 + i] = (n >>> (8 * i)) & 0xff;
    return out;
  }
  throw new Error("compact-size length is too large.");
};

const u64LeHex = (value) => {
  let n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error("Amount is outside the unsigned 64-bit range.");
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytesToHex(out);
};

export const parseAmountSats = (text) => {
  const raw = String(text ?? "").trim().replace(/_/g, "").replace(/,/g, "");
  if (!raw) throw new Error("Enter an amount in sats or BTC.");
  if (/^\d+$/.test(raw)) {
    const sats = BigInt(raw);
    if (sats > MAX_MONEY_SATS) throw new Error("Amount exceeds Bitcoin's MAX_MONEY.");
    return sats;
  }
  if (!/^\d+(\.\d{1,8})?$/.test(raw)) throw new Error("Amount must be integer sats or BTC with at most 8 decimals.");
  const [whole, frac = ""] = raw.split(".");
  const sats = BigInt(whole) * 100000000n + BigInt(frac.padEnd(8, "0"));
  if (sats > MAX_MONEY_SATS) throw new Error("Amount exceeds Bitcoin's MAX_MONEY.");
  return sats;
};

export const encodeWitnessUtxo = (valueSats, scriptHex) => {
  const script = hexToBytes(String(scriptHex ?? "").trim().toLowerCase());
  const prefix = hexToBytes(u64LeHex(valueSats));
  const size = compactSize(script.length);
  const out = new Uint8Array(prefix.length + size.length + script.length);
  out.set(prefix, 0);
  out.set(size, prefix.length);
  out.set(script, prefix.length + size.length);
  return bytesToHex(out);
};

const parseTxid = (text) => {
  const hex = String(text ?? "").trim().toLowerCase();
  if (!isHex(hex) || hex.length !== 64) throw new Error("Prevout txid must be 32 bytes of hex (64 digits).");
  return hex;
};

const parseVout = (text) => {
  const raw = String(text ?? "").trim();
  if (!/^\d+$/.test(raw)) throw new Error("Vout must be a non-negative integer.");
  const vout = Number(raw);
  if (!Number.isSafeInteger(vout) || vout > 0xffffffff) throw new Error("Vout is out of the 32-bit range.");
  return vout;
};

const parseSequence = (text, fallback = DEFAULT_SEQUENCE) => {
  const raw = String(text ?? "").trim();
  if (!raw) return fallback;
  const n = raw.toLowerCase().startsWith("0x") ? Number.parseInt(raw, 16) : Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error("Sequence must be a 32-bit integer.");
  return n;
};

export const constructUnsignedPsbtDoc = (spec) => {
  const version = spec.version == null ? 2 : Number(spec.version);
  if (!Number.isInteger(version) || version < 1 || version > 2) throw new Error("Transaction version must be 1 or 2.");
  const locktime = spec.locktime == null || spec.locktime === "" ? 0 : Number(spec.locktime);
  if (!Number.isInteger(locktime) || locktime < 0 || locktime > 0xffffffff) throw new Error("Locktime must be a 32-bit integer.");

  const inputsIn = Array.isArray(spec.inputs) ? spec.inputs : [];
  const outputsIn = Array.isArray(spec.outputs) ? spec.outputs : [];
  if (!inputsIn.length) throw new Error("Add at least one input (txid:vout plus the spent script and amount).");
  if (!outputsIn.length) throw new Error("Add at least one output (address or script plus amount).");

  const network = spec.network === "testnet" ? "testnet" : "mainnet";
  const seen = new Set();
  const txInputs = [];
  const inputMaps = [];
  let totalIn = 0n;

  inputsIn.forEach((row, index) => {
    const what = `input ${index}`;
    const txid = parseTxid(row.txid);
    const vout = parseVout(row.vout);
    const key = `${txid}:${vout}`;
    if (seen.has(key)) throw new Error(`${what}: duplicate prevout ${key}.`);
    seen.add(key);
    const value = parseAmountSats(row.value);
    totalIn += value;
    if (totalIn > MAX_MONEY_SATS) throw new Error("Input amounts exceed Bitcoin's MAX_MONEY.");
    const script = buildOutputScript(row.script, { network, mode: row.scriptMode || "auto" });
    const sequence = parseSequence(row.sequence);
    txInputs.push({ txid, vout, scriptSig: "", sequence });
    const pairs = [];
    if (row.attachWitnessUtxo !== false) {
      pairs.push({ key: "01", value: encodeWitnessUtxo(value, script.scriptHex) });
    }
    inputMaps.push(pairs);
  });

  const txOutputs = [];
  const outputMaps = [];
  let totalOut = 0n;
  outputsIn.forEach((row, index) => {
    const what = `output ${index}`;
    const value = parseAmountSats(row.value);
    totalOut += value;
    if (totalOut > MAX_MONEY_SATS) throw new Error(`${what}: output amounts exceed Bitcoin's MAX_MONEY.`);
    const script = buildOutputScript(row.script, { network, mode: row.scriptMode || "auto" });
    txOutputs.push({ value: Number(value), scriptPubKey: script.scriptHex });
    outputMaps.push([]);
  });

  if (totalOut > totalIn) throw new Error("Output amounts exceed claimed input amounts.");

  return {
    tx: { version, locktime, inputs: txInputs, outputs: txOutputs },
    globals: [],
    inputs: inputMaps,
    outputs: outputMaps,
    claimedFeeSats: totalIn - totalOut,
  };
};
