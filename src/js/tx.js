// Raw Bitcoin transaction parser for EntropyLab inspect.
// Used when the paste is a signed (or unsigned) transaction, not a PSBT.
//
// The consensus decode runs on rust-bitcoin's Transaction in the WASM module
// (entropylab-wasm); this file reshapes the flat layout it emits and keeps
// the app's guardrails (size caps, the witness-flag rule, the trailing-byte
// rule) and error strings.
import { heap, wasmExports as wasm, withInput } from "./entropylab-wasm.js";

const ORD_MAGIC = Uint8Array.of(0x00, 0x63, 0x03, 0x6f, 0x72, 0x64); // OP_FALSE OP_IF "ord"

function containsOrdEnvelope(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < ORD_MAGIC.length) return false;
  outer: for (let i = 0; i <= bytes.length - ORD_MAGIC.length; i++) {
    for (let j = 0; j < ORD_MAGIC.length; j++) {
      if (bytes[i + j] !== ORD_MAGIC[j]) continue outer;
    }
    return true;
  }
  return false;
}

function looksLikeDerSig(bytes) {
  if (!bytes || bytes.length < 9 || bytes[0] !== 0x30) return false;
  const body = bytes[1];
  if (body >= 0x80) return false;
  return 2 + body + 1 === bytes.length || 2 + body === bytes.length;
}

function looksLikePubkey(bytes) {
  if (!bytes) return false;
  if (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) return true;
  if (bytes.length === 65 && bytes[0] === 4) return true;
  return false;
}

export function scriptPushes(script) {
  if (!(script instanceof Uint8Array)) return [];
  const pushes = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    if (op === 0x00) {
      pushes.push(new Uint8Array());
      continue;
    }
    if (op <= 0x4b) {
      if (i + op > script.length) break;
      pushes.push(script.slice(i, i + op));
      i += op;
      continue;
    }
    if (op === 0x4c) {
      if (i >= script.length) break;
      const length = script[i++];
      if (i + length > script.length) break;
      pushes.push(script.slice(i, i + length));
      i += length;
      continue;
    }
    if (op === 0x4d) {
      if (i + 2 > script.length) break;
      const length = script[i] | (script[i + 1] << 8);
      i += 2;
      if (i + length > script.length) break;
      pushes.push(script.slice(i, i + length));
      i += length;
      continue;
    }
  }
  return pushes;
}

function sigFromBytes(bytes, inputIndex) {
  if (!looksLikeDerSig(bytes)) return null;
  const hasSighash = bytes.length === 2 + bytes[1] + 1;
  const der = hasSighash ? bytes.slice(0, -1) : bytes;
  // No sighash byte appended to the DER => the sighash type is unknown here,
  // not SIGHASH_ALL; do not invent one.
  const sighash = hasSighash ? bytes[bytes.length - 1] : null;
  return { input: inputIndex, der, sighash, raw: bytes, pubkey: null };
}

function collectSigs(items, inputIndex, signatures) {
  let pending = null;
  for (const item of items) {
    const sig = sigFromBytes(item, inputIndex);
    if (sig) {
      if (pending) signatures.push(pending);
      pending = sig;
      continue;
    }
    if (pending && looksLikePubkey(item)) {
      pending.pubkey = item;
      signatures.push(pending);
      pending = null;
      continue;
    }
  }
  if (pending) signatures.push(pending);
}

// Cursor over the flat little-endian layout el_tx_parse emits. This is not a
// consensus parser — it only reshapes bytes the WASM already validated.
const layoutReader = (bytes) => {
  let offset = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = () => {
    const value = view.getUint32(offset, true);
    offset += 4;
    return value;
  };
  const take = (n) => {
    const out = bytes.slice(offset, offset + n);
    offset += n;
    return out;
  };
  return { u32, take };
};

// Serializes the { version, inputs, outputs, locktime } shape back to wire
// bytes (no witness — the PSBT unsigned transaction never has one). Used when
// the tx was synthesized from PSBT v2 fields and has no `raw`.
export function serializeTx(tx) {
  const out = [];
  const u32 = (v) => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];
  const varint = (n) => (n < 0xfd ? [n] : n < 0x10000 ? [0xfd, n & 255, (n >>> 8) & 255] : [0xfe, ...u32(n)]);
  out.push(...u32(tx.version >>> 0));
  out.push(...varint(tx.inputs.length));
  for (const input of tx.inputs) {
    const script = input.scriptSig ?? input.script ?? new Uint8Array();
    out.push(...input.txid, ...u32(input.vout), ...varint(script.length), ...script, ...u32(input.sequence));
  }
  out.push(...varint(tx.outputs.length));
  for (const output of tx.outputs) {
    let amount = BigInt(output.amount);
    for (let i = 0; i < 8; i++) {
      out.push(Number(amount & 255n));
      amount >>= 8n;
    }
    out.push(...varint(output.script.length), ...output.script);
  }
  out.push(...u32(tx.locktime >>> 0));
  return new Uint8Array(out);
}

export function parseRawTx(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("Transaction must be bytes.");
  if (bytes.length < 10) throw new Error("That is too short to be a Bitcoin transaction.");
  if (bytes.length > 5e6) throw new Error("This transaction is too large to inspect safely.");
  // BIP144: a zero marker must be followed by flag 0x01 (kept from the
  // previous parser; rust-bitcoin would decode other flags).
  if (bytes[4] === 0x00 && bytes.length > 5 && bytes[5] !== 0x01) throw new Error("Unknown witness flag.");
  const cap = bytes.length * 2 + 65536;
  const { code, body } = withInput(bytes, (p) => {
    const outPtr = wasm().el_alloc(cap);
    try {
      const produced = wasm().el_tx_parse(p, bytes.length, outPtr, cap);
      return { code: produced, body: produced > 0 ? heap().slice(outPtr, outPtr + produced) : null };
    } finally {
      wasm().el_free(outPtr, cap);
    }
  });
  if (code === -2) throw new Error("Transaction contains trailing bytes.");
  if (!body) throw new Error("Transaction ended early.");
  const r = layoutReader(body);
  const version = r.u32();
  const segwit = r.take(1)[0] === 1;
  const inputCount = r.u32();
  if (inputCount > 1e5) throw new Error("Transaction has too many inputs.");
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = r.take(32);
    const vout = r.u32();
    const scriptSig = r.take(r.u32());
    const sequence = r.u32();
    const witness = [];
    const stackCount = r.u32();
    for (let j = 0; j < stackCount; j++) witness.push(r.take(r.u32()));
    inputs.push({ txid, vout, scriptSig, sequence, witness });
  }
  const outputCount = r.u32();
  if (outputCount > 1e5) throw new Error("Transaction has too many outputs.");
  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    let amount = 0n;
    const amountBytes = r.take(8);
    for (let j = 0; j < 8; j++) amount |= BigInt(amountBytes[j]) << BigInt(8 * j);
    outputs.push({ amount, script: r.take(r.u32()) });
  }
  const locktime = r.u32();
  return { version, segwit, inputs, outputs, locktime, raw: bytes };
}

export function extractEcdsaSignatures(tx) {
  const signatures = [];
  (tx.inputs || []).forEach((input, index) => {
    collectSigs(scriptPushes(input.scriptSig || new Uint8Array()), index, signatures);
    collectSigs(input.witness || [], index, signatures);
  });
  return signatures;
}

export function inscriptionHints(tx) {
  const hits = [];
  (tx.inputs || []).forEach((input, index) => {
    const scripts = [input.scriptSig, ...(input.witness || [])].filter(Boolean);
    for (const script of scripts) {
      if (containsOrdEnvelope(script)) {
        hits.push({ input: index, scriptBytes: script.length });
        break;
      }
    }
  });
  return hits;
}

export function isPsbtMagic(bytes) {
  return Boolean(bytes && bytes.length >= 5 && bytes[0] === 0x70 && bytes[1] === 0x73 && bytes[2] === 0x62 && bytes[3] === 0x74 && bytes[4] === 0xff);
}

export { containsOrdEnvelope };
