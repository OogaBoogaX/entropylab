// Base58Check for EntropyLab, backed by rust-bitcoin's base58ck compiled to
// WebAssembly (Rust crate in entropylab-wasm/, loaded by entropylab-wasm.js).
//
// Drop-in replacement for the slice of @scure/base the app uses for
// Base58Check: encode(bytes) -> string, decode(string) -> bytes with the
// checksum verified. WIF keys and extended keys both ride on this.
import { wasmExports as wasm, withInput, withOutput } from "./entropylab-wasm.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// A 78-byte extended key encodes to <= 112 chars; 512 is generous for every
// payload the app encodes (extended keys, WIF) and a hard ceiling elsewhere.
const ENCODE_CAP = 512;
const DECODE_CAP = 512;

export const base58checkEncode = (payload) => {
  if (!(payload instanceof Uint8Array)) throw new Error("Base58Check payload must be a Uint8Array.");
  const out = withInput(payload, (p) => withOutput(ENCODE_CAP, (o) => wasm().el_b58check_encode(p, payload.length, o, ENCODE_CAP)));
  if (!out) throw new Error("Base58Check payload is too large.");
  // `out` encodes a WIF or an extended key. The string is the result; the
  // bytes are a second copy of the same key material and are the only part
  // that can be erased, so erase them (RT-JSBOUNDARY-1).
  try {
    return textDecoder.decode(out);
  } finally {
    out.fill(0);
  }
};

export const base58checkDecode = (text) => {
  if (typeof text !== "string") throw new Error("Base58Check input must be a string.");
  const bytes = textEncoder.encode(text);
  try {
    return base58checkDecodeBytes(bytes);
  } finally {
    bytes.fill(0);
  }
};

// The same decode from ASCII bytes the caller owns (a vault's copy), so a WIF
// never becomes a string. The input is left as it was; the result is a fresh
// array the caller owns.
export const base58checkDecodeBytes = (bytes) => {
  if (!(bytes instanceof Uint8Array)) throw new Error("Base58Check input must be a Uint8Array.");
  const out = withInput(bytes, (p) => withOutput(DECODE_CAP, (o) => wasm().el_b58check_decode(p, bytes.length, o, DECODE_CAP)));
  if (!out) throw new Error("Invalid Base58Check string.");
  return out;
};
