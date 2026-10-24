// Cryptographic hashes for EntropyLab, backed by bitcoin_hashes compiled to
// WebAssembly (Rust crate in entropylab-wasm/, loaded by entropylab-wasm.js).
//
// Drop-in replacement for the slice of @noble/hashes the app uses: sha256,
// sha512, ripemd160, hash160, HMAC-SHA-512, and PBKDF2-HMAC-SHA-512. Every
// function is synchronous and takes/returns Uint8Array, exactly like noble.
// Loading semantics are the shared loader's: browsers must await wasmReady
// (re-exported as hashesReady) before calling; Node initializes at import.
import { wasmExports as wasm, wasmReady, withInput, withOutput } from "./entropylab-wasm.js";

export const hashesReady = wasmReady;

const assertBytes = (bytes, what) => {
  if (!(bytes instanceof Uint8Array)) throw new Error(`${what} must be a Uint8Array.`);
};

// noble's hmac(sha512, key, ...messages) takes message chunks; every caller
// here passes one, and the boundary takes a single buffer, so chunks are
// concatenated JS-side.
const concatBytes = (...chunks) => {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

export const sha256 = (bytes) => {
  assertBytes(bytes, "SHA-256 input");
  return withInput(bytes, (p) => withOutput(32, (out) => wasm().el_sha256(p, bytes.length, out)));
};

export const sha512 = (bytes) => {
  assertBytes(bytes, "SHA-512 input");
  return withInput(bytes, (p) => withOutput(64, (out) => wasm().el_sha512(p, bytes.length, out)));
};

export const ripemd160 = (bytes) => {
  assertBytes(bytes, "RIPEMD-160 input");
  return withInput(bytes, (p) => withOutput(20, (out) => wasm().el_ripemd160(p, bytes.length, out)));
};

// RIPEMD-160(SHA-256(x)) — the Bitcoin address hash.
export const hash160 = (bytes) => {
  assertBytes(bytes, "HASH160 input");
  return withInput(bytes, (p) => withOutput(20, (out) => wasm().el_hash160(p, bytes.length, out)));
};

export const hmacSha512 = (key, ...messages) => {
  assertBytes(key, "HMAC key");
  const message = concatBytes(...messages);
  try {
    return withInput(key, (k) =>
      withInput(message, (m) => withOutput(64, (out) => wasm().el_hmac_sha512(k, key.length, m, message.length, out)))
    );
  } finally {
    // BIP85 passes the child private key as the message; the WASM copy is
    // zeroed by el_free, but this JS copy is not.
    message.fill(0);
  }
};

// RFC 2898 over HMAC-SHA-512 (BIP39 seeds, Electrum seeds). `iterations` is
// caller-fixed; this module never invents parameters.
export const pbkdf2Sha512 = (password, salt, iterations, dkLen = 64) => {
  assertBytes(password, "PBKDF2 password");
  assertBytes(salt, "PBKDF2 salt");
  if (!Number.isSafeInteger(iterations) || iterations < 1) throw new Error("PBKDF2 iterations must be a positive integer.");
  if (!Number.isSafeInteger(dkLen) || dkLen < 1 || dkLen > 4096) throw new Error("PBKDF2 dkLen must be between 1 and 4096 bytes.");
  return withInput(password, (p) =>
    withInput(salt, (s) => withOutput(dkLen, (out) => wasm().el_pbkdf2_hmac_sha512(p, password.length, s, salt.length, iterations, out, dkLen)))
  );
};
