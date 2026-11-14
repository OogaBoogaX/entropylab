// bech32m for EntropyLab, backed by rust-bitcoin's bech32 crate compiled to
// WebAssembly (Rust crate in entropylab-wasm/, loaded by entropylab-wasm.js).
//
// Drop-in replacement for the slice of @scure/base the app uses for BIP352
// silent payment addresses: word-level bech32m encode/decode with the
// extended 1023-character limit (the bech32 crate's CODE_LENGTH for Bech32m).
// convertbits (toWords/fromWords) stays here in JS — it is pure bit
// reshaping, not cryptography.
import { heap, wasmExports as wasm, withInput } from "./entropylab-wasm.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// Decode buffer for the human-readable part. BIP-173 allows 1–83 characters,
// so size for the standard, not only the app's own short HRPs ("sp", "bc", …).
const HRP_CAP = 84;
const WORDS_CAP = 1024;
const STRING_CAP = 1024;

// 8-bit bytes -> 5-bit words with padding (scure's bech32m.toWords).
export const toWords = (bytes) => {
  let acc = 0, bits = 0;
  const out = [];
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
};

// 5-bit words -> 8-bit bytes without padding (scure's bech32m.fromWords).
export const fromWords = (words) => {
  let acc = 0, bits = 0;
  const out = [];
  for (const word of words) {
    acc = (acc << 5) | word;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) throw new Error("Invalid padding in bech32 data.");
  return new Uint8Array(out);
};

export const bech32mEncode = (hrp, words) => {
  if (typeof hrp !== "string" || !hrp) throw new Error("bech32m hrp must be a non-empty string.");
  if (!Array.isArray(words) && !ArrayBuffer.isView(words)) throw new Error("bech32m words must be an array of integers 0..31.");
  // Validate in place: Array.from(words) would keep a second unwiped copy of
  // the private-key bits carried by spscan/spspend word arrays (AR-07).
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (!Number.isInteger(word) || word < 0 || word > 31) throw new Error("bech32m word values must be integers 0..31.");
  }
  const hrpBytes = textEncoder.encode(hrp);
  const wordBytes = Uint8Array.from(words);
  // Word arrays for spscan/spspend carry private-key bits; the 5-bit copy
  // handed to WASM is zeroed once the call returns (audit follow-up).
  try {
    const out = withInput(hrpBytes, (h) =>
      withInput(wordBytes, (w) => {
        const outPtr = wasm().el_alloc(STRING_CAP);
        try {
          const length = wasm().el_bech32m_encode(h, hrpBytes.length, w, wordBytes.length, outPtr, STRING_CAP);
          if (length < 0) return null;
          // The encoded string is the result; its UTF-8 byte copy carries the
          // same private-key bits (spscan/spspend) and is erased here
          // (RT-JSBOUNDARY-1).
          const encoded = heap().slice(outPtr, outPtr + length);
          try {
            return textDecoder.decode(encoded);
          } finally {
            encoded.fill(0);
          }
        } finally {
          wasm().el_free(outPtr, STRING_CAP);
        }
      })
    );
    if (!out) throw new Error("bech32m encoding failed (bad hrp or word values).");
    return out;
  } finally {
    wordBytes.fill(0);
    hrpBytes.fill(0);
  }
};

// Returns { prefix, words } like scure's decodeUnsafe, or null on any
// checksum/format error. Callers lowercase first (bech32 rejects mixed case).
// The WASM packs its two outputs into one return: hrp_len + (wordCount << 12).
export const bech32mDecode = (text) => {
  if (typeof text !== "string" || !text) return null;
  const bytes = textEncoder.encode(text);
  try {
    return withInput(bytes, (p) => {
      const hrpPtr = wasm().el_alloc(HRP_CAP);
      const wordsPtr = wasm().el_alloc(WORDS_CAP);
      try {
        const packed = wasm().el_bech32m_decode(p, bytes.length, hrpPtr, HRP_CAP, wordsPtr, WORDS_CAP);
        if (packed < 0) return null;
        const hrpLen = packed & 0xfff;
        const wordCount = packed >> 12;
        // Both outputs arrive as byte copies. The number array returned to the
        // caller owns the decoded words; these two copies carry the same bits
        // and are erased before returning (RT-JSBOUNDARY-1).
        const hrpOut = heap().slice(hrpPtr, hrpPtr + hrpLen);
        const wordsOut = heap().slice(wordsPtr, wordsPtr + wordCount);
        try {
          return {
            prefix: textDecoder.decode(hrpOut).toLowerCase(),
            words: Array.from(wordsOut),
          };
        } finally {
          hrpOut.fill(0);
          wordsOut.fill(0);
        }
      } finally {
        wasm().el_free(hrpPtr, HRP_CAP);
        wasm().el_free(wordsPtr, WORDS_CAP);
      }
    });
  } finally {
    bytes.fill(0);
  }
};
