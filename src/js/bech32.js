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

const HRP_CAP = 16; // "sp" / "tsp" / "spscan" / "spspend" / "tspscan" / "tspspend" / "bc" / "tb"
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
  const hrpBytes = textEncoder.encode(hrp);
  const wordBytes = Uint8Array.from(words);
  const out = withInput(hrpBytes, (h) =>
    withInput(wordBytes, (w) => {
      const outPtr = wasm().el_alloc(STRING_CAP);
      try {
        const length = wasm().el_bech32m_encode(h, hrpBytes.length, w, wordBytes.length, outPtr, STRING_CAP);
        return length < 0 ? null : textDecoder.decode(heap().slice(outPtr, outPtr + length));
      } finally {
        wasm().el_free(outPtr, STRING_CAP);
      }
    })
  );
  if (!out) throw new Error("bech32m encoding failed (bad hrp or word values).");
  return out;
};

// Returns { prefix, words } like scure's decodeUnsafe, or null on any
// checksum/format error. Callers lowercase first (bech32 rejects mixed case).
// The WASM packs its two outputs into one return: hrp_len + (wordCount << 12).
export const bech32mDecode = (text) => {
  if (typeof text !== "string" || !text) return null;
  const bytes = textEncoder.encode(text);
  return withInput(bytes, (p) => {
    const hrpPtr = wasm().el_alloc(HRP_CAP);
    const wordsPtr = wasm().el_alloc(WORDS_CAP);
    try {
      const packed = wasm().el_bech32m_decode(p, bytes.length, hrpPtr, HRP_CAP, wordsPtr, WORDS_CAP);
      if (packed < 0) return null;
      const hrpLen = packed & 0xfff;
      const wordCount = packed >> 12;
      return {
        prefix: textDecoder.decode(heap().slice(hrpPtr, hrpPtr + hrpLen)),
        words: Array.from(heap().slice(wordsPtr, wordsPtr + wordCount)),
      };
    } finally {
      wasm().el_free(hrpPtr, HRP_CAP);
      wasm().el_free(wordsPtr, WORDS_CAP);
    }
  });
};
