// Parses a typed private key held as UTF-8 bytes, for secure entry: the key
// never becomes a string. It never turns the input into a string, never
// changes the input array, zeroes every temporary buffer it makes, and
// returns fresh arrays the caller owns and must zero.
import { base58checkDecodeBytes } from "./base58.js";
import { sha256 } from "./hashes.js";

export class KeyBytesError extends Error {
  constructor(code) {
    super(code);
    this.name = "KeyBytesError";
    this.code = code;
  }
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_BYTES = new Set([...BASE58_ALPHABET].map((character) => character.charCodeAt(0)));

const isAsciiWhitespace = (byte) => byte === 0x20 || (byte >= 0x09 && byte <= 0x0d);

const hexValue = (byte) => {
  if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;
  if (byte >= 0x41 && byte <= 0x46) return byte - 0x41 + 10;
  if (byte >= 0x61 && byte <= 0x66) return byte - 0x61 + 10;
  return -1;
};

// A Casascius mini key: "S", 22/26/30 Base58 characters, and SHA-256 of the
// text plus "?" starting with a zero byte. The hash is a check, never a
// result, so it is zeroed here.
const isMiniKey = (bytes) => {
  if (bytes.length !== 22 && bytes.length !== 26 && bytes.length !== 30) return false;
  if (bytes[0] !== 0x53) return false;
  for (const byte of bytes) if (!BASE58_BYTES.has(byte)) return false;
  const withQuestion = new Uint8Array(bytes.length + 1);
  withQuestion.set(bytes);
  withQuestion[bytes.length] = 0x3f;
  let hash;
  try {
    hash = sha256(withQuestion);
    return hash[0] === 0;
  } finally {
    withQuestion.fill(0);
    if (hash) hash.fill(0);
  }
};

// The shape of a WIF: "5", "K", "L", "9" or "c" then 50 or 51 Base58
// characters. Checked byte by byte, never as a string.
const isWifShape = (bytes) => {
  if (bytes.length !== 51 && bytes.length !== 52) return false;
  const first = bytes[0];
  if (first !== 0x35 && first !== 0x4b && first !== 0x4c && first !== 0x39 && first !== 0x63) return false;
  for (let index = 1; index < bytes.length; index++) if (!BASE58_BYTES.has(bytes[index])) return false;
  return true;
};

// Parses a typed private key held as UTF-8 bytes.
// kind: "wif" | "hex-key" | "minikey" (the Key Station's private-key kinds;
// "brain" is not parsed here). As in hodlSingleKeyWallet, only "minikey" is
// forced; "wif" and "hex-key" both auto-detect WIF or hex.
// Returns { source: "minikey" | "wif" | "hex", priv: Uint8Array(32),
//   compressed: true | false | null, network: "mainnet" | "testnet" | null,
//   minikey: Uint8Array | null }.
export function parsePrivateKeyBytes(input, options) {
  // A null or missing options object means the default kind, never a raw
  // TypeError the caller cannot map.
  const kind = options?.kind ?? "wif";
  if (!(input instanceof Uint8Array)) throw new KeyBytesError("BAD_INPUT");
  if (kind !== "wif" && kind !== "hex-key" && kind !== "minikey") throw new KeyBytesError("BAD_KIND");
  for (const byte of input) if (byte >= 0x80) throw new KeyBytesError("NOT_ASCII");
  let start = 0, end = input.length;
  while (start < end && isAsciiWhitespace(input[start])) start++;
  while (end > start && isAsciiWhitespace(input[end - 1])) end--;
  if (start === end) throw new KeyBytesError("EMPTY");
  const trimmed = input.slice(start, end);
  try {
    const mini = isMiniKey(trimmed);
    if (kind === "minikey" || mini) {
      if (!mini) throw new KeyBytesError("BAD_MINIKEY");
      return { source: "minikey", priv: sha256(trimmed), compressed: null, network: null, minikey: trimmed.slice() };
    }
    if (isWifShape(trimmed)) {
      let payload;
      try {
        payload = base58checkDecodeBytes(trimmed);
      } catch {
        throw new KeyBytesError("BAD_CHECKSUM");
      }
      try {
        if (payload.length !== 33 && payload.length !== 34) throw new KeyBytesError("BAD_WIF_LENGTH");
        const version = payload[0];
        let network;
        if (version === 0x80) network = "mainnet";
        else if (version === 0xef) network = "testnet";
        else throw new KeyBytesError("BAD_WIF_PREFIX");
        let compressed;
        if (payload.length === 34) {
          if (payload[33] !== 0x01) throw new KeyBytesError("BAD_WIF_SUFFIX");
          compressed = true;
        } else {
          compressed = false;
        }
        return { source: "wif", priv: payload.slice(1, 33), compressed, network, minikey: null };
      } finally {
        payload.fill(0);
      }
    }
    const compacted = new Uint8Array(trimmed.length);
    try {
      let length = 0;
      for (const byte of trimmed) if (!isAsciiWhitespace(byte)) compacted[length++] = byte;
      let hexStart = 0;
      if (length >= 2 && compacted[0] === 0x30 && (compacted[1] === 0x78 || compacted[1] === 0x58)) hexStart = 2;
      if (length - hexStart !== 64) throw new KeyBytesError("BAD_FORMAT");
      for (let index = hexStart; index < length; index++) if (hexValue(compacted[index]) < 0) throw new KeyBytesError("BAD_FORMAT");
      const priv = new Uint8Array(32);
      for (let index = 0; index < 32; index++) priv[index] = (hexValue(compacted[hexStart + index * 2]) << 4) | hexValue(compacted[hexStart + index * 2 + 1]);
      return { source: "hex", priv, compressed: null, network: null, minikey: null };
    } finally {
      compacted.fill(0);
    }
  } finally {
    trimmed.fill(0);
  }
}
