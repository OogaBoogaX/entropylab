// Classifies the raw bytes of a scanned QR code before any text decoding.
// The caller owns `bytes`; the returned `indices` are the caller's too. Every
// other buffer this module creates is zeroed before it returns.
//
// Security contract: a payload is reported as a seed only when its exact
// length, alphabet and BIP39 checksum all hold, a WIF only when its base58
// checksum and version byte hold, and anything else is reported as "unknown"
// with its length alone — the bytes are never echoed, repaired or guessed at.

import { bip39English, entropyFromWordIndices, indicesFromEntropy } from "./bip39.js";
import { parsePrivateKeyBytes } from "./key-bytes.js";

const STANDARD_LENGTHS = new Set([48, 96]);
const COMPACT_LENGTHS = new Set([16, 32]);
const WIF_LENGTHS = new Set([51, 52]);
const WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_BYTES = (() => {
  const table = new Uint8Array(128);
  for (let i = 0; i < BASE58_ALPHABET.length; i += 1) table[BASE58_ALPHABET.charCodeAt(i)] = 1;
  return table;
})();

const strictTextDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const isDigit = (byte) => byte >= 0x30 && byte <= 0x39;
const isBase58 = (byte) => byte < 128 && BASE58_BYTES[byte] === 1;

const wipe = (buffer) => {
  try {
    if (ArrayBuffer.isView(buffer)) new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).fill(0);
    else if (buffer instanceof ArrayBuffer) new Uint8Array(buffer).fill(0);
  } catch {
    // A detached buffer holds nothing to wipe.
  }
};

const allBytes = (bytes, predicate) => {
  for (let i = 0; i < bytes.length; i += 1) if (!predicate(bytes[i])) return false;
  return true;
};

// The BIP39 checksum, checked by round-tripping the indices through the
// entropy they encode: a wrong checksum cannot survive the trip, whether or
// not entropyFromWordIndices validates it itself.
const checksumValid = (indices) => {
  let entropy = null;
  let again = null;
  try {
    entropy = entropyFromWordIndices(indices);
    if (!(entropy instanceof Uint8Array)) return false;
    again = indicesFromEntropy(entropy);
    if (again.length !== indices.length) return false;
    for (let i = 0; i < indices.length; i += 1) if (again[i] !== indices[i]) return false;
    return true;
  } catch {
    return false;
  } finally {
    if (entropy) wipe(entropy);
    if (again) wipe(again);
  }
};

const classifyStandard = (bytes) => {
  if (!STANDARD_LENGTHS.has(bytes.length)) return null;
  if (!allBytes(bytes, isDigit)) return null;
  const count = bytes.length / 4;
  const indices = new Uint16Array(count);
  for (let i = 0; i < count; i += 1) {
    const offset = i * 4;
    const index =
      (bytes[offset] - 0x30) * 1000 +
      (bytes[offset + 1] - 0x30) * 100 +
      (bytes[offset + 2] - 0x30) * 10 +
      (bytes[offset + 3] - 0x30);
    if (index > 2047) {
      wipe(indices);
      return null;
    }
    indices[i] = index;
  }
  if (!checksumValid(indices)) {
    wipe(indices);
    return null;
  }
  return { format: "standard-seedqr", words: count, indices };
};

// Valid UTF-8 with no control characters other than tab, line feed and
// carriage return is text (digits, hex, a password, a label in any language),
// not raw entropy. A trailing newline left "my password!123\n" reading as
// CompactSeedQR entropy (red-team sweep 0eed735, qr-payload #5).
const isText = (bytes) => {
  let text;
  try {
    text = strictTextDecoder.decode(bytes);
  } catch {
    return false;
  }
  for (const character of text) {
    const code = character.codePointAt(0);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || (code >= 0x7f && code <= 0x9f)) return false;
  }
  return true;
};

const classifyCompact = (bytes) => {
  if (!COMPACT_LENGTHS.has(bytes.length)) return null;
  // Text is refused (fail closed) rather than read as a seed. Random 16-byte
  // entropy is valid control-free UTF-8 well under one time in a million.
  if (isText(bytes)) return null;
  return { format: "compact-seedqr", words: bytes.length === 16 ? 12 : 24, indices: indicesFromEntropy(bytes) };
};

const classifyWif = (bytes) => {
  if (!WIF_LENGTHS.has(bytes.length)) return null;
  if (!allBytes(bytes, isBase58)) return null;
  const copy = bytes.slice();
  let parsed = null;
  try {
    parsed = parsePrivateKeyBytes(copy, { kind: "wif" });
    if (!parsed || parsed.source !== "wif") return null;
    return { format: "wif", network: parsed.network, compressed: parsed.compressed, bytes: bytes.slice() };
  } catch {
    return null;
  } finally {
    try { parsed?.priv?.fill(0); } catch {}
    try { parsed?.minikey?.fill(0); } catch {}
    try { copy.fill(0); } catch {}
  }
};

// The English wordlist as bytes, sorted by byte order, for matching a words
// QR without decoding it: the decoded text and its split words were the scan
// path's only string copies of the mnemonic, and no wipe can clear a string
// (red-team sweep 0eed735, qr-payload #3). The words are ASCII.
const WORD_ENTRIES = bip39English
  .map((word, index) => ({ bytes: Uint8Array.from(word, (character) => character.charCodeAt(0)), index }))
  .sort((a, b) => compareBytes(a.bytes, 0, a.bytes.length, b.bytes));
function compareBytes(bytes, start, end, word) {
  const length = end - start;
  for (let i = 0; i < length && i < word.length; i += 1) {
    if (bytes[start + i] !== word[i]) return bytes[start + i] - word[i];
  }
  return length - word.length;
}
// The wordlist index of bytes[start, end), or -1.
const wordIndexAt = (bytes, start, end) => {
  let low = 0, high = WORD_ENTRIES.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1, order = compareBytes(bytes, start, end, WORD_ENTRIES[mid].bytes);
    if (!order) return WORD_ENTRIES[mid].index;
    if (order < 0) high = mid - 1;
    else low = mid + 1;
  }
  return -1;
};

// Words separated by single spaces, matched byte for byte: a non-ASCII or
// invalid UTF-8 byte, an empty word or any other separator matches no word,
// as the decoded text's split did.
const classifyWords = (bytes) => {
  let count = 1;
  for (const byte of bytes) if (byte === 0x20) count += 1;
  if (!WORD_COUNTS.has(count)) return null;
  const indices = new Uint16Array(count);
  let start = 0, at = 0;
  for (let i = 0; i <= bytes.length; i += 1) {
    if (i < bytes.length && bytes[i] !== 0x20) continue;
    const index = wordIndexAt(bytes, start, i);
    if (index < 0) {
      wipe(indices);
      return null;
    }
    indices[at++] = index;
    start = i + 1;
  }
  if (!checksumValid(indices)) {
    wipe(indices);
    return null;
  }
  return { format: "words", words: count, indices };
};

export function classifyQrPayload(bytes, { network } = {}) {
  // `network` is the caller's context; a WIF's version byte is what decides
  // the network reported below, so it never reinterprets the payload.
  if (!(bytes instanceof Uint8Array)) return { format: "unknown", length: 0 };
  return (
    classifyStandard(bytes) ??
    classifyCompact(bytes) ??
    classifyWif(bytes) ??
    classifyWords(bytes) ?? { format: "unknown", length: bytes.length }
  );
}
