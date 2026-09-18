// BOLT11 invoice decoder for EntropyLab: parses a user-supplied Lightning
// invoice string (lnbc… / lntb… / lntbs… / lnbcrt…) into its fields and
// verifies the payee's recoverable ECDSA signature, recovering the node id
// from it.
//
// Deterministic inspection of user-supplied bytes only: nothing here
// generates entropy, nothing touches the network, and no invoice is ever
// created. The bech32 checksum proves the string survived copy/paste; it
// says nothing about authenticity — only a recovered signature that
// verifies against the invoice contents makes an invoice "signature
// valid", and that is the only success state this module reports.
//
// BOLT11 uses the ORIGINAL bech32 checksum (constant 1), not bech32m, and
// does not inherit segwit's 90-character limit, so the checksum is checked
// here in JS (public data, no secrets) instead of the WASM bech32m path.
import { sha256 } from "./hashes.js";
import { secp256k1 } from "./secp256k1.js";
import { hex } from "./coders.js";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHARKEY = new Map([...CHARSET].map((c, i) => [c, i]));
const MAX_LENGTH = 1023; // same ceiling as the WASM bech32 path
const SIGNATURE_WORDS = 104; // 65 bytes (64-byte compact sig + recovery id)

const fail = (key, vars) => {
  throw { key, vars };
};

// ── bech32 (BOLT11 variant: constant 1, extended length) ───────────────────

const polymod = (values) => {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
  }
  return chk;
};

const hrpExpand = (hrp) => [
  ...[...hrp].map((c) => c.charCodeAt(0) >> 5),
  0,
  ...[...hrp].map((c) => c.charCodeAt(0) & 31),
];

// Returns { hrp, words } (words exclude the 6 checksum words) or fails.
const bech32DecodeBolt11 = (text) => {
  if (typeof text !== "string" || text.length === 0) fail("Paste an invoice first.");
  if (text.length > MAX_LENGTH) fail("This string is too long to be a BOLT11 invoice.");
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) {
    fail("This invoice mixes upper and lower case, which bech32 forbids.");
  }
  const lower = text.toLowerCase();
  for (const c of lower) {
    const code = c.charCodeAt(0);
    if (code < 33 || code > 126) fail("This invoice contains characters outside the bech32 range.");
  }
  const sep = lower.lastIndexOf("1");
  if (sep < 1 || sep + 7 > lower.length) fail("This is not a bech32 string (no valid separator).");
  const hrp = lower.slice(0, sep);
  const words = [];
  for (const c of lower.slice(sep + 1)) {
    const v = CHARKEY.get(c);
    if (v === undefined) fail("This invoice contains characters outside the bech32 alphabet.");
    words.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...words]) !== 1) {
    fail("This invoice's checksum does not verify. It may be truncated, corrupted, or checksummed with bech32m instead of bech32.");
  }
  return { hrp, words: words.slice(0, -6) };
};

// 5-bit words to bytes, discarding leftover bits that only pad the field to
// the 5-bit boundary (tag payloads, fixed-length fields, the signature).
const wordsToBytesTrimmed = (words) => {
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
};

// 5-bit words to bytes, including a final byte zero-padded to the byte
// boundary when the word count does not divide evenly — the form the BOLT11
// signature hashes (hrp || timestamp+tags).
const wordsToBytesPadded = (words) => {
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  if (bits > 0) out.push((acc << (8 - bits)) & 0xff);
  return Uint8Array.from(out);
};

// 5-bit words to bytes, requiring an exact fit (tag payloads).
const wordsToBytes = (words, expectedLength, what) => {
  const bytes = wordsToBytesTrimmed(words);
  if (bytes.length !== expectedLength) {
    fail("The {what} field has the wrong length for a BOLT11 invoice.", { what });
  }
  return bytes;
};

const wordsToInt = (words) => words.reduce((acc, w) => acc * 32 + w, 0);

// ── human-readable part ────────────────────────────────────────────────────

const NETWORKS = { bc: "mainnet", tb: "testnet", tbs: "signet", bcrt: "regtest" };
const MULTIPLIERS = { m: 10n ** 8n, u: 10n ** 5n, n: 10n ** 2n, p: 10n }; // msat per unit

const parseHrp = (hrp) => {
  if (!hrp.startsWith("ln")) fail("This is bech32, but not a Lightning invoice (missing the \"ln\" prefix).");
  const rest = hrp.slice(2);
  const coin = rest.match(/^[a-z]+/)[0];
  const network = NETWORKS[coin];
  if (!network) fail("This invoice is for an unknown network (\"{coin}\").", { coin });
  const amountPart = rest.slice(coin.length);
  if (amountPart === "") return { network, amountMsat: null };
  const match = amountPart.match(/^(\d+)([munp])?$/);
  if (!match) fail("The amount in the invoice prefix is malformed.");
  const amount = BigInt(match[1]);
  const multiplier = match[2];
  if (!multiplier) return { network, amountMsat: (amount * 10n ** 11n).toString() };
  if (amount === 0n) fail("A zero amount must not carry a multiplier.");
  if (multiplier === "p" && amount % 10n !== 0n) fail("The amount has sub-millisatoshi precision, which BOLT11 forbids.");
  return { network, amountMsat: (amount * MULTIPLIERS[multiplier]).toString() };
};

// ── tagged fields ──────────────────────────────────────────────────────────

const TAG_PAYMENT_HASH = 1; // 'p'
const TAG_ROUTE_HINT = 3; // 'r'
const TAG_FEATURES = 5; // '9'
const TAG_EXPIRY = 6; // 'x'
const TAG_FALLBACK = 9; // 'f'
const TAG_DESCRIPTION = 13; // 'd'
const TAG_PAYMENT_SECRET = 16; // 's'
const TAG_NODE_ID = 19; // 'n'
const TAG_DESCRIPTION_HASH = 23; // 'h'
const TAG_MIN_FINAL_CLTV = 24; // 'c'

const ROUTE_HOP_WORDS = 51; // 33-byte pubkey + 8-byte scid + 4 + 4 + 2 fee/cltv

const parseTags = (words) => {
  const out = {
    paymentHash: null,
    description: null,
    descriptionHash: null,
    declaredNodeId: null,
    expiry: null,
    minFinalCltvExpiry: null,
    fallbacks: [],
    routeHintHops: 0,
    paymentSecret: null,
    features: null,
    unknownOddTags: [],
  };
  const seen = new Set();
  let i = 0;
  while (i < words.length) {
    if (i + 3 > words.length) fail("A tagged field in this invoice is truncated.");
    const type = words[i];
    const length = words[i + 1] * 32 + words[i + 2];
    const data = words.slice(i + 3, i + 3 + length);
    if (data.length !== length) fail("A tagged field in this invoice is truncated.");
    i += 3 + length;
    const known = [TAG_PAYMENT_HASH, TAG_ROUTE_HINT, TAG_FEATURES, TAG_EXPIRY, TAG_FALLBACK,
      TAG_DESCRIPTION, TAG_PAYMENT_SECRET, TAG_NODE_ID, TAG_DESCRIPTION_HASH, TAG_MIN_FINAL_CLTV];
    if (!known.includes(type)) {
      if (type % 2 === 0) fail("This invoice has an unknown required field (tag {type}).", { type });
      out.unknownOddTags.push(type);
      continue;
    }
    if (seen.has(type) && type !== TAG_ROUTE_HINT && type !== TAG_FALLBACK) {
      fail("This invoice repeats a field (tag {type}).", { type });
    }
    seen.add(type);
    switch (type) {
      case TAG_PAYMENT_HASH:
        out.paymentHash = hex.encode(wordsToBytes(data, 32, "payment hash"));
        break;
      case TAG_DESCRIPTION:
        out.description = new TextDecoder("utf-8", { fatal: true }).decode(wordsToBytesTrimmed(data));
        break;
      case TAG_DESCRIPTION_HASH:
        out.descriptionHash = hex.encode(wordsToBytes(data, 32, "description hash"));
        break;
      case TAG_NODE_ID:
        out.declaredNodeId = hex.encode(wordsToBytes(data, 33, "node id"));
        break;
      case TAG_EXPIRY:
        out.expiry = wordsToInt(data);
        break;
      case TAG_MIN_FINAL_CLTV:
        out.minFinalCltvExpiry = wordsToInt(data);
        break;
      case TAG_FALLBACK: {
        if (data.length < 1) fail("A fallback address field in this invoice is empty.");
        // A reader MUST skip over fallback fields with an unknown version
        // (17 = P2PKH, 18 = P2SH, 0 = segwit v0 are the defined ones).
        if (data[0] === 17 || data[0] === 18 || data[0] === 0) {
          out.fallbacks.push({ version: data[0], program: hex.encode(wordsToBytesTrimmed(data.slice(1))) });
        }
        break;
      }
      case TAG_ROUTE_HINT:
        if (data.length % ROUTE_HOP_WORDS !== 0) fail("A route hint in this invoice is malformed.");
        out.routeHintHops += data.length / ROUTE_HOP_WORDS;
        break;
      case TAG_PAYMENT_SECRET:
        out.paymentSecret = hex.encode(wordsToBytes(data, 32, "payment secret"));
        break;
      case TAG_FEATURES:
        out.features = hex.encode(wordsToBytesTrimmed(data));
        break;
    }
  }
  return out;
};

// ── top level ──────────────────────────────────────────────────────────────

// Decodes a BOLT11 invoice string. Returns the parsed fields with the
// recovered node id; fails (throws { key, vars }) on any structural or
// signature problem. An invoice is only returned once its recoverable
// signature verifies — a valid checksum alone never reaches the caller.
export const bolt11Decode = (text) => {
  const { hrp, words } = bech32DecodeBolt11(typeof text === "string" ? text.trim() : text);
  const { network, amountMsat } = parseHrp(hrp);
  if (words.length < 7 + SIGNATURE_WORDS) fail("This invoice is too short to contain a signature.");

  const dataWords = words.slice(0, -SIGNATURE_WORDS);
  const sigBytes = wordsToBytesTrimmed(words.slice(-SIGNATURE_WORDS));
  if (sigBytes.length !== 65) fail("This invoice's signature has the wrong length.");
  const signature = sigBytes.slice(0, 64);
  const recoveryId = sigBytes[64];
  if (recoveryId > 3) fail("This invoice's signature recovery id is invalid.");

  const timestamp = wordsToInt(dataWords.slice(0, 7));
  const tags = parseTags(dataWords.slice(7));

  // Required-content rules a BOLT11 reader MUST enforce.
  if (!tags.paymentSecret) fail("This invoice has no payment secret, which BOLT11 requires.");
  if (!tags.description && !tags.descriptionHash) fail("This invoice has neither a description nor a description hash.");
  if (tags.description && tags.descriptionHash) fail("This invoice has both a description and a description hash, which BOLT11 forbids.");

  // The signature covers SHA256(hrp as UTF-8 || timestamp+tags as bytes).
  const hrpBytes = new TextEncoder().encode(hrp);
  const signedBytes = wordsToBytesPadded(dataWords);
  const message = new Uint8Array(hrpBytes.length + signedBytes.length);
  message.set(hrpBytes, 0);
  message.set(signedBytes, hrpBytes.length);
  const msghash = sha256(message);

  let nodeId;
  if (tags.declaredNodeId) {
    // With a declared node id a reader MUST validate against it (no
    // recovery) and MUST reject a non-canonical (high-S) signature.
    const declared = hex.decode(tags.declaredNodeId);
    if (!secp256k1.verify(signature, msghash, declared, { prehash: false })) {
      fail("This invoice's signature does not verify against its declared node id. Do not trust its contents.");
    }
    nodeId = tags.declaredNodeId;
  } else {
    // Without one a reader MUST recover the node id, accepting high-S.
    const nodeIdBytes = secp256k1.recover(msghash, signature, recoveryId);
    if (!nodeIdBytes || !secp256k1.verify(signature, msghash, nodeIdBytes, { prehash: false, lowS: false })) {
      fail("This invoice's signature does not verify. Do not trust its contents.");
    }
    nodeId = hex.encode(nodeIdBytes);
  }

  return {
    kind: "bolt11",
    network,
    amountMsat,
    timestamp,
    nodeId,
    signatureValid: true,
    ...tags,
  };
};
