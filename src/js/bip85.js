// BIP-85: deterministic entropy from a BIP32 root. This is a calculator, not a
// generator — the same parent, application, and index always reproduce the
// same child. HMAC-SHA512(key="bip-entropy-from-k", msg=k) after a fully
// hardened path m/83696968'/{app}'/…; trailing (least significant) bytes are
// truncated, so callers keep the leftmost / most-significant slice.
//
// English BIP-39, HD-seed WIF, XPRV, HEX, and BASE64/BASE85 passwords are
// implemented. RSA, GPG, DRNG, Dice, and Nostr are out of scope here.
import { hmacSha512 } from "./hashes.js";
import { hex as hexCoder, base64 as base64Coder } from "./coders.js";
import { base58checkEncode } from "./base58.js";
import { HDKey } from "./hdkey.js";
import { entropyToMnemonic } from "./bip39.js";
import { wordlist as bip39English } from "./bip39-english.js";

export const BIP85_PURPOSE = 83696968;
export const BIP85_HMAC_KEY = "bip-entropy-from-k";
export const BIP85_APPS = Object.freeze({
  BIP39: 39,
  WIF: 2,
  XPRV: 32,
  HEX: 128169,
  PWD_BASE64: 707764,
  PWD_BASE85: 707785
});
export const BIP39_LANGUAGE_ENGLISH = 0;
export const BIP39_ENTROPY_BYTES_BY_WORD_COUNT = Object.freeze({ 12: 16, 15: 20, 18: 24, 21: 28, 24: 32 });
export const HEX_BYTES_MIN = 16;
export const HEX_BYTES_MAX = 64;
export const PWD_BASE64_MIN = 20;
export const PWD_BASE64_MAX = 86;
export const PWD_BASE85_MIN = 10;
export const PWD_BASE85_MAX = 80;
export const INDEX_MIN = 0;
export const INDEX_MAX = 2147483647;
export const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
// RFC 1924 (IPv6) alphabet used by BIP-85 PWD BASE85. Not Ascii85, not z85.
export const RFC1924_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
export const XPRV_VERSIONS = Object.freeze({
  mainnet: Object.freeze({ private: 0x0488ade4, public: 0x0488b21e }),
  testnet: Object.freeze({ private: 0x04358394, public: 0x043587cf })
});
const INVALID_KEY_MESSAGE = "Derived key is invalid (zero or at/above the secp256k1 curve order). BIP-85 requires a hard fail here; increment the index and derive again.";
const HMAC_KEY_BYTES = new TextEncoder().encode(BIP85_HMAC_KEY);

export function wipeBytes(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
  return bytes;
}

// Parses a plain (unhardened) BIP32 child index; the caller applies the
// hardening. Passing an already-hardened value (>= 2^31) is rejected.
export function parseChildIndex(value, label = "index") {
  let n = typeof value === "number" ? value : Number(String(value ?? "").trim());
  if (!Number.isInteger(n) || n < INDEX_MIN || n > INDEX_MAX) throw new Error(`${label} must be an integer from ${INDEX_MIN} to ${INDEX_MAX}.`);
  return n;
}

export function hardenedPath(indices) {
  if (!Array.isArray(indices) || !indices.length) throw new Error("BIP-85 path needs at least one hardened index.");
  return "m/" + indices.map((value, i) => `${parseChildIndex(value, `path[${i}]`)}'`).join("/");
}

export function bip85Path(app, ...rest) {
  return hardenedPath([BIP85_PURPOSE, app, ...rest]);
}

export function isValidSecp256k1Secret(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return false;
  let n = 0n;
  for (let i = 0; i < 32; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n > 0n && n < SECP256K1_ORDER;
}

export function assertValidSecp256k1Secret(bytes) {
  if (!isValidSecp256k1Secret(bytes)) throw new Error(INVALID_KEY_MESSAGE);
  return bytes;
}

export function deriveBip85Entropy(root, path) {
  if (!root || typeof root.derive !== "function") throw new Error("BIP-85 needs a BIP32 root private key.");
  if (!root.privateKey) throw new Error("BIP-85 needs a BIP32 root private key. Watch-only keys cannot derive children.");
  let child = root.derive(path), key = child.privateKey;
  try {
    if (!key) throw new Error("BIP-85 needs a BIP32 root private key. Watch-only keys cannot derive children.");
    return hmacSha512(HMAC_KEY_BYTES, key);
  } finally {
    wipeBytes(key); // the getter copy
    child.wipePrivateData(); // the node itself (derive already wiped the intermediates)
  }
}

export function truncateEntropy(entropy, numBytes) {
  if (!(entropy instanceof Uint8Array) || entropy.length !== 64) throw new Error("BIP-85 HMAC output must be 64 bytes.");
  if (!Number.isInteger(numBytes) || numBytes < 1 || numBytes > 64) throw new Error("BIP-85 truncation must keep between 1 and 64 leftmost bytes.");
  return entropy.slice(0, numBytes);
}

export function encodeWifCompressed(priv, testnet = false) {
  assertValidSecp256k1Secret(priv);
  let payload = new Uint8Array(34);
  payload[0] = testnet ? 239 : 128;
  payload.set(priv, 1);
  payload[33] = 1;
  try {
    return base58checkEncode(payload);
  } finally {
    wipeBytes(payload);
  }
}

export function encodeXprv(chainCode, privateKey, testnet = false) {
  if (!(chainCode instanceof Uint8Array) || chainCode.length !== 32) throw new Error("XPRV chain code must be 32 bytes.");
  assertValidSecp256k1Secret(privateKey);
  // BIP-85 reverses BIP32's HMAC split: first 32 bytes are chain code, last 32
  // are the private key. Depth, fingerprint, and child number are forced to 0.
  const node = new HDKey({
    versions: testnet ? XPRV_VERSIONS.testnet : XPRV_VERSIONS.mainnet,
    depth: 0,
    index: 0,
    parentFingerprint: 0,
    chainCode,
    privateKey
  });
  try {
    return node.privateExtendedKey;
  } finally {
    node.wipePrivateData();
  }
}

export function encodeRfc1924Base85(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length % 4 !== 0) throw new Error("RFC1924 Base85 encoding requires a multiple of 4 bytes.");
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) {
    let n = (bytes[i] * 2 ** 24 + bytes[i + 1] * 2 ** 16 + bytes[i + 2] * 2 ** 8 + bytes[i + 3]) >>> 0;
    let group = "";
    for (let j = 0; j < 5; j++) {
      group = RFC1924_ALPHABET[n % 85] + group;
      n = Math.floor(n / 85);
    }
    out += group;
  }
  return out;
}

function result(fields) {
  return {
    app: fields.app,
    path: fields.path,
    entropy: fields.entropy,
    entropyHex: hexCoder.encode(fields.entropy),
    secret: fields.secret,
    secretLabel: fields.secretLabel,
    notes: fields.notes || [],
    warnings: fields.warnings || []
  };
}

export function deriveBip39(root, { words = 24, index = 0, language = BIP39_LANGUAGE_ENGLISH } = {}) {
  let wordCount = Number(words);
  let bytes = BIP39_ENTROPY_BYTES_BY_WORD_COUNT[wordCount];
  if (!bytes) throw new Error("BIP-85 BIP39 children are 12, 15, 18, 21, or 24 English words.");
  if (language !== BIP39_LANGUAGE_ENGLISH) throw new Error("This version derives English BIP-39 children only (language code 0').");
  let path = bip85Path(BIP85_APPS.BIP39, language, wordCount, parseChildIndex(index));
  let digest = deriveBip85Entropy(root, path);
  try {
    let entropy = truncateEntropy(digest, bytes);
    return result({
      app: "bip39",
      path,
      entropy,
      secret: entropyToMnemonic(entropy, bip39English),
      secretLabel: `BIP-39 mnemonic · ${wordCount} English words`,
      notes: [`English wordlist (0'). Path ${path}.`]
    });
  } finally {
    wipeBytes(digest); // the 64-byte HMAC outlives its truncated slice
  }
}

export function deriveWif(root, { index = 0, testnet = false } = {}) {
  let path = bip85Path(BIP85_APPS.WIF, parseChildIndex(index));
  let digest = deriveBip85Entropy(root, path);
  try {
    let entropy = truncateEntropy(digest, 32);
    return result({
      app: "wif",
      path,
      entropy,
      secret: encodeWifCompressed(entropy, testnet),
      secretLabel: testnet ? "Compressed WIF · testnet" : "Compressed WIF · mainnet",
      notes: ["Most-significant 256 bits as a compressed WIF hdseed (Bitcoin Core)."]
    });
  } finally {
    wipeBytes(digest);
  }
}

export function deriveXprv(root, { index = 0, testnet = false } = {}) {
  let path = bip85Path(BIP85_APPS.XPRV, parseChildIndex(index));
  let digest = deriveBip85Entropy(root, path);
  let chainCode = digest.slice(0, 32), privateKey = digest.slice(32);
  try {
    // The published BIP "DERIVED ENTROPY" for XPRV is the private-key half.
    let entropy = privateKey.slice();
    return result({
      app: "xprv",
      path,
      entropy,
      secret: encodeXprv(chainCode, privateKey, testnet),
      secretLabel: testnet ? "BIP-32 TPRV" : "BIP-32 XPRV",
      notes: ["HMAC split is reversed from BIP32: first 32 bytes = chain code, last 32 = private key. Depth, fingerprint, and child number are zero."],
      warnings: testnet ? ["Input root is a testnet key, so this child is a tprv."] : []
    });
  } finally {
    wipeBytes(digest);
    wipeBytes(chainCode);
    wipeBytes(privateKey);
  }
}

export function deriveHex(root, { numBytes = 32, index = 0 } = {}) {
  let size = Number(numBytes);
  if (!Number.isInteger(size) || size < HEX_BYTES_MIN || size > HEX_BYTES_MAX) throw new Error(`HEX children are ${HEX_BYTES_MIN} to ${HEX_BYTES_MAX} bytes.`);
  let path = bip85Path(BIP85_APPS.HEX, size, parseChildIndex(index));
  let digest = deriveBip85Entropy(root, path);
  try {
    let entropy = truncateEntropy(digest, size);
    return result({
      app: "hex",
      path,
      entropy,
      secret: hexCoder.encode(entropy),
      secretLabel: `Hex entropy · ${size} bytes`,
      notes: [`Leftmost ${size} bytes of the HMAC (trailing bytes discarded).`]
    });
  } finally {
    wipeBytes(digest);
  }
}

export function derivePwdBase64(root, { length = 21, index = 0 } = {}) {
  let size = Number(length);
  if (!Number.isInteger(size) || size < PWD_BASE64_MIN || size > PWD_BASE64_MAX) throw new Error(`BASE64 passwords are ${PWD_BASE64_MIN} to ${PWD_BASE64_MAX} characters.`);
  let path = bip85Path(BIP85_APPS.PWD_BASE64, size, parseChildIndex(index));
  let digest = deriveBip85Entropy(root, path);
  try {
    // The password encodes all 64 HMAC bytes, so the result keeps its own
    // copy and the digest is wiped like in the other four apps.
    let entropy = digest.slice();
    let encoded = base64Coder.encode(entropy).replace(/\s+/g, "");
    return result({
      app: "pwd-base64",
      path,
      entropy,
      secret: encoded.slice(0, size),
      secretLabel: `Password · Base64 · ${size} characters`,
      notes: ["RFC 4648 Base64 of all 64 HMAC bytes, then sliced to the requested length. Length ≤ 86 so the password never includes padding."]
    });
  } finally {
    wipeBytes(digest);
  }
}

export function derivePwdBase85(root, { length = 12, index = 0 } = {}) {
  let size = Number(length);
  if (!Number.isInteger(size) || size < PWD_BASE85_MIN || size > PWD_BASE85_MAX) throw new Error(`BASE85 passwords are ${PWD_BASE85_MIN} to ${PWD_BASE85_MAX} characters.`);
  let path = bip85Path(BIP85_APPS.PWD_BASE85, size, parseChildIndex(index));
  let digest = deriveBip85Entropy(root, path);
  try {
    let entropy = digest.slice();
    return result({
      app: "pwd-base85",
      path,
      entropy,
      secret: encodeRfc1924Base85(entropy).slice(0, size),
      secretLabel: `Password · RFC1924 Base85 · ${size} characters`,
      notes: ["RFC 1924 Base85 of all 64 HMAC bytes (4-byte groups), then sliced to the requested length."]
    });
  } finally {
    wipeBytes(digest);
  }
}

export function deriveApplication(root, spec = {}) {
  let app = spec.app || "bip39";
  if (app === "bip39") return deriveBip39(root, spec);
  if (app === "wif") return deriveWif(root, spec);
  if (app === "xprv") return deriveXprv(root, spec);
  if (app === "hex") return deriveHex(root, spec);
  if (app === "pwd-base64") return derivePwdBase64(root, spec);
  if (app === "pwd-base85") return derivePwdBase85(root, spec);
  throw new Error("Unknown BIP-85 application.");
}

export function wipeBip85Result(derived) {
  if (!derived) return;
  wipeBytes(derived.entropy);
  derived.entropyHex = "";
  derived.secret = "";
}
