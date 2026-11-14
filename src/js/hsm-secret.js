// Core Lightning hsm_secret support (type 2: BIP-39 mnemonic, no passphrase).
//
// CLN writes a mnemonic hsm_secret as 32 zero bytes (the "no passphrase"
// marker) followed by the English BIP-39 words; a nonzero 32-byte prefix
// means the words are protected by a passphrase (type 3), which this module
// refuses. The node identity and the on-chain descriptors are reproduced
// exactly as hsmd derives them (common/hsm_secret.c and hsmd/libhsmd.c at
// v26.06.9):
//
//  * node key: RFC 5869 HKDF-SHA256 over the first 32 bytes of the 64-byte
//    BIP-39 seed, salt = a little-endian counter, info = "nodeid", retried
//    with the next counter until the output is a valid secp256k1 key;
//  * descriptors: the BIP86 account key m/86'/0'/0' from the full 64-byte
//    seed (no HKDF), printed as wpkh / sh(wpkh) / tr over the same xpub.
//
// Deterministic transformations of user input only: nothing here generates
// entropy. Every secret byte buffer is zeroed before returning; the mnemonic
// and other JS strings cannot be wiped, so wiping those is best effort, as
// elsewhere in the app.
import { HDKey } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { sha256 } from "./hashes.js";
import { descriptorChecksum } from "./core-importdescriptors.js";
import { secp256k1 } from "./secp256k1.js";
import { hex } from "./coders.js";

// ── hsm_secret type detection (common/hsm_secret.c) ─────────────────────────

export const HSM_SECRET_PLAIN = 0;
export const HSM_SECRET_ENCRYPTED = 1;
export const HSM_SECRET_MNEMONIC_NO_PASS = 2;
export const HSM_SECRET_MNEMONIC_WITH_PASS = 3;
export const HSM_SECRET_INVALID = 4;

const PLAIN_SIZE = 32;
// 24-byte secretstream header + 32-byte secret + 17-byte Poly1305 tag.
const ENCRYPTED_SIZE = 73;
const PASSPHRASE_HASH_LEN = 32;

// Mirrors detect_hsm_secret_type(): the length decides the legacy formats
// before the 32-byte prefix decides which mnemonic flavour this is.
export const detectHsmSecretType = (bytes) => {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("hsm_secret must be bytes.");
  if (bytes.length < PLAIN_SIZE) return HSM_SECRET_INVALID;
  if (bytes.length === PLAIN_SIZE) return HSM_SECRET_PLAIN;
  if (bytes.length === ENCRYPTED_SIZE) return HSM_SECRET_ENCRYPTED;
  for (let i = 0; i < PASSPHRASE_HASH_LEN; i++) {
    if (bytes[i] !== 0) return HSM_SECRET_MNEMONIC_WITH_PASS;
  }
  return HSM_SECRET_MNEMONIC_NO_PASS;
};

// Keyed refusals: `code` is the stable machine identifier the tests hook on,
// `key` is the English sentence t() translates in the UI step (C2).
const refuse = (code, key) => Object.assign(new Error(key), { code, key });

// ── HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869) ───────────────────────
// src/js has no HMAC or HKDF helper, so both are built on the repository's
// sha256. Exported so the RFC vectors can pin them.

const SHA256_BLOCK = 64;

const concatBytes = (...parts) => {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

export const hmacSha256 = (key, message) => {
  const block = new Uint8Array(SHA256_BLOCK);
  const inner = new Uint8Array(SHA256_BLOCK);
  const outer = new Uint8Array(SHA256_BLOCK);
  let hashedKey = null;
  let innerInput = null;
  let innerHash = null;
  let outerInput = null;
  try {
    if (key.length > SHA256_BLOCK) {
      hashedKey = sha256(key);
      block.set(hashedKey);
    } else {
      block.set(key);
    }
    for (let i = 0; i < SHA256_BLOCK; i++) {
      inner[i] = block[i] ^ 0x36;
      outer[i] = block[i] ^ 0x5c;
    }
    innerInput = concatBytes(inner, message);
    innerHash = sha256(innerInput);
    outerInput = concatBytes(outer, innerHash);
    return sha256(outerInput);
  } finally {
    block.fill(0);
    inner.fill(0);
    outer.fill(0);
    if (hashedKey) hashedKey.fill(0);
    if (innerInput) innerInput.fill(0);
    if (innerHash) innerHash.fill(0);
    if (outerInput) outerInput.fill(0);
  }
};

export const hkdfSha256 = (ikm, salt, info, length) => {
  // RFC 5869 §2.3: L <= 255 * HashLen. The block counter is a single byte,
  // so a longer request would silently repeat blocks instead of failing.
  if (length > 255 * 32) {
    throw new RangeError("HKDF-SHA256 output length must not exceed 255 * 32 bytes.");
  }
  const prk = hmacSha256(salt, ikm);
  const okm = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let success = false;
  try {
    for (let counter = 1, offset = 0; offset < length; counter++) {
      const input = concatBytes(previous, info, Uint8Array.of(counter));
      let block;
      try {
        block = hmacSha256(prk, input);
      } finally {
        input.fill(0);
      }
      previous.fill(0);
      previous = block;
      const take = Math.min(block.length, length - offset);
      okm.set(block.subarray(0, take), offset);
      offset += take;
    }
    success = true;
    return okm;
  } finally {
    previous.fill(0);
    prk.fill(0);
    if (!success) okm.fill(0);
  }
};

// ── Node identity (hsmd/libhsmd.c node_key) ─────────────────────────────────

const NODEID_INFO = new TextEncoder().encode("nodeid");

// The exact do/while loop: HKDF over the first 32 bytes of the secret with a
// little-endian u32 salt, retried with the next counter until the output is a
// valid key (a ~2^-127 event, but the loop is part of the derivation).
const deriveNodePrivateKey = (seed) => {
  const ikm = seed.subarray(0, 32);
  const salt = new Uint8Array(4);
  try {
    for (let counter = 0; counter <= 0xffffffff; counter++) {
      salt[0] = counter & 0xff;
      salt[1] = (counter >>> 8) & 0xff;
      salt[2] = (counter >>> 16) & 0xff;
      salt[3] = (counter >>> 24) & 0xff;
      const candidate = hkdfSha256(ikm, salt, NODEID_INFO, 32);
      let valid = false;
      try {
        valid = secp256k1.utils.isValidSecretKey(candidate);
        if (valid) return candidate;
      } finally {
        if (!valid) candidate.fill(0);
      }
    }
  } finally {
    salt.fill(0);
  }
  throw refuse("hsm-secret-node-key", "Could not derive a valid node key.");
};

// ── On-chain descriptors (hsmd/libhsmd.c derive_bip86_base_key) ─────────────

const BIP86_PATH = "m/86'/0'/0'";

// CLN fixes coin type 0' on every network; only the extended-key version
// bytes change (xpub vs tpub).
const NETWORKS = {
  bitcoin: { private: 0x0488ade4, public: 0x0488b21e, prefix: "xpub" },
  testnet: { private: 0x04358394, public: 0x043587cf, prefix: "tpub" },
  signet: { private: 0x04358394, public: 0x043587cf, prefix: "tpub" },
  regtest: { private: 0x04358394, public: 0x043587cf, prefix: "tpub" },
};

const isValidMnemonic = (phrase) => {
  try {
    return validateMnemonic(phrase) === true;
  } catch {
    return false;
  }
};

export const deriveClnNode = (mnemonic, network = "bitcoin") => {
  // Own properties only: "constructor", "__proto__" or "toString" must not
  // resolve to an inherited Object.prototype member.
  const params = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : null;
  if (!params) throw refuse("hsm-secret-network", "Unknown network.");
  const phrase = String(mnemonic).trim().toLowerCase().replace(/\s+/g, " ");
  if (!isValidMnemonic(phrase)) {
    throw refuse("hsm-secret-invalid-mnemonic", "The BIP39 checksum does not match.");
  }
  const seed = mnemonicToSeedSync(phrase, "");
  let nodePrivateKey = null;
  let master = null;
  let base = null;
  try {
    nodePrivateKey = deriveNodePrivateKey(seed);
    const nodeId = hex.encode(secp256k1.getPublicKey(nodePrivateKey, true));
    master = HDKey.fromMasterSeed(seed, { private: params.private, public: params.public });
    base = master.derive(BIP86_PATH);
    const xpub = base.publicExtendedKey;
    if (typeof xpub !== "string" || !xpub.startsWith(params.prefix)) {
      throw refuse("hsm-secret-xpub", "The account key was not serialized with the expected version bytes.");
    }
    const descriptors = [
      `wpkh(${xpub}/0/*)`,
      `sh(wpkh(${xpub}/0/*))`,
      `tr(${xpub}/0/*)`,
    ].map((body) => `${body}#${descriptorChecksum(body)}`);
    return { nodeId, xpub, descriptors };
  } finally {
    seed.fill(0);
    if (nodePrivateKey) nodePrivateKey.fill(0);
    if (base) base.wipePrivateData();
    if (master) master.wipePrivateData();
  }
};

// ── Reading a type-2 hsm_secret ─────────────────────────────────────────────

const MNEMONIC_LENGTHS = [12, 15, 18, 21, 24];

const readWords = (text) => {
  const words = String(text).trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length < 12) {
    throw refuse("hsm-secret-truncated", "The mnemonic is truncated.");
  }
  if (!MNEMONIC_LENGTHS.includes(words.length)) {
    throw refuse("hsm-secret-trailing", "The mnemonic has trailing words.");
  }
  const phrase = words.join(" ");
  if (!isValidMnemonic(phrase)) {
    throw refuse("hsm-secret-invalid-mnemonic", "The BIP39 checksum does not match.");
  }
  return phrase;
};

const decodeMnemonicText = (bytes) => {
  const copy = Uint8Array.from(bytes);
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(copy);
  } catch {
    throw refuse("hsm-secret-invalid-mnemonic", "The mnemonic is not valid UTF-8.");
  } finally {
    copy.fill(0);
  }
};

// Accepts the raw hsm_secret file bytes or the words `lightning-hsmtool
// getsecret` prints; returns the normalized mnemonic for type 2 only.
//
// The words-only path cannot see the 32-byte prefix, so it assumes type 2
// (no passphrase). A passphrase-protected wallet's words derive a different
// node, so the UI step must say that this path is for type-2 secrets only.
export const readClnMnemonic = (input) => {
  if (typeof input === "string") return readWords(input);
  if (!(input instanceof Uint8Array)) {
    throw new TypeError("Expected the hsm_secret bytes or the mnemonic words.");
  }
  switch (detectHsmSecretType(input)) {
    case HSM_SECRET_PLAIN:
      throw refuse("hsm-secret-plain", "This is a legacy 32-byte hsm_secret, not a mnemonic secret.");
    case HSM_SECRET_ENCRYPTED:
      throw refuse("hsm-secret-encrypted", "This encrypted legacy hsm_secret is not supported.");
    case HSM_SECRET_MNEMONIC_WITH_PASS:
      throw refuse("hsm-secret-passphrase", "This hsm_secret needs a passphrase.");
    case HSM_SECRET_MNEMONIC_NO_PASS:
      return readWords(decodeMnemonicText(input.subarray(PASSPHRASE_HASH_LEN)));
    case HSM_SECRET_INVALID:
    default:
      throw refuse("hsm-secret-truncated", "This hsm_secret is truncated.");
  }
};
