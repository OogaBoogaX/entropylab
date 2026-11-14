// Public-only verification package for independent Bitcoin Core checks.
//
// EntropyLab hands an external verifier (portlandhodl/wasm-bitcoin-tools) a
// small, versioned JSON document holding only public output: descriptors,
// extended public keys, addresses, a PSBT and a wallet.dat digest. Nothing
// secret may cross that boundary, so every string in the input is scanned for
// private key material before anything is emitted. Pure: no I/O, no clock,
// same input → same bytes.

import { base58checkDecode, base58checkEncode } from "./base58.js";
import { wordlist } from "./bip39-english.js";
import { buildOutputScript } from "./script-builder.js";
import { psbtInspectDoc } from "./psbt-wasm.js";
import { sha256 } from "./hashes.js";
import { canonicalizeWatchDescriptor, descriptorChecksum } from "./core-importdescriptors.js";

const SCHEMA = "entropylab-verification/1";

const NETWORKS = new Map([
  ["mainnet", "main"],
  ["testnet", "test"],
  ["testnet3", "test"],
  ["testnet4", "testnet4"],
  ["signet", "signet"],
  ["regtest", "regtest"],
]);

// The network names are Bitcoin Core's own chain names (-chain=main, test,
// testnet4, signet, regtest), so testnet3 and testnet4 stay distinct.
const BASE58_RUN = /[1-9A-HJ-NP-Za-km-z]+/g;
const EXTENDED_PRIVATE_PREFIX = /^(?:[xyztuv]prv|[YZUV]prv)/;
const WIF_PREFIXES = "5KL9c";
const WORD_RUN = /[A-Za-z]+/g;
const BIP39_WORDS = new Set(wordlist);

// Base58Check through the repo's own codec (base58.js, WASM-backed), the
// same one the app passes to canonicalizeWatchDescriptor; no hand-written
// hashing here.
const BASE58CHECK = { decode: base58checkDecode, encode: base58checkEncode };

// A key or WIF is a whole base58 token, never a slice of a longer one: an
// xpub is 111 characters and would otherwise contain 51-character windows
// starting with 5/K/L/9/c by chance.
function containsExtendedPrivateKey(text) {
  for (const match of text.matchAll(BASE58_RUN)) {
    if (match[0].length >= 94 && EXTENDED_PRIVATE_PREFIX.test(match[0])) return true;
  }
  return false;
}

function containsWif(text) {
  for (const match of text.matchAll(BASE58_RUN)) {
    const token = match[0];
    if ((token.length === 51 || token.length === 52) && WIF_PREFIXES.includes(token[0])) return true;
  }
  return false;
}

function containsMnemonicRun(text) {
  let run = 0;
  for (const match of text.matchAll(WORD_RUN)) {
    if (BIP39_WORDS.has(match[0].toLowerCase())) {
      run += 1;
      if (run >= 12) return true;
    } else {
      run = 0;
    }
  }
  return false;
}

function collectStrings(value, out) {
  // Binary input (walletDatBytes) is only ever hashed, never emitted; walking
  // it byte by byte would stall the page on a multi-megabyte wallet.dat.
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return;
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      out.push(key);
      collectStrings(item, out);
    }
  }
}

// The refusal never repeats the material: the message is fixed text.
function assertPublicOnly(input) {
  const strings = [];
  // The PSBT is base64, which shares 58 of its 64 symbols with base58: its
  // runs would read as WIFs (the "cHNidP8" prefix starts with c). It is
  // validated by the PSBT parser instead (normalizePsbt).
  const { psbtBase64, ...scanned } = input;
  void psbtBase64;
  collectStrings(scanned, strings);
  for (const text of strings) {
    if (containsExtendedPrivateKey(text) || containsWif(text) || containsMnemonicRun(text)) {
      throw new Error("private: the verification package is public-only and must not carry private key material.");
    }
  }
}

function mapNetwork(network) {
  const mapped = typeof network === "string" ? NETWORKS.get(network) : undefined;
  if (!mapped) throw new Error("network: unsupported network for a verification package.");
  return mapped;
}

function optionalHex(value, length, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${label}: expected ${length} lowercase hex characters.`);
  }
  return value;
}

// Public extended-key version words: xpub, tpub and the SLIP-132 public
// families. The second set is the test-chain group, which canonicalizes to
// tpub; the rest canonicalize to xpub.
const PUBLIC_VERSIONS = new Set([0x0488b21e, 0x043587cf, 0x049d7cb2, 0x04b24746, 0x0295b43f, 0x02aa7ed3, 0x044a5262, 0x045f1cf6, 0x024289ef, 0x02575483]);
const TEST_CHAIN_VERSIONS = new Set([0x043587cf, 0x044a5262, 0x045f1cf6, 0x024289ef, 0x02575483]);
const NUMS_POINT = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const KEY_EXPRESSION = String.raw`(?:\[[0-9a-fA-F]{8}(?:/\d+[hH']?)*\])?(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]{100,112}(?:/\d+)*(?:/<\d+(?:;\d+)+>)?/\*`;
const KEY_LIST = String.raw`\d+(?:,${KEY_EXPRESSION})+`;
const DESCRIPTOR_SHAPES = [
  String.raw`^(?:pkh|wpkh|tr)\(${KEY_EXPRESSION}\)$`,
  String.raw`^sh\(wpkh\(${KEY_EXPRESSION}\)\)$`,
  String.raw`^(?:sh|wsh)\((?:sorted)?multi\(${KEY_LIST}\)\)$`,
  String.raw`^sh\(wsh\((?:sorted)?multi\(${KEY_LIST}\)\)\)$`,
  String.raw`^tr\(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,(?:sorted)?multi_a\(${KEY_LIST}\)\)$`,
].map((source) => new RegExp(source));
const NOT_PUBLIC = "private: the verification package is public-only; a key in it is not a verifiable extended public key.";

// The scanners above recognise known private forms; this proves the
// opposite. A key passes only if it Base58Check-decodes to a 78-byte
// extended key with a public version word and a public key-data byte, so a
// form no heuristic knows (BIP-38 "6P…", raw hex, a mangled xprv) is refused
// rather than copied into a package meant for another tool. Returns the raw
// payload; the caller wipes nothing, since it is public.
function publicExtendedKeyBytes(token) {
  let raw;
  try {
    raw = base58checkDecode(token);
  } catch {
    throw new Error(NOT_PUBLIC);
  }
  if (!(raw instanceof Uint8Array) || raw.length !== 78) throw new Error(NOT_PUBLIC);
  const version = ((raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]) >>> 0;
  if (!PUBLIC_VERSIONS.has(version) || (raw[45] !== 0x02 && raw[45] !== 0x03)) throw new Error(NOT_PUBLIC);
  return { raw, version };
}

function normalizeDescriptor(descriptor) {
  if (typeof descriptor !== "string") throw new Error("descriptor: each descriptor must be a string.");
  const text = descriptor.trim();
  if (!text) throw new Error("descriptor: descriptor is empty.");
  const hash = text.lastIndexOf("#");
  if (hash >= 0) {
    let expected;
    try {
      expected = descriptorChecksum(text.slice(0, hash));
    } catch (error) {
      throw new Error(`descriptor: ${error.message}`);
    }
    if (expected !== text.slice(hash + 1)) throw new Error("checksum: descriptor checksum does not match.");
  }
  let canonical;
  try {
    canonical = canonicalizeWatchDescriptor(text, BASE58CHECK, "Descriptor");
  } catch (error) {
    throw new Error(`descriptor: ${error.message}`);
  }
  // Every long base58 run in the emitted descriptor is a key position (origin
  // fingerprints and the checksum are 8 characters), and each must be a
  // verifiable extended public key.
  const emittedHash = canonical.lastIndexOf("#");
  const body = emittedHash >= 0 ? canonical.slice(0, emittedHash) : canonical;
  for (const match of body.matchAll(BASE58_RUN)) {
    if (match[0].length >= 50) publicExtendedKeyBytes(match[0]);
  }
  // A raw 32-byte hex value looks the same whether it is an x-only public key
  // or a private key, so the only raw key allowed is BIP-341's NUMS point
  // (the Taproot multisig internal key); every other key must be an
  // extended public key.
  for (const match of body.matchAll(/[0-9a-fA-F]{64,}/g)) {
    if (match[0].toLowerCase() !== NUMS_POINT) throw new Error(NOT_PUBLIC);
  }
  // The whole body must be one of the supported shapes, built only from
  // xpub/tpub key expressions (and the NUMS point): no free text, words or
  // fragments can ride inside a descriptor string.
  if (!DESCRIPTOR_SHAPES.some((shape) => shape.test(body))) {
    throw new Error("descriptor: not a supported watch-only descriptor shape for a verification package.");
  }
  // The emitted checksum must pin the emitted body, whatever the rewrite did.
  if (emittedHash < 0 || descriptorChecksum(body) !== canonical.slice(emittedHash + 1)) {
    throw new Error("checksum: the canonical descriptor's checksum does not match its body.");
  }
  return canonical;
}

function normalizeDescriptors(descriptors) {
  if (descriptors === undefined || descriptors === null) return [];
  if (!Array.isArray(descriptors)) throw new Error("descriptor: descriptors must be an array.");
  return descriptors.map(normalizeDescriptor);
}

function normalizeXpubs(xpubs) {
  if (xpubs === undefined || xpubs === null) return [];
  if (!Array.isArray(xpubs)) throw new Error("xpub: xpubs must be an array.");
  return xpubs.map((xpub) => {
    if (typeof xpub !== "string" || !xpub.trim()) throw new Error("xpub: each extended public key must be a non-empty string.");
    const token = xpub.trim();
    // One whole base58 token that decodes to a public extended key, emitted
    // in its xpub/tpub form like the descriptors.
    if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(token)) throw new Error(NOT_PUBLIC);
    const { raw, version } = publicExtendedKeyBytes(token);
    if (version === 0x0488b21e || version === 0x043587cf) return token;
    const target = TEST_CHAIN_VERSIONS.has(version) ? 0x043587cf : 0x0488b21e;
    const next = new Uint8Array(raw);
    next[0] = target >>> 24 & 255;
    next[1] = target >>> 16 & 255;
    next[2] = target >>> 8 & 255;
    next[3] = target & 255;
    return base58checkEncode(next);
  });
}

// Every address must decode as an address of the declared network (through
// script-builder's @scure/btc-signer decoder): a typo, a hex string or words
// can never pass as one.
const SCRIPT_NETWORK = { main: "mainnet", regtest: "regtest" };
function normalizeAddresses(entries, label, network) {
  if (entries === undefined || entries === null) return [];
  if (!Array.isArray(entries)) throw new Error(`${label}: must be an array.`);
  const addresses = [];
  let previous = -1;
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") throw new Error(`${label}: each entry needs an index and an address.`);
    if (!Number.isSafeInteger(entry.index) || entry.index < 0) throw new Error(`${label}: index must be a non-negative whole number.`);
    if (entry.index <= previous) throw new Error(`${label}: indexes must ascend without duplicates.`);
    previous = entry.index;
    if (typeof entry.address !== "string" || !entry.address.trim()) throw new Error(`${label}: address must be a non-empty string.`);
    const address = entry.address.trim();
    let decoded = null;
    try {
      decoded = buildOutputScript(address, { network: SCRIPT_NETWORK[network] ?? "testnet" });
    } catch {
      decoded = null;
    }
    if (decoded?.kind !== "address") throw new Error(`${label}: not a valid ${network} address.`);
    addresses.push({ index: entry.index, address });
  }
  return addresses;
}

function normalizePsbt(psbtBase64) {
  if (psbtBase64 === undefined || psbtBase64 === null) return null;
  const text = typeof psbtBase64 === "string" ? psbtBase64.trim() : "";
  if (!text.startsWith("cHNidP8") || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw new Error("psbt: expected base64 PSBT data beginning with cHNidP8.");
  // A real PSBT, decoded by the reference parser (rust-bitcoin, psbt-wasm.js):
  // pasted text that is not PSBT data can never ride along in this field.
  const bytes = Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
  let doc;
  try {
    doc = psbtInspectDoc(bytes);
  } catch {
    throw new Error("psbt: not a valid PSBT.");
  } finally {
    bytes.fill(0);
  }
  // Proprietary (type 0xfc) and unknown pairs can carry arbitrary bytes,
  // a secret included; a PSBT for independent checking carries neither.
  const pairs = [...(doc?.globals ?? []), ...(doc?.inputs ?? []).flat(), ...(doc?.outputs ?? []).flat()];
  // The parser names them PSBT_*_PROPRIETARY / PSBT_*_UNKNOWN (key type 0xfc
  // or a type BIP-174 does not define).
  if (pairs.some((pair) => !pair?.name || /_(?:PROPRIETARY|UNKNOWN)$/.test(pair.name) || String(pair?.key ?? "").slice(0, 2).toLowerCase() === "fc")) {
    throw new Error("psbt: the PSBT carries proprietary or unknown fields; export one without them.");
  }
  return text;
}

export function buildVerificationPackage(input) {
  const source = input && typeof input === "object" ? input : {};
  assertPublicOnly(source);
  const network = mapNetwork(source.network);
  const masterFingerprint = optionalHex(source.masterFingerprint, 8, "masterFingerprint");
  // The hash is computed here from the file's bytes: a caller-supplied 64-hex
  // string is indistinguishable from a raw private key, so none is accepted.
  if (source.walletDatSha256 !== undefined && source.walletDatSha256 !== null) {
    throw new Error("walletDat: pass the wallet.dat bytes (walletDatBytes); the package computes the hash itself.");
  }
  let walletDatSha256 = null;
  if (source.walletDatBytes !== undefined && source.walletDatBytes !== null) {
    if (!(source.walletDatBytes instanceof Uint8Array) || !source.walletDatBytes.length) throw new Error("walletDat: walletDatBytes must be the file's bytes.");
    walletDatSha256 = [...sha256(source.walletDatBytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  const descriptors = normalizeDescriptors(source.descriptors);
  const xpubs = normalizeXpubs(source.xpubs);
  const receiveAddresses = normalizeAddresses(source.receiveAddresses, "receiveAddresses", network);
  const changeAddresses = normalizeAddresses(source.changeAddresses, "changeAddresses", network);
  const psbt = normalizePsbt(source.psbtBase64);
  if (!descriptors.length && !receiveAddresses.length && !changeAddresses.length) {
    throw new Error("empty: a verification package needs at least one descriptor or one address.");
  }
  return `${JSON.stringify({
    schema: SCHEMA,
    network,
    masterFingerprint,
    descriptors,
    xpubs,
    receiveAddresses,
    changeAddresses,
    psbt,
    walletDatSha256,
  }, null, 2)}\n`;
}

// The file name carries no free text at all, so nothing typed into a label
// (a key, hex, words) can leak through it: only the network and the master
// fingerprint, both public and both validated.
export function verificationPackageFilename({ network, masterFingerprint } = {}) {
  const chain = mapNetwork(network);
  const fingerprint = optionalHex(masterFingerprint, 8, "masterFingerprint");
  return `entropylab-verification-${chain}${fingerprint ? `-${fingerprint}` : ""}.json`;
}
