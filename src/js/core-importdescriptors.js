// Watch-only Bitcoin Core `importdescriptors` JSON.
//
// Pure transformation of already-derived public output descriptors into the
// RPC array Core loads into a blank disable_private_keys wallet. No entropy,
// no I/O, no private keys. Same inputs → same JSON.

export const CORE_IMPORT_RANGE_END = 1000;

// BIP32's last unhardened child index: the deepest address a window can
// display, and the deepest Core can watch on a ranged descriptor.
const CORE_IMPORT_MAX_INDEX = 0x7fffffff;

// Every SLIP-132 private family, capital multisig prefixes included.
const PRIVATE_KEY = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;
const EXTENDED_PUB = /((?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{90,})/g;
const SLIP_PUB = /^(?:ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)/;
const CORE_PUB = /^(?:xpub|tpub)/;
const TESTNET_PUB = /^(?:tpub|upub|vpub|Upub|Vpub)/;

const MAINNET_XPUB = 0x0488b21e;
const TESTNET_TPUB = 0x043587cf;

const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function descriptorSymbolValues(text) {
  const symbols = [];
  const groups = [];
  for (const character of text) {
    const index = INPUT_CHARSET.indexOf(character);
    if (index < 0) throw new Error(`Invalid descriptor character: ${character}`);
    groups.push(index & 31);
    symbols.push(index >> 5);
    if (symbols.length === 3) {
      groups.push(symbols[0] * 9 + symbols[1] * 3 + symbols[2]);
      symbols.length = 0;
    }
  }
  if (symbols.length === 1) groups.push(symbols[0]);
  else if (symbols.length === 2) groups.push(symbols[0] * 3 + symbols[1]);
  return groups;
}

function descriptorPolymod(values) {
  const generators = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
  let chk = 1n;
  for (const value of values) {
    const top = chk >> 35n;
    chk = (chk & 0x7ffffffffn) << 5n ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i) & 1n) !== 0n) chk ^= generators[i];
  }
  return chk;
}

export function descriptorChecksum(body) {
  const values = descriptorSymbolValues(body).concat([0, 0, 0, 0, 0, 0, 0, 0]);
  const mod = descriptorPolymod(values) ^ 1n;
  let checksum = "";
  for (let i = 0; i < 8; i++) checksum += CHECKSUM_CHARSET[Number(mod >> BigInt(5 * (7 - i)) & 31n)];
  return checksum;
}

export function stripDescriptorChecksum(descriptor) {
  const text = String(descriptor ?? "");
  const hash = text.lastIndexOf("#");
  return hash >= 0 ? text.slice(0, hash) : text;
}

function withChecksum(body) {
  return `${body}#${descriptorChecksum(body)}`;
}

function assertNoPrivateMaterial(text, label) {
  if (PRIVATE_KEY.test(text)) throw new Error(`${label} carries an extended private key. Watch-only export refused.`);
}

function rewritePubKey(key, codec) {
  if (CORE_PUB.test(key)) return key;
  if (!SLIP_PUB.test(key)) throw new Error(`Unsupported extended public key prefix in ${key.slice(0, 4)}.`);
  if (!codec?.decode || !codec?.encode) throw new Error("SLIP-132 public keys need the Base58Check codec to rewrite as xpub/tpub.");
  const raw = codec.decode(key);
  if (!(raw instanceof Uint8Array) || raw.length !== 78) throw new Error("Extended public key decoded to an unexpected length.");
  const version = TESTNET_PUB.test(key) ? TESTNET_TPUB : MAINNET_XPUB;
  const next = new Uint8Array(raw);
  next[0] = version >>> 24 & 255;
  next[1] = version >>> 16 & 255;
  next[2] = version >>> 8 & 255;
  next[3] = version & 255;
  return codec.encode(next);
}

export function canonicalizeWatchDescriptor(descriptor, codec, label = "Descriptor") {
  const text = String(descriptor ?? "").trim();
  if (!text) throw new Error(`${label} is missing.`);
  assertNoPrivateMaterial(text, label);
  const body = stripDescriptorChecksum(text);
  if (text.includes("#") && withChecksum(body) !== text) throw new Error(`${label} checksum does not match.`);
  let changed = false;
  const rewritten = body.replace(EXTENDED_PUB, (key) => {
    const next = rewritePubKey(key, codec);
    if (next !== key) changed = true;
    return next;
  });
  assertNoPrivateMaterial(rewritten, label);
  return changed || !text.includes("#") ? withChecksum(rewritten) : text;
}

function stripAddressBranch(body) {
  return body.replace(/\/\d+\/\*(?=(?:,|\)))/g, "/*");
}

export function assertMatchingWatchDescriptors(receiveDescriptor, changeDescriptor) {
  if (!receiveDescriptor || !changeDescriptor) return;
  const receive = stripAddressBranch(stripDescriptorChecksum(receiveDescriptor));
  const change = stripAddressBranch(stripDescriptorChecksum(changeDescriptor));
  if (receive !== change) throw new Error("Receive and change descriptors name different keys.");
}

function resolveTimestamp(timestamp) {
  if (timestamp === undefined || timestamp === "genesis" || timestamp === 0) return 0;
  if (timestamp === "now") return "now";
  throw new Error("timestamp must be 0 or \"now\"");
}

// The watched range mirrors the wallet.dat export (wallet-export.js
// branchRangeFromRows): it starts at 0 — a fresh Core wallet's first
// getnewaddress is this wallet's receive index 0 — and runs Core's default
// lookahead past the deepest displayed address, so a window shown above row
// 1000 is still watched (audit B7b). A caller that cannot say which indexes
// it displays gets Core's default lookahead. Anything the descriptor cannot
// climb to is refused outright, never silently clipped.
//
// Core's import bound: ParseDescriptorRange refuses a range whose span
// reaches 1,000,000 ("Range is too large"). With the start pinned at 0 that
// bound bites at a displayed end of 999,000 — deeper JSON would fail loudly
// on the online node, so refuse at export instead (#861 review).
function resolveRangeEnd(displayedEnd) {
  if (displayedEnd === undefined || displayedEnd === null) return CORE_IMPORT_RANGE_END;
  if (!Number.isSafeInteger(displayedEnd) || displayedEnd < 0 || displayedEnd > CORE_IMPORT_MAX_INDEX) {
    throw new Error("Address range end must be a whole number from 0 to 2,147,483,647.");
  }
  if (displayedEnd + CORE_IMPORT_RANGE_END >= 1000000) {
    throw new Error("Bitcoin Core importdescriptors refuses a range span of 1,000,000 or more, so an address window ending at 999,000 or deeper cannot be exported. Show a shallower window and export again.");
  }
  return Math.min(displayedEnd + CORE_IMPORT_RANGE_END, CORE_IMPORT_MAX_INDEX);
}

function descriptorEntry(descriptor, internal, timestamp, codec, label, rangeEnd) {
  return {
    desc: canonicalizeWatchDescriptor(descriptor, codec, label),
    active: true,
    internal,
    timestamp,
    range: [0, rangeEnd],
  };
}

export function buildImportDescriptorsJson({ receiveDescriptor, changeDescriptor, timestamp, decode, encode, rangeEnd } = {}) {
  const receive = String(receiveDescriptor ?? "").trim();
  const change = String(changeDescriptor ?? "").trim();
  if (!receive && !change) throw new Error("No watch-only descriptors to export.");
  const codec = decode && encode ? { decode, encode } : null;
  const resolvedRangeEnd = resolveRangeEnd(rangeEnd);
  const entries = [];
  if (receive) entries.push(descriptorEntry(receive, false, resolveTimestamp(timestamp), codec, "Receive descriptor", resolvedRangeEnd));
  if (change) entries.push(descriptorEntry(change, true, resolveTimestamp(timestamp), codec, "Change descriptor", resolvedRangeEnd));
  if (receive && change) assertMatchingWatchDescriptors(entries[0].desc, entries[1].desc);
  return JSON.stringify(entries, null, 2);
}

export function coreImportDescriptorsFilename(wallet = {}) {
  const m = wallet.m;
  const n = wallet.n;
  if (Number.isSafeInteger(m) && Number.isSafeInteger(n)) return `entropylab-msig-${m}of${n}-importdescriptors.json`;
  return "entropylab-importdescriptors.json";
}
