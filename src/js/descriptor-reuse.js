// Duplicate key material across multipath descriptor branches (issue #164).
//
// Informational only: it reports reuse, it never refuses a descriptor for it.
// Watch-only descriptors are parsed, BIP-389 multipath steps are expanded and
// the concrete compressed public keys are derived through HDKey (the WASM
// curve code). No curve math happens here, nothing is logged, and no private
// material is ever returned: extended private keys and WIF tokens are refused
// before parsing, and only public keys and their paths leave this module.
import { descriptorChecksum } from "./core-importdescriptors.js";
import { HDKey } from "./hdkey.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";

const MAX_KEYS = 20;
const MAX_MULTIPATH_VALUES = 8;
const MAX_INDEXES = 1000;
const MAX_DERIVATIONS = 20000;
const MAX_COLLISIONS = 20;

// BIP-341: the unspendable internal key of a script-path-only taproot output.
const NUMS_POINT = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

const MAINNET_XPUB = 0x0488b21e;
const TESTNET_TPUB = 0x043587cf;
const MAINNET_VERSIONS = { private: 0x0488ade4, public: MAINNET_XPUB };
const TESTNET_VERSIONS = { private: 0x04358394, public: TESTNET_TPUB };

// SLIP-132 public version words: ypub zpub Ypub Zpub, upub vpub Upub Vpub.
const SLIP132_PUBLIC_VERSIONS = new Set([0x049d7cb2, 0x04b24746, 0x0295b43f, 0x02aa7ed3, 0x044a5262, 0x045f1cf6, 0x024289ef, 0x02575483]);

const EXTENDED_PUBLIC = /^(?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)/;
const TESTNET_PUBLIC = /^(?:tpub|upub|vpub|Upub|Vpub)/;
const EXTENDED_PRIVATE = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;
const WIF_TOKEN = /(?:^|[^1-9A-HJ-NP-Za-km-z])([5KL9c][1-9A-HJ-NP-Za-km-z]{50,51})(?![1-9A-HJ-NP-Za-km-z])/;

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

// The refusal never echoes the token: a message that repeated a private key
// would leak it into logs, screenshots and bug reports.
function assertNoPrivateMaterial(text) {
  if (EXTENDED_PRIVATE.test(text) || WIF_TOKEN.test(text)) {
    throw new Error("private: descriptor carries private key material");
  }
}

function splitArgs(inner) {
  const args = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < inner.length; i += 1) {
    const character = inner[i];
    if (character === "(" || character === "[" || character === "<") depth += 1;
    else if (character === ")" || character === "]" || character === ">") depth -= 1;
    else if (character === "," && depth === 0) {
      args.push(inner.slice(start, i));
      start = i + 1;
    }
  }
  args.push(inner.slice(start));
  return args;
}

function parseCall(text) {
  const match = /^([a-z0-9_]+)\(/.exec(text);
  if (!match) return null;
  let depth = 0;
  let end = -1;
  for (let i = match[0].length - 1; i < text.length; i += 1) {
    const character = text[i];
    if (character === "(") depth += 1;
    else if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end !== text.length - 1) return null;
  return { name: match[1], args: splitArgs(text.slice(match[0].length, end)) };
}

function multiKeys(call) {
  if (call.args.length < 2 || !/^\d+$/.test(call.args[0])) {
    throw new Error(`unsupported: ${call.name} needs a threshold and at least one key`);
  }
  return call.args.slice(1);
}

function collectKeys(text) {
  const call = parseCall(text);
  if (!call) throw new Error("unsupported: not a descriptor expression");
  const { name, args } = call;
  if (name === "pkh" || name === "wpkh") {
    if (args.length !== 1) throw new Error(`unsupported: ${name} takes one key`);
    return [args[0]];
  }
  if (name === "sh") {
    if (args.length !== 1) throw new Error("unsupported: sh takes one argument");
    const inner = parseCall(args[0]);
    if (!inner) throw new Error("unsupported: sh argument");
    if (inner.name === "wpkh") {
      if (inner.args.length !== 1) throw new Error("unsupported: sh(wpkh(...))");
      return [inner.args[0]];
    }
    if (inner.name === "multi" || inner.name === "sortedmulti") return multiKeys(inner);
    if (inner.name === "wsh") {
      if (inner.args.length !== 1) throw new Error("unsupported: sh(wsh(...))");
      const deep = parseCall(inner.args[0]);
      if (!deep || (deep.name !== "multi" && deep.name !== "sortedmulti")) throw new Error("unsupported: sh(wsh(...))");
      return multiKeys(deep);
    }
    throw new Error("unsupported: sh(...)");
  }
  if (name === "wsh") {
    if (args.length !== 1) throw new Error("unsupported: wsh takes one argument");
    const inner = parseCall(args[0]);
    if (!inner || (inner.name !== "multi" && inner.name !== "sortedmulti")) throw new Error("unsupported: wsh(...)");
    return multiKeys(inner);
  }
  if (name === "tr") {
    if (args.length === 1) return [args[0]];
    if (args.length === 2) {
      if (args[0].toLowerCase() !== NUMS_POINT) throw new Error("unsupported: tr() key path must be the BIP-341 NUMS point");
      const inner = parseCall(args[1]);
      if (!inner || (inner.name !== "multi_a" && inner.name !== "sortedmulti_a")) throw new Error("unsupported: tr(...) script");
      return multiKeys(inner);
    }
    throw new Error("unsupported: tr(...)");
  }
  throw new Error(`unsupported: ${name}`);
}

function parseKeyExpression(text) {
  let rest = text;
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close < 0) throw new Error("unsupported: malformed key origin");
    if (!/^[0-9a-fA-F]{8}(?:\/\d+['hH]?)*$/.test(rest.slice(1, close))) throw new Error("unsupported: malformed key origin");
    rest = rest.slice(close + 1);
  }
  const match = /^[1-9A-HJ-NP-Za-km-z]+/.exec(rest);
  if (!match) throw new Error("unsupported: missing extended public key");
  const extended = match[0];
  if (!EXTENDED_PUBLIC.test(extended)) throw new Error("unsupported: unsupported extended key prefix");
  rest = rest.slice(extended.length);
  if (rest && !rest.startsWith("/")) throw new Error("unsupported: malformed key path");
  if (rest.includes("//")) throw new Error("unsupported: malformed key path");
  if (/(?:^|\/)\d+['hH](?=\/|$)/.test(rest) || /\/\*['hH]/.test(rest)) {
    throw new Error("hardened: hardened derivation after an extended public key");
  }
  if (!rest.endsWith("/*")) throw new Error("unranged: key is not ranged");
  const parts = rest.slice(1, -2).split("/").filter((part) => part !== "");
  const steps = [];
  let multipath = null;
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    if (/^\d+$/.test(part)) {
      if (Number(part) >= 0x80000000) throw new Error("hardened: hardened derivation after an extended public key");
      steps.push(part);
      continue;
    }
    const group = /^<([^<>]*)>$/.exec(part);
    if (group) {
      if (multipath) throw new Error("unsupported: more than one multipath step");
      if (i !== parts.length - 1) throw new Error("unsupported: multipath step must come right before /*");
      const values = group[1].split(";");
      if (values.some((value) => !/^\d+$/.test(value) || Number(value) >= 0x80000000)) {
        throw new Error("unsupported: malformed multipath step");
      }
      multipath = values;
      continue;
    }
    throw new Error("unsupported: malformed key path step");
  }
  return { extended, prefix: extended.slice(0, 4), steps, multipath };
}

// Same rewrite as rewritePubKey in core-importdescriptors.js: a SLIP-132
// public key keeps its payload and only its version word becomes xpub/tpub.
function rewriteExtendedKey(key) {
  if (/^(?:xpub|tpub)/.test(key)) return key;
  let raw;
  try {
    raw = base58checkDecode(key);
  } catch {
    throw new Error("unsupported: extended public key does not decode");
  }
  if (!(raw instanceof Uint8Array) || raw.length !== 78) throw new Error("unsupported: extended public key has an unexpected length");
  const version = new DataView(raw.buffer, raw.byteOffset).getUint32(0, false);
  if (!SLIP132_PUBLIC_VERSIONS.has(version)) throw new Error("unsupported: extended public key version is not a SLIP-132 public version");
  const target = TESTNET_PUBLIC.test(key) ? TESTNET_TPUB : MAINNET_XPUB;
  const next = new Uint8Array(raw);
  next[0] = target >>> 24 & 255;
  next[1] = target >>> 16 & 255;
  next[2] = target >>> 8 & 255;
  next[3] = target & 255;
  return base58checkEncode(next);
}

export function checkDescriptorKeyReuse(descriptor, { indexes = 20, network = "mainnet" } = {}) {
  // `network` is accepted for API symmetry. Each key's own version bytes
  // decide how it is parsed, so a tpub derives the same children whatever the
  // caller passes and no derived pubkey depends on this argument.
  void network;
  if (!Number.isSafeInteger(indexes) || indexes < 1 || indexes > MAX_INDEXES) {
    throw new Error(`limit: indexes must be an integer from 1 to ${MAX_INDEXES}`);
  }
  const text = String(descriptor ?? "").trim();
  if (!text) throw new Error("unsupported: descriptor is missing");
  assertNoPrivateMaterial(text);
  const hash = text.lastIndexOf("#");
  const body = hash >= 0 ? text.slice(0, hash) : text;
  if (hash >= 0) {
    let expected;
    try {
      expected = descriptorChecksum(body);
    } catch {
      throw new Error("unsupported: descriptor contains characters outside the descriptor charset");
    }
    if (expected !== text.slice(hash + 1)) throw new Error("checksum: descriptor checksum does not match");
  }
  const keyTexts = collectKeys(body);
  if (keyTexts.length > MAX_KEYS) throw new Error(`limit: at most ${MAX_KEYS} keys`);
  const keys = keyTexts.map(parseKeyExpression);
  const lengths = new Set(keys.filter((key) => key.multipath).map((key) => key.multipath.length));
  if (lengths.size > 1) throw new Error("multipath-length: every multipath step must have the same number of values");
  const branches = lengths.size ? [...lengths][0] : 1;
  if (branches > MAX_MULTIPATH_VALUES) throw new Error(`limit: at most ${MAX_MULTIPATH_VALUES} multipath values`);
  // Every child derivation counts: the fixed steps walked once per (branch,
  // key) to reach the branch node, plus one per index below it.
  const derivations = keys.reduce((sum, key) => sum + branches * (key.steps.length + (key.multipath ? 1 : 0) + indexes), 0);
  if (derivations > MAX_DERIVATIONS) throw new Error(`limit: at most ${MAX_DERIVATIONS} derivations`);
  const roots = keys.map((key) => {
    const rewritten = rewriteExtendedKey(key.extended);
    try {
      return HDKey.fromExtendedKey(rewritten, TESTNET_PUBLIC.test(key.extended) ? TESTNET_VERSIONS : MAINNET_VERSIONS);
    } catch {
      throw new Error("unsupported: extended public key does not parse");
    }
  });
  const seen = new Map();
  const collisions = [];
  let collisionCount = 0;
  for (let branch = 0; branch < branches; branch += 1) {
    for (let slot = 0; slot < keys.length; slot += 1) {
      const key = keys[slot];
      const segments = key.multipath ? key.steps.concat([key.multipath[branch]]) : key.steps;
      const node = segments.length ? roots[slot].derive(`m/${segments.join("/")}`) : roots[slot];
      for (let index = 0; index < indexes; index += 1) {
        const pubkey = hex(node.deriveChild(index).publicKey);
        const position = { branch, slot, index, path: `${key.prefix}…/${segments.concat([String(index)]).join("/")}` };
        const first = seen.get(pubkey);
        if (first) {
          collisionCount += 1;
          if (collisions.length < MAX_COLLISIONS) collisions.push({ pubkey, first, second: position });
        } else {
          seen.set(pubkey, position);
        }
      }
    }
  }
  return { branches, indexes, keys: keys.length, collisions, collisionCount };
}
