// BIP-138 (draft 0.1.3) encrypted backups of a watch-only descriptor.
// Pure: no DOM, no i18n, no network, and no randomness of its own.
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "./hashes.js";
import { base58checkDecode } from "./base58.js";

export class Bip138Error extends Error {
  constructor(code) { super(code); this.name = "Bip138Error"; this.code = code; }
}
export const BIP138_VERSION = 1;
export const BIP138_CHACHA20_POLY1305 = 1;
export const BIP138_NUMS_XONLY = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
export const BIP138_TEXT_PREFIX = "QklQMTM4";
export const BIP138_MAX_FILE_BYTES = 1048576;

const MAGIC = Uint8Array.of(0x42, 0x49, 0x50, 0x31, 0x33, 0x38);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function fail(code) { throw new Bip138Error(code); }
function isBytes(value) { return value instanceof Uint8Array; }

function concatBytes(parts) {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function compareBytes(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
function comparePaths(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
function be32(value) {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

export function bip138CompactSize(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail("varint");
  if (value <= 0xfc) return Uint8Array.of(value);
  if (value <= 0xffff) return Uint8Array.of(0xfd, value & 0xff, (value >>> 8) & 0xff);
  if (value <= 0xffffffff) return Uint8Array.of(0xfe, value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
  const out = new Uint8Array(9);
  out[0] = 0xff;
  let rest = BigInt(value);
  for (let i = 1; i <= 8; i++) { out[i] = Number(rest & 0xffn); rest >>= 8n; }
  return out;
}
export function bip138ReadCompactSize(bytes, offset) {
  if (!isBytes(bytes) || !Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) fail("truncated");
  const first = bytes[offset];
  if (first < 0xfd) return { value: first, next: offset + 1 };
  if (first === 0xfd) {
    if (offset + 3 > bytes.length) fail("truncated");
    const value = bytes[offset + 1] | (bytes[offset + 2] << 8);
    if (value < 0xfd) fail("varint");
    return { value, next: offset + 3 };
  }
  if (first === 0xfe) {
    if (offset + 5 > bytes.length) fail("truncated");
    const value = (bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24)) >>> 0;
    if (value < 0x10000) fail("varint");
    return { value, next: offset + 5 };
  }
  if (offset + 9 > bytes.length) fail("truncated");
  let value = 0n;
  for (let i = 8; i >= 1; i--) value = (value << 8n) | BigInt(bytes[offset + i]);
  if (value < 0x100000000n) fail("varint");
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail("truncated");
  return { value: Number(value), next: offset + 9 };
}

export function bip138TaggedHash(tag, bytes) {
  const tagHash = sha256(textEncoder.encode(tag));
  return sha256(concatBytes([tagHash, tagHash, bytes]));
}

export function bip138SortKeys(keys) {
  if (!Array.isArray(keys)) fail("descriptor");
  const copies = keys.map((key) => {
    if (!isBytes(key) || key.length !== 32) fail("descriptor");
    return key.slice();
  });
  copies.sort(compareBytes);
  const out = [];
  for (const key of copies) {
    if (out.length && equalBytes(out[out.length - 1], key)) key.fill(0);
    else out.push(key);
  }
  return out;
}

export function bip138DecryptionSecret(keys) {
  const sorted = bip138SortKeys(keys);
  if (!sorted.length) fail("no-keys");
  const data = concatBytes(sorted);
  try {
    return bip138TaggedHash("BIP138_DECRYPTION_SECRET", data);
  } finally {
    data.fill(0);
    for (const key of sorted) key.fill(0);
  }
}

export function bip138IndividualSecrets(secret, keys) {
  if (!isBytes(secret) || secret.length !== 32) fail("descriptor");
  const sorted = bip138SortKeys(keys);
  const out = [];
  try {
    for (const key of sorted) {
      const si = bip138TaggedHash("BIP138_INDIVIDUAL_SECRET", key);
      const ci = new Uint8Array(32);
      for (let i = 0; i < 32; i++) ci[i] = secret[i] ^ si[i];
      si.fill(0);
      out.push(ci);
    }
    return out;
  } finally {
    for (const key of sorted) key.fill(0);
  }
}

export function bip138ParsePath(text) {
  if (typeof text !== "string") fail("descriptor");
  let value = text.trim();
  if (value === "m") return [];
  if (value.startsWith("m/")) value = value.slice(2);
  else if (value.startsWith("m")) fail("descriptor");
  if (!value) fail("descriptor");
  const out = [];
  for (const part of value.split("/")) {
    if (!/^\d+['hH]?$/.test(part)) fail("descriptor");
    const hardened = /['hH]$/.test(part);
    const digits = hardened ? part.slice(0, -1) : part;
    const number = Number(digits);
    if (!Number.isSafeInteger(number) || number > 2147483647) fail("descriptor");
    out.push(hardened ? (number | 0x80000000) >>> 0 : number);
  }
  return out;
}

export function bip138EncodeDerivationPaths(paths) {
  if (!Array.isArray(paths)) fail("descriptor");
  const copies = paths.map((path) => {
    if (!Array.isArray(path)) fail("descriptor");
    return path.map((child) => {
      if (!Number.isSafeInteger(child) || child < 0 || child > 0xffffffff) fail("descriptor");
      return child >>> 0;
    });
  });
  copies.sort(comparePaths);
  const unique = [];
  for (const path of copies) {
    if (!unique.length || comparePaths(unique[unique.length - 1], path) !== 0) unique.push(path);
  }
  if (unique.length > 255) fail("too-many-paths");
  const out = [unique.length];
  for (const path of unique) {
    if (path.length === 0) fail("empty-path");
    if (path.length > 255) fail("path-too-long");
    out.push(path.length);
    for (const child of path) out.push((child >>> 24) & 0xff, (child >>> 16) & 0xff, (child >>> 8) & 0xff, child & 0xff);
  }
  return Uint8Array.from(out);
}

export function bip138DecodeDerivationPaths(bytes, offset) {
  if (!isBytes(bytes) || !Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) fail("truncated");
  const count = bytes[offset++];
  const paths = [];
  for (let i = 0; i < count; i++) {
    if (offset >= bytes.length) fail("truncated");
    const childCount = bytes[offset++];
    if (childCount === 0) fail("empty-path");
    const path = [];
    for (let j = 0; j < childCount; j++) {
      if (offset + 4 > bytes.length) fail("truncated");
      path.push(((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0);
      offset += 4;
    }
    paths.push(path);
  }
  paths.sort(comparePaths);
  const unique = [];
  for (const path of paths) {
    if (!unique.length || comparePaths(unique[unique.length - 1], path) !== 0) unique.push(path);
  }
  return { paths: unique, next: offset };
}

export function bip138CommonPath(path) {
  if (!Array.isArray(path)) return false;
  const harden = (value) => (value | 0x80000000) >>> 0;
  const same = (candidate) => candidate.length === path.length && candidate.every((child, i) => child === path[i]);
  for (const coin of [0, 1]) {
    for (let account = 0; account <= 9; account++) {
      for (const script of [1, 2]) {
        if (same([harden(48), harden(coin), harden(account), harden(script)])) return true;
      }
      for (const purpose of [44, 49, 84, 86, 87]) {
        if (same([harden(purpose), harden(coin), harden(account)])) return true;
      }
    }
  }
  return false;
}

export function bip138EncodeIndividualSecrets(secrets) {
  if (!Array.isArray(secrets)) fail("descriptor");
  const copies = secrets.map((secret) => {
    if (!isBytes(secret) || secret.length !== 32) fail("descriptor");
    return secret.slice();
  });
  copies.sort(compareBytes);
  const unique = [];
  for (const secret of copies) {
    if (unique.length && equalBytes(unique[unique.length - 1], secret)) secret.fill(0);
    else unique.push(secret);
  }
  if (unique.length === 0) fail("no-secrets");
  if (unique.length > 255) fail("too-many");
  const out = new Uint8Array(1 + unique.length * 32);
  out[0] = unique.length;
  unique.forEach((secret, i) => out.set(secret, 1 + i * 32));
  return out;
}
export function bip138DecodeIndividualSecrets(bytes, offset) {
  if (!isBytes(bytes) || !Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) fail("truncated");
  const count = bytes[offset++];
  if (count === 0) fail("no-secrets");
  const secrets = [];
  for (let i = 0; i < count; i++) {
    if (offset + 32 > bytes.length) fail("truncated");
    secrets.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }
  secrets.sort(compareBytes);
  const unique = [];
  for (const secret of secrets) {
    if (unique.length && equalBytes(unique[unique.length - 1], secret)) secret.fill(0);
    else unique.push(secret);
  }
  return { secrets: unique, next: offset };
}

export function bip138EncodeContentType({ type, bip, params } = {}) {
  if (!Number.isSafeInteger(type)) fail("content-type");
  if (type === 1) {
    if (!Number.isSafeInteger(bip) || bip < 0 || bip > 0xffff) fail("content-type");
    return Uint8Array.of(1, (bip >>> 8) & 0xff, bip & 0xff);
  }
  if (type === 3) {
    if (params && params.length) fail("content-type");
    return Uint8Array.of(3, 0);
  }
  if (type >= 2 && type <= 0x7f) {
    const data = isBytes(params) ? params : new Uint8Array();
    return concatBytes([Uint8Array.of(type), bip138CompactSize(data.length), data]);
  }
  fail("content-type");
}
export function bip138DecodeContentType(bytes, offset) {
  if (!isBytes(bytes) || !Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) fail("truncated");
  const type = bytes[offset++];
  if (type === 0) fail("content-type");
  if (type === 1) {
    if (offset + 2 > bytes.length) fail("truncated");
    return { type, bip: (bytes[offset] << 8) | bytes[offset + 1], params: new Uint8Array(), next: offset + 2 };
  }
  if (type >= 2 && type <= 0x7f) {
    const { value: length, next } = bip138ReadCompactSize(bytes, offset);
    offset = next;
    if (offset + length > bytes.length) fail("truncated");
    const params = bytes.slice(offset, offset + length);
    if (type === 3 && params.length) fail("content-type");
    return { type, bip: undefined, params, next: offset + length };
  }
  fail("content-type");
}

export function bip138EncodePayload(items) {
  if (!Array.isArray(items) || items.length === 0) fail("empty-payload");
  const parts = [];
  for (const item of items) {
    if (!item || !isBytes(item.contentType) || !isBytes(item.content) || item.content.length === 0) fail("empty-payload");
    parts.push(item.contentType, bip138CompactSize(item.content.length), item.content);
  }
  return concatBytes(parts);
}
export function bip138DecodePayload(bytes) {
  if (!isBytes(bytes) || bytes.length === 0) fail("empty-payload");
  const items = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes[offset] === 0) break;
    const contentType = bip138DecodeContentType(bytes, offset);
    offset = contentType.next;
    const { value: length, next } = bip138ReadCompactSize(bytes, offset);
    offset = next;
    if (offset + length > bytes.length) fail("truncated");
    items.push({ type: contentType.type, bip: contentType.bip, params: contentType.params, content: bytes.slice(offset, offset + length) });
    offset += length;
  }
  if (items.length === 0) fail("empty-payload");
  return items;
}

export function bip138Encrypt(secret, nonce, plaintext) {
  if (!isBytes(secret) || secret.length !== 32) fail("descriptor");
  if (!isBytes(nonce) || nonce.length !== 12) fail("zero-nonce");
  if (nonce.every((byte) => byte === 0)) fail("zero-nonce");
  if (!isBytes(plaintext) || plaintext.length === 0) fail("empty-payload");
  return chacha20poly1305(secret, nonce).encrypt(plaintext);
}
export function bip138Decrypt(secret, nonce, ciphertext) {
  if (!isBytes(secret) || secret.length !== 32) return null;
  if (!isBytes(nonce) || nonce.length !== 12) return null;
  if (!isBytes(ciphertext) || ciphertext.length < 16) return null;
  try {
    return chacha20poly1305(secret, nonce).decrypt(ciphertext);
  } catch {
    return null;
  }
}

export function bip138EncodeBackup({ keys, payload, nonce, decoys = [], derivationPaths = [] } = {}) {
  if (!Array.isArray(keys)) fail("no-keys");
  const nums = hexToBytes(BIP138_NUMS_XONLY);
  const filtered = keys.filter((key) => !(isBytes(key) && equalBytes(key, nums)));
  const sorted = bip138SortKeys(filtered);
  if (!sorted.length) fail("no-keys");
  if (sorted.length > 255) fail("too-many");
  const paths = derivationPaths.filter((path) => !bip138CommonPath(path));
  const encodedPaths = bip138EncodeDerivationPaths(paths);
  const secret = bip138DecryptionSecret(sorted);
  const real = [];
  const decoyCopies = [];
  try {
    for (const entry of bip138IndividualSecrets(secret, sorted)) real.push(entry);
    for (const decoy of decoys) {
      if (!isBytes(decoy) || decoy.length !== 32) fail("descriptor");
      decoyCopies.push(decoy.slice());
    }
    const encodedSecrets = bip138EncodeIndividualSecrets([...real, ...decoyCopies]);
    const ciphertext = bip138Encrypt(secret, nonce, payload);
    return concatBytes([MAGIC, Uint8Array.of(BIP138_VERSION), encodedPaths, encodedSecrets, Uint8Array.of(BIP138_CHACHA20_POLY1305), nonce, bip138CompactSize(ciphertext.length), ciphertext]);
  } finally {
    secret.fill(0);
    for (const entry of real) entry.fill(0);
    for (const entry of decoyCopies) entry.fill(0);
    for (const key of sorted) key.fill(0);
  }
}
export function bip138ParseBackup(bytes) {
  if (!isBytes(bytes) || bytes.length < 6) fail("magic");
  for (let i = 0; i < 6; i++) if (bytes[i] !== MAGIC[i]) fail("magic");
  let offset = 6;
  if (offset >= bytes.length) fail("truncated");
  const version = bytes[offset++];
  if (version === 0) fail("bad-version");
  if (version > BIP138_VERSION) fail("unsupported-version");
  const paths = bip138DecodeDerivationPaths(bytes, offset);
  offset = paths.next;
  const secrets = bip138DecodeIndividualSecrets(bytes, offset);
  offset = secrets.next;
  if (offset >= bytes.length) fail("truncated");
  const encryption = bytes[offset++];
  if (encryption === 0) fail("bad-encryption");
  if (encryption !== BIP138_CHACHA20_POLY1305) fail("unsupported-encryption");
  if (offset + 12 > bytes.length) fail("truncated");
  const nonce = bytes.slice(offset, offset + 12);
  offset += 12;
  if (nonce.every((byte) => byte === 0)) fail("zero-nonce");
  const { value: length, next } = bip138ReadCompactSize(bytes, offset);
  offset = next;
  if (offset + length > bytes.length) fail("truncated");
  return { version, derivationPaths: paths.paths, secrets: secrets.secrets, encryption, nonce, ciphertext: bytes.slice(offset, offset + length) };
}
export function bip138DecryptBackup(parsed, key) {
  if (!parsed || !isBytes(key) || key.length !== 32) fail("wrong-key");
  const si = bip138TaggedHash("BIP138_INDIVIDUAL_SECRET", key);
  try {
    for (const entry of parsed.secrets) {
      const secret = new Uint8Array(32);
      for (let i = 0; i < 32; i++) secret[i] = entry[i] ^ si[i];
      const plaintext = bip138Decrypt(secret, parsed.nonce, parsed.ciphertext);
      secret.fill(0);
      if (plaintext) return plaintext;
    }
    fail("wrong-key");
  } finally {
    si.fill(0);
  }
}

export function bip138HasPrivateKey(text) {
  const source = String(text ?? "");
  for (const match of source.matchAll(/[1-9A-HJ-NP-Za-km-z]{50,}/g)) {
    let payload;
    try {
      payload = base58checkDecode(match[0]);
    } catch {
      continue;
    }
    try {
      if (payload.length === 78 && payload[45] === 0) return true;
      if ((payload.length === 33 || payload.length === 34) && (payload[0] === 0x80 || payload[0] === 0xef)) return true;
    } finally {
      payload.fill(0);
    }
  }
  return false;
}

function splitTopLevel(text) {
  const parts = [];
  let depth = 0, start = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === "(" || char === "{" || char === "[") depth++;
    else if (char === ")" || char === "}" || char === "]") {
      depth--;
      if (depth < 0) fail("descriptor");
    }
    if (depth === 0 && char === ",") {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  if (depth !== 0) fail("descriptor");
  parts.push(text.slice(start));
  return parts;
}

function recordKey(state, flags, x, kind, hasSteps) {
  state.records.push({
    x,
    kind,
    hasSteps,
    inMusig: Boolean(flags.inMusig),
    internal: Boolean(flags.internal),
    descriptor: state.descriptor,
    index: flags.internal ? null : state.count++,
  });
}

function walkKeyExpression(text, state, flags) {
  let value = text.trim();
  if (value.startsWith("musig(")) {
    let depth = 0, close = -1;
    for (let i = 5; i < value.length; i++) {
      if (value[i] === "(") depth++;
      else if (value[i] === ")") {
        depth--;
        if (depth === 0) { close = i; break; }
      }
    }
    if (close < 0) fail("descriptor");
    for (const participant of splitTopLevel(value.slice(6, close))) {
      if (participant.trim().startsWith("musig(")) fail("descriptor");
      walkKeyExpression(participant, state, { inMusig: true, internal: false });
    }
    return;
  }
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end < 0) fail("descriptor");
    value = value.slice(end + 1);
  }
  const slash = value.indexOf("/");
  const keyText = slash >= 0 ? value.slice(0, slash) : value;
  const hasSteps = slash >= 0 && slash + 1 < value.length;
  let x = null, kind = null;
  if (/^0[23][0-9a-fA-F]{64}$/.test(keyText) || /^04[0-9a-fA-F]{128}$/.test(keyText)) {
    x = hexToBytes(keyText).slice(1, 33);
    kind = "literal";
  } else if (/^[0-9a-fA-F]{64}$/.test(keyText)) {
    x = hexToBytes(keyText);
    kind = "literal";
  } else if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(keyText)) {
    let payload;
    try {
      payload = base58checkDecode(keyText);
    } catch {
      fail("descriptor");
    }
    try {
      if (payload.length === 78 && payload[45] === 0) fail("private-key");
      if (payload.length === 78 && (payload[45] === 2 || payload[45] === 3)) {
        x = payload.slice(46, 78);
        kind = "xpub";
      } else if ((payload.length === 33 || payload.length === 34) && (payload[0] === 0x80 || payload[0] === 0xef)) {
        fail("private-key");
      } else {
        fail("descriptor");
      }
    } finally {
      payload.fill(0);
    }
  } else {
    fail("descriptor");
  }
  recordKey(state, flags, x, kind, hasSteps);
}

function walkTree(text, state) {
  const value = text.trim();
  if (value.startsWith("{")) {
    if (!value.endsWith("}")) fail("descriptor");
    for (const part of splitTopLevel(value.slice(1, -1))) walkTree(part, state);
    return;
  }
  walkFragment(value, state);
}

function walkFragment(text, state) {
  let value = text.trim();
  const wrapper = value.match(/^[a-z]+:/);
  if (wrapper) value = value.slice(wrapper[0].length);
  const nameMatch = value.match(/^[a-z_][a-z0-9_]*/);
  if (!nameMatch) fail("descriptor");
  const name = nameMatch[0];
  if (value[name.length] !== "(") fail("descriptor");
  let depth = 0, close = -1;
  for (let i = name.length; i < value.length; i++) {
    if (value[i] === "(") depth++;
    else if (value[i] === ")") {
      depth--;
      if (depth === 0) { close = i; break; }
    }
  }
  if (close !== value.length - 1) fail("descriptor");
  const args = splitTopLevel(value.slice(name.length + 1, close));
  if (name === "pk" || name === "pkh" || name === "wpkh" || name === "combo" || name === "pk_k" || name === "pk_h" || name === "rawtr") {
    if (args.length !== 1) fail("descriptor");
    walkKeyExpression(args[0], state, { inMusig: false, internal: false });
    return;
  }
  if (name === "multi" || name === "sortedmulti" || name === "multi_a" || name === "sortedmulti_a") {
    if (args.length < 2 || !/^\d+$/.test(args[0].trim())) fail("descriptor");
    for (const arg of args.slice(1)) walkKeyExpression(arg, state, { inMusig: false, internal: false });
    return;
  }
  if (name === "tr") {
    if (args.length < 1) fail("descriptor");
    walkKeyExpression(args[0], state, { inMusig: false, internal: true });
    for (const arg of args.slice(1)) walkTree(arg, state);
    return;
  }
  if (name === "addr" || name === "raw") return;
  if (name === "musig") fail("descriptor");
  for (const arg of args) if (arg.includes("(")) walkFragment(arg, state);
}

export function bip138RecipientKeys(descriptors) {
  if (!Array.isArray(descriptors)) fail("descriptor");
  const records = [];
  descriptors.forEach((descriptor, index) => {
    let text = String(descriptor ?? "").trim();
    const hash = text.lastIndexOf("#");
    if (hash >= 0) text = text.slice(0, hash);
    if (!text || /\s/.test(text)) fail("descriptor");
    walkFragment(text, { descriptor: index, count: 0, records });
  });
  const exposed = new Set();
  for (const record of records) {
    if (record.inMusig) continue;
    if (record.kind === "literal" || (record.kind === "xpub" && !record.hasSteps)) exposed.add(bytesToHex(record.x));
  }
  const keys = [], exclusions = [];
  for (const record of records) {
    const hex = bytesToHex(record.x);
    let reason = null;
    if (record.kind === "literal") reason = hex === BIP138_NUMS_XONLY ? "nums" : "literal";
    else if (!record.inMusig && !record.hasSteps) reason = "exposed";
    else if (hex === BIP138_NUMS_XONLY) reason = "nums";
    else if (exposed.has(hex)) reason = "exposed";
    if (reason) exclusions.push({ descriptor: record.descriptor, index: record.index, internal: record.internal, reason });
    else keys.push(record.x);
  }
  return { keys: bip138SortKeys(keys), exclusions };
}

export function bip138SecretBucket(count) {
  if (!Number.isSafeInteger(count) || count < 1) fail("no-keys");
  if (count > 255) fail("too-many");
  let bucket = 5;
  while (bucket < count) bucket *= 2;
  return Math.min(bucket, 255);
}

export function bip138CreateDescriptorBackup(descriptor) {
  const text = String(descriptor ?? "").trim();
  if (!text) fail("descriptor");
  if (bip138HasPrivateKey(text)) fail("private-key");
  const { keys, exclusions } = bip138RecipientKeys([text]);
  if (!keys.length) return { status: "no-keys", exclusions };
  const content = textEncoder.encode(text);
  const payload = bip138EncodePayload([{ contentType: Uint8Array.of(1, 1, 0x7c), content }]);
  const secret = bip138DecryptionSecret(keys);
  const real = [];
  const decoys = [];
  try {
    let nonce = null;
    for (let counter = 0; counter <= 255; counter++) {
      const candidate = bip138TaggedHash("ENTROPYLAB_BIP138_NONCE", concatBytes([secret, payload, Uint8Array.of(counter)])).slice(0, 12);
      if (!candidate.every((byte) => byte === 0)) { nonce = candidate; break; }
    }
    if (!nonce) fail("verify");
    const target = bip138SecretBucket(keys.length);
    for (const entry of bip138IndividualSecrets(secret, keys)) real.push(entry);
    for (let j = 0; real.length + decoys.length < target; j++) {
      const candidate = bip138TaggedHash("ENTROPYLAB_BIP138_DECOY", concatBytes([secret, be32(j)]));
      if (candidate.every((byte) => byte === 0)) continue;
      if (real.some((entry) => equalBytes(entry, candidate))) continue;
      if (decoys.some((entry) => equalBytes(entry, candidate))) continue;
      decoys.push(candidate);
    }
    const bytes = bip138EncodeBackup({ keys, payload, nonce, decoys, derivationPaths: [] });
    const parsed = bip138ParseBackup(bytes);
    if (parsed.derivationPaths.length !== 0) fail("verify");
    if (parsed.secrets.length !== target) fail("verify");
    for (const key of keys) {
      const plaintext = bip138DecryptBackup(parsed, key);
      try {
        const items = bip138DecodePayload(plaintext);
        if (items.length !== 1) fail("verify");
        if (items[0].type !== 1 || items[0].bip !== 380) fail("verify");
        if (!equalBytes(items[0].content, content)) fail("verify");
      } finally {
        plaintext.fill(0);
      }
    }
    return { status: "ok", bytes, exclusions };
  } catch {
    fail("verify");
  } finally {
    secret.fill(0);
    for (const entry of real) entry.fill(0);
    for (const entry of decoys) entry.fill(0);
    for (const key of keys) key.fill(0);
  }
}

export function bip138OpenDescriptorBackup(bytes, key) {
  const parsed = bip138ParseBackup(bytes);
  const payload = bip138DecryptBackup(parsed, key);
  try {
    let items;
    try {
      items = bip138DecodePayload(payload);
    } catch {
      fail("damaged");
    }
    const item = items.find((entry) => entry.type === 1 && entry.bip === 380);
    if (!item) fail("unsupported-content");
    let text;
    try {
      text = textDecoder.decode(item.content);
    } catch {
      fail("damaged");
    }
    if (bip138HasPrivateKey(text)) fail("private-key");
    let result = text;
    if (text.trimStart().startsWith("{")) {
      let doc;
      try {
        doc = JSON.parse(text);
      } catch {
        fail("damaged");
      }
      if (!bip138ValidDescriptorDocument(doc)) fail("damaged");
      if (doc.descriptor_sets.length !== 1 || doc.descriptor_sets[0].change_descriptor !== undefined) fail("unsupported-content");
      result = doc.descriptor_sets[0].descriptor;
    }
    if (!result.trim()) fail("damaged");
    // Anyone who holds one of a wallet's xpubs can write a backup that opens
    // with it, so an opened backup proves only that its writer knew that key.
    // At the least its descriptor must name the key that opened it (Claude,
    // from the Kaitiaki review, 11-01).
    if (!bip138DescriptorNamesKey(result, key)) fail("wrong-key");
    return { descriptor: result };
  } finally {
    payload.fill(0);
  }
}

// True when the descriptor's text contains the 32-byte x-only key, at any
// place, as an xpub or a literal key; false when it cannot be read.
export function bip138DescriptorNamesKey(descriptor, key) {
  if (!isBytes(key) || key.length !== 32) return false;
  try {
    let text = String(descriptor ?? "").trim();
    const hash = text.lastIndexOf("#");
    if (hash >= 0) text = text.slice(0, hash);
    if (!text || /\s/.test(text)) return false;
    const records = [];
    walkFragment(text, { descriptor: 0, count: 0, records });
    return records.some((record) => isBytes(record.x) && equalBytes(record.x, key));
  } catch {
    return false;
  }
}

export function bip138KeyFromXpubText(text) {
  let value = String(text ?? "").trim();
  if (!value) return { status: "invalid" };
  if (/\s/.test(value)) return { status: "private-key" };
  if (/^[0-9a-fA-F]{64}$/.test(value)) return { status: "private-key" };
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end < 0) return { status: "invalid" };
    value = value.slice(end + 1);
  }
  const slash = value.indexOf("/");
  if (slash >= 0) value = value.slice(0, slash);
  if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(value)) return { status: "invalid" };
  let payload;
  try {
    payload = base58checkDecode(value);
  } catch {
    return { status: "invalid" };
  }
  try {
    if (payload.length === 78) {
      if (payload[45] === 0) return { status: "private-key" };
      if (payload[45] === 2 || payload[45] === 3) return { status: "ok", key: payload.slice(46, 78) };
      return { status: "invalid" };
    }
    if ((payload.length === 33 || payload.length === 34) && (payload[0] === 0x80 || payload[0] === 0xef)) return { status: "private-key" };
    return { status: "invalid" };
  } finally {
    payload.fill(0);
  }
}

export function bip138LooksLikeText(text) {
  return String(text ?? "").replace(/\s+/g, "").startsWith(BIP138_TEXT_PREFIX);
}

export function bip138BytesFromText(text) {
  const compact = String(text ?? "").replace(/\s+/g, "");
  if (!compact || compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) fail("base64");
  let binary;
  try {
    binary = atob(compact);
  } catch {
    fail("base64");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  if (bytes.length < 6) fail("magic");
  for (let i = 0; i < 6; i++) if (bytes[i] !== MAGIC[i]) fail("magic");
  return bytes;
}

export function bip138BytesFromFile(raw) {
  if (!isBytes(raw)) fail("magic");
  if (raw.length > BIP138_MAX_FILE_BYTES) fail("too-large");
  if (raw.length >= 6) {
    let magic = true;
    for (let i = 0; i < 6; i++) if (raw[i] !== MAGIC[i]) { magic = false; break; }
    if (magic) return raw.slice();
  }
  let text;
  try {
    text = textDecoder.decode(raw);
  } catch {
    fail("magic");
  }
  if (text.replace(/\s+/g, "").startsWith(BIP138_TEXT_PREFIX)) return bip138BytesFromText(text);
  fail("magic");
}

export function bip138ToBase64(bytes) {
  if (!isBytes(bytes)) fail("base64");
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function validRange(value) {
  return Array.isArray(value) && value.length === 2 && value.every((entry) => Number.isSafeInteger(entry) && entry >= 0 && entry <= 2147483647) && value[0] <= value[1];
}
function validMetadata(value) {
  if (value.archived !== undefined && typeof value.archived !== "boolean") return false;
  if (value.range !== undefined && !validRange(value.range)) return false;
  if (value.birth_time !== undefined && !(Number.isSafeInteger(value.birth_time) && value.birth_time >= 0)) return false;
  return true;
}

export function bip138ValidDescriptorDocument(doc) {
  if (!isPlainObject(doc)) return false;
  if (doc.version !== 1) return false;
  if (!Array.isArray(doc.descriptor_sets) || doc.descriptor_sets.length === 0) return false;
  for (const set of doc.descriptor_sets) {
    if (!isPlainObject(set)) return false;
    if (typeof set.descriptor !== "string" || !set.descriptor) return false;
    if (set.change_descriptor !== undefined) {
      if (typeof set.change_descriptor !== "string" || !set.change_descriptor) return false;
      if (set.descriptor.includes("<")) return false;
    }
    if (!validMetadata(set)) return false;
  }
  return true;
}

const POLICY_KEY = /^(\[[0-9a-fA-F]{8}(\/\d+['hH]?)*\])?([1-9A-HJ-NP-Za-km-z]+)$/;
function validPolicyKey(text) {
  if (typeof text !== "string") return false;
  const match = text.match(POLICY_KEY);
  if (!match) return false;
  let payload;
  try {
    payload = base58checkDecode(match[3]);
  } catch {
    return false;
  }
  try {
    return payload.length === 78 && (payload[45] === 2 || payload[45] === 3);
  } finally {
    payload.fill(0);
  }
}
function validPolicy(policy) {
  if (!isPlainObject(policy)) return false;
  if (!Array.isArray(policy.keys) || policy.keys.length === 0) return false;
  if (!policy.keys.every(validPolicyKey)) return false;
  if (typeof policy.policy !== "string" || !policy.policy) return false;
  return validMetadata(policy);
}

export function bip138ValidPolicyDocument(doc) {
  if (!isPlainObject(doc)) return false;
  if (doc.policy_sets !== undefined) {
    if (doc.version !== 1) return false;
    if (!Array.isArray(doc.policy_sets) || doc.policy_sets.length === 0) return false;
    return doc.policy_sets.every(validPolicy);
  }
  if (doc.policy !== undefined) return validPolicy(doc);
  return false;
}
