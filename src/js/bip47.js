// BIP-47 reusable payment codes (version 1) for EntropyLab.
// Deterministic only: same inputs → same outputs. No entropy is invented.
// Curve ops go through the libsecp256k1 WASM facade (./secp256k1.js),
// hashes through the bitcoin_hashes WASM facade (./hashes.js), BIP32 through
// the rust-bitcoin WASM facade (./hdkey.js), Base58Check through ./base58.js,
// and transactions through ./tx.js.
//
// BIP-47 deliberately has no hashed-ECDH helper here: the shared secret is
// SHA-256 of the ECDH point's raw x-coordinate (no parity byte), and the
// notification mask is HMAC-SHA-512(key=outpoint, message=x(S)) — the
// argument order the BIP's own test vectors settle (its prose is
// inconsistent between the sender and receiver steps).
//
// BigInts cannot be wiped (same limit as bip352.js): every Uint8Array this
// module owns is filled with zeros by its caller; the scalar BigInts and the
// immutable point wrappers they produce stay GC-managed.
import { sha256, hmacSha512 } from "./hashes.js";
import { secp256k1 } from "./secp256k1.js";
import { HDKey, HARDENED_OFFSET } from "./hdkey.js";
import { base58checkEncode, base58checkDecode } from "./base58.js";
import { p2pkhScript, addressFromScript } from "./addresses.js";
import { parseRawTx, scriptPushes } from "./tx.js";

export const BIP47_PURPOSE = 47;
export const PAYMENT_CODE_VERSION_BYTE = 0x47;
export const PAYMENT_CODE_VERSION = 0x01;
export const PAYMENT_CODE_PAYLOAD_LENGTH = 80; // payload, after the 0x47 byte
export const PAIR_ROW_COUNT = 10;

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Point = secp256k1.Point;

const hexToBytes = (hex) => {
  if (typeof hex !== "string" || hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const bytesToBig = (bytes) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};
const bigToBytes32 = (value) => {
  if (value < 0n || value >= (1n << 256n)) throw new Error("Scalar does not fit in 32 bytes.");
  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  return bytes;
};
const equalBytes = (a, b) => {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

const isValidTweak = (bytes) => {
  const value = bytesToBig(bytes);
  return value > 0n && value < ORDER;
};

// The account node of a private root: m/47'/coin'/0'. BIP-47 never shares
// material with BIP-352's m/352' paths; this derives its own subtree only.
export function bip47AccountPath(coinType) {
  return `m/${BIP47_PURPOSE}'/${coinType}'/0'`;
}
export function bip47AccountNode(root, coinType = 0) {
  if (!root || !root.privateKey) throw new Error("Watch-only roots cannot derive BIP-47's hardened account path.");
  if (!Number.isInteger(coinType) || coinType < 0 || coinType > 0x7fffffff) throw new Error("coin_type is out of range.");
  const node = root.derive(bip47AccountPath(coinType));
  if (!node.privateKey) throw new Error("BIP-47's account node is missing private material.");
  return node;
}

// The 80-byte payload: version, features, sign byte || x, chain code,
// thirteen zero bytes. Base58Check with version byte 0x47 (always "PM8T…";
// there is no testnet prefix and no network field).
export function bip47Payload(publicKey, chainCode, features = 0) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 33) throw new Error("Payment code public key must be a compressed 33-byte point.");
  try { Point.fromBytes(publicKey); } catch { throw new Error("Payment code public key is not a secp256k1 point."); }
  if (!(chainCode instanceof Uint8Array) || chainCode.length !== 32) throw new Error("Payment code chain code must be 32 bytes.");
  if (!Number.isInteger(features) || features < 0 || features > 255) throw new Error("Payment code features byte out of range.");
  const payload = new Uint8Array(PAYMENT_CODE_PAYLOAD_LENGTH);
  payload[0] = PAYMENT_CODE_VERSION;
  payload[1] = features;
  payload.set(publicKey, 2);
  payload.set(chainCode, 35);
  return payload;
}
export function encodePaymentCode(publicKey, chainCode, features = 0) {
  const payload = bip47Payload(publicKey, chainCode, features);
  const full = new Uint8Array(1 + PAYMENT_CODE_PAYLOAD_LENGTH);
  full[0] = PAYMENT_CODE_VERSION_BYTE;
  full.set(payload, 1);
  return base58checkEncode(full);
}

// Full v1 parse of an 80-byte payload. Warns on non-zero feature bits and
// non-zero reserved bytes (shown, never acted on); rejects anything that is
// not a compressed on-curve point.
export function decodePaymentCodePayload(payload) {
  if (!(payload instanceof Uint8Array) || payload.length !== PAYMENT_CODE_PAYLOAD_LENGTH) {
    throw new Error("A BIP-47 payment code holds an 80-byte payload.");
  }
  const version = payload[0];
  if (version !== PAYMENT_CODE_VERSION) {
    // Another version (v2/v3 live in OBPP RFCs, not BIP-47): report and stop.
    return { version, supported: false };
  }
  const features = payload[1];
  const sign = payload[2];
  const x = payload.slice(3, 35);
  const chainCode = payload.slice(35, 67);
  const reserved = payload.slice(67);
  if (sign !== 0x02 && sign !== 0x03) throw new Error("Payment code sign byte must be 0x02 or 0x03 (a compressed SEC key).");
  const publicKey = new Uint8Array(33);
  publicKey[0] = sign;
  publicKey.set(x, 1);
  try { Point.fromBytes(publicKey); } catch {
    throw new Error("Payment code x-coordinate is not on the secp256k1 curve.");
  }
  const warnings = [];
  if (features !== 0) warnings.push(`0x${features.toString(16).padStart(2, "0")} feature bits are set (bit 0 = Bitmessage); shown only, never used by this card.`);
  const reservedOffsets = [...reserved].map((byte, index) => (byte ? 67 + index : -1)).filter((offset) => offset >= 0);
  if (reservedOffsets.length) warnings.push(`Reserved byte${reservedOffsets.length === 1 ? "" : "s"} ${reservedOffsets.join(", ")} are non-zero; shown only.`);
  return { version: PAYMENT_CODE_VERSION, supported: true, features, sign, x, chainCode, publicKey, reserved: reservedOffsets, warnings };
}

// Checksum, version byte 0x47 and 80-byte payload are mandatory; the string
// cannot claim a network, and this card never pretends to detect one.
export function decodePaymentCode(text) {
  if (typeof text !== "string" || !text.trim()) throw new Error("Paste a BIP-47 payment code.");
  let decoded;
  try {
    decoded = base58checkDecode(text.trim());
  } catch {
    throw new Error("Not a valid Base58Check payment code.");
  }
  if (decoded[0] !== PAYMENT_CODE_VERSION_BYTE) throw new Error("Payment codes always use Base58Check version byte 0x47.");
  if (decoded.length !== 1 + PAYMENT_CODE_PAYLOAD_LENGTH) throw new Error("A BIP-47 payment code holds an 80-byte payload.");
  return decodePaymentCodePayload(decoded.slice(1));
}

// A decoded code as a public-only BIP32 node (depth is nominal; only
// non-hardened child derivation matters). Child 0 is the notification key.
export function paymentCodePublicNode(publicKey, chainCode) {
  return new HDKey({ depth: 3, index: 0, parentFingerprint: 0, chainCode, publicKey });
}
export function bip47ChildPublic(publicKey, chainCode, index) {
  const node = paymentCodePublicNode(publicKey, chainCode);
  try { return node.deriveChild(index).publicKey; }
  finally { node.wipePrivateData(); } // public-only: a no-op guard
}
export function bip47NotificationAddress(publicChild0, network) {
  return addressFromScript(p2pkhScript(publicChild0), network);
}

// The shared tweak: S = a·B_i (send) or b_i·A (receive), s = SHA256(x(S)).
// x(S) is the raw x-coordinate — never a parity-prefixed point, never a
// hashed ECDH helper.
const sharedSecretX = (scalarBig, otherPublic) => {
  const point = Point.fromBytes(otherPublic).multiply(scalarBig);
  return point.toBytes(true).slice(1);
};
const tweakFromX = (x) => sha256(x);
export function bip47SharedX(privateScalar, otherPublic) {
  if (!(privateScalar instanceof Uint8Array) || privateScalar.length !== 32) throw new Error("Shared-secret scalar must be 32 bytes.");
  const big = bytesToBig(privateScalar);
  if (big === 0n || big >= ORDER) throw new Error("Shared-secret scalar is out of the secp256k1 range.");
  return sharedSecretX(big, otherPublic);
}

// One pair row at index i, from the sender side: address = P2PKH(B_i + s·G).
// Returns null when the row must be skipped (s invalid, or the tweak point
// at infinity) — callers list the skipped index and never renumber.
export function bip47SendRow(ownNotificationPriv, counterpartyPublic, counterpartyChain, index, network, { checkTweak = isValidTweak } = {}) {
  if (!(ownNotificationPriv instanceof Uint8Array) || ownNotificationPriv.length !== 32) throw new Error("Pair send needs the 32-byte notification private key.");
  const a = bytesToBig(ownNotificationPriv);
  if (a === 0n || a >= ORDER) throw new Error("Notification private key is out of the secp256k1 range.");
  const biPublic = bip47ChildPublic(counterpartyPublic, counterpartyChain, index);
  const sBytes = tweakFromX(sharedSecretX(a, biPublic));
  if (!checkTweak(sBytes)) return null;
  const s = bytesToBig(sBytes);
  if (s === 0n || s >= ORDER) return null;
  let tweaked;
  try { tweaked = Point.fromBytes(biPublic).add(Point.BASE.multiply(s)); } catch { return null; }
  const publicRow = tweaked.toBytes(true);
  return { index, publicKey: publicRow, address: bip47NotificationAddress(publicRow, network) };
}

// One pair row at index i, from the receiver side: private key
// b'_i = (b_i + s) mod n, public key B_i + s·G. Send rows never get this.
export function bip47ReceiveRow(ownAccountNode, counterpartyPublic, counterpartyChain, index, network, { checkTweak = isValidTweak } = {}) {
  if (!ownAccountNode || !ownAccountNode.privateKey) throw new Error("Pair receive needs the BIP-47 account node with private material.");
  const childNode = ownAccountNode.deriveChild(index);
  let childPriv = null;
  try {
    childPriv = childNode.privateKey;
    const bi = bytesToBig(childPriv);
    const theirA = bip47ChildPublic(counterpartyPublic, counterpartyChain, 0);
    const sBytes = tweakFromX(sharedSecretX(bi, theirA));
    if (!checkTweak(sBytes)) return null;
    const s = bytesToBig(sBytes);
    if (s === 0n || s >= ORDER) return null;
    const full = (bi + s) % ORDER;
    if (full === 0n) return null;
    const privateRow = bigToBytes32(full); // BigInt residue: not wipeable
    const publicRow = secp256k1.getPublicKey(privateRow, true);
    return { index, publicKey: publicRow, privateKey: privateRow, address: bip47NotificationAddress(publicRow, network) };
  } finally {
    if (childPriv) childPriv.fill(0);
    childNode.wipePrivateData();
  }
}

// From a start index, collect `count` rows, skipping invalid indices
// (reported, never renumbered). Public derivation stays below 2^31.
export function bip47PairRows(direction, options, start, count, network) {
  if (!Number.isInteger(start) || start < 0 || start >= HARDENED_OFFSET) throw new Error("Pair start index must be a non-hardened BIP32 index.");
  if (!Number.isInteger(count) || count < 1 || count > 100) throw new Error("Pair rows count must be between 1 and 100.");
  const run = direction === "send" ? bip47SendRow : direction === "receive" ? bip47ReceiveRow : null;
  if (!run) throw new Error("Pair direction must be send or receive.");
  const rows = [], skipped = [];
  let index = start;
  while (rows.length < count) {
    if (index >= HARDENED_OFFSET) throw new Error("Ran out of non-hardened pair indices.");
    const row = run(options.own, options.publicKey, options.chainCode, index, network, { checkTweak: options.checkTweak });
    if (row) rows.push(row);
    else skipped.push(index);
    index += 1;
  }
  return { rows, skipped };
}

// The HMAC mask. The key is the 36-byte outpoint, the message x(S) — settled
// by the BIP's own notification vector.
export function bip47Mask(x, outpoint) {
  if (!(outpoint instanceof Uint8Array) || outpoint.length !== 36) throw new Error("Notification outpoint must be 36 bytes.");
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error("Shared-secret x must be 32 bytes.");
  return hmacSha512(outpoint, x);
}
export function bip47BlindPayload(payload, mask) {
  if (!(payload instanceof Uint8Array) || payload.length !== PAYMENT_CODE_PAYLOAD_LENGTH) throw new Error("Notification payload must be 80 bytes.");
  if (!(mask instanceof Uint8Array) || mask.length !== 64) throw new Error("Notification mask must be 64 bytes.");
  const out = payload.slice();
  for (let i = 0; i < 32; i++) {
    out[3 + i] ^= mask[i];
    out[35 + i] ^= mask[32 + i];
  }
  return out;
}
// Send side of the mask: the designated input's private key against the
// counterparty's child-0 public key.
export function bip47BlindNotification(payload, designatedPriv, counterpartyPublic0, outpoint) {
  if (!(designatedPriv instanceof Uint8Array) || designatedPriv.length !== 32) throw new Error("Designated-input private key must be 32 bytes.");
  const a = bytesToBig(designatedPriv);
  if (a === 0n || a >= ORDER) throw new Error("Designated-input private key is out of the secp256k1 range.");
  return bip47BlindPayload(payload, bip47Mask(sharedSecretX(a, counterpartyPublic0), outpoint));
}

// "txid:vout" in display order -> the 36 internal bytes (internal txid byte
// order, then vout little-endian), exactly as serialized inside a tx.
export function bip47OutpointFromDisplay(text) {
  if (typeof text !== "string") throw new Error("Enter the designated input's outpoint as txid:vout.");
  const match = /^([0-9a-fA-F]{64}):(\d+)$/.exec(text.trim());
  if (!match) throw new Error("Enter the designated input's outpoint as txid:vout (64 hex characters, a colon, and a decimal index).");
  const vout = Number(match[2]);
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) throw new Error("Outpoint vout out of range.");
  const out = new Uint8Array(36);
  const txid = hexToBytes(match[1]);
  for (let i = 0; i < 32; i++) out[i] = txid[31 - i];
  new DataView(out.buffer).setUint32(32, vout, true);
  return out;
}
export function bip47InputOutpoint(input) {
  const out = new Uint8Array(36);
  out.set(input.txid, 0);
  new DataView(out.buffer).setUint32(32, input.vout, true);
  return out;
}

// A DER signature (with or without the sighash byte), enough to tell a
// P2PKH unlock from multisig — full strictness is not needed to find the key.
const looksLikeDerSig = (bytes) => {
  if (!bytes || bytes.length < 9 || bytes[0] !== 0x30) return false;
  const body = bytes[1];
  if (body >= 0x80) return false;
  return 2 + body + 1 === bytes.length || 2 + body === bytes.length;
};
const pointFrom33or65 = (bytes) => {
  if (!bytes) return null;
  const shaped = (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) || (bytes.length === 65 && bytes[0] === 4);
  if (!shaped) return null;
  try { return Point.fromBytes(bytes); } catch { return null; }
};

// The designated input is the FIRST input that exposes a public key. BIP-47
// reads keys from P2PKH scriptSigs; the two witness forms are common
// practice but not in the BIP text. Anything unrecognized (P2PK, multisig,
// anything else) stops the scan at that input — never skip ahead.
export function extractDesignatedPubKey(tx) {
  for (const [inputIndex, input] of (tx.inputs || []).entries()) {
    const pushes = scriptPushes(input.scriptSig || new Uint8Array());
    const witness = input.witness || [];
    if (pushes.length === 2 && looksLikeDerSig(pushes[0]) && pointFrom33or65(pushes[1])) {
      return { status: "found", inputIndex, kind: "p2pkh", publicKey: pushes[1] };
    }
    if (pushes.length === 0 && witness.length === 2 && pointFrom33or65(witness[1]) && witness[1].length === 33) {
      return { status: "found", inputIndex, kind: "p2wpkh", publicKey: witness[1] };
    }
    if (
      pushes.length === 1 && pushes[0].length === 22 && pushes[0][0] === 0x00 && pushes[0][1] === 0x14 &&
      witness.length === 2 && pointFrom33or65(witness[1]) && witness[1].length === 33
    ) {
      return { status: "found", inputIndex, kind: "p2sh-p2wpkh", publicKey: witness[1] };
    }
    return { status: "manual-needed", inputIndex };
  }
  return { status: "manual-needed", inputIndex: null };
}

// The notification payload: the OP_RETURN output carrying one 80-byte push.
export function bip47NotificationPayload(tx) {
  for (const output of tx.outputs || []) {
    if (!(output.script instanceof Uint8Array) || output.script[0] !== 0x6a) continue;
    for (const push of scriptPushes(output.script)) if (push.length === PAYMENT_CODE_PAYLOAD_LENGTH) return push;
  }
  return null;
}

// Decode-only: parse the tx, find the 80-byte OP_RETURN payload, unblind it
// with our notification key, and validate the recovered payment code. Never
// builds, signs, or broadcasts anything.
export function bip47DecodeNotificationTx(txHex, notificationPriv, { designatedPub = null } = {}) {
  const bytes = typeof txHex === "string" ? hexToBytes(txHex.trim()) : txHex;
  const tx = parseRawTx(bytes);
  const payload = bip47NotificationPayload(tx);
  if (!payload) return { status: "no-payload" };
  if (payload[0] !== PAYMENT_CODE_VERSION) return { status: "unsupported-version", version: payload[0] };
  if (!(notificationPriv instanceof Uint8Array) || notificationPriv.length !== 32) throw new Error("Notification-tx decode needs the 32-byte notification private key.");
  const b = bytesToBig(notificationPriv);
  if (b === 0n || b >= ORDER) throw new Error("Notification private key is out of the secp256k1 range.");
  const designated = extractDesignatedPubKey(tx);
  let inputIndex, kind, publicKey;
  if (designated.status === "found") {
    ({ inputIndex, kind } = designated);
    publicKey = designated.publicKey;
  } else {
    inputIndex = designated.inputIndex;
    kind = "manual";
    if (designatedPub === null) return { status: "manual-needed", inputIndex };
    publicKey = typeof designatedPub === "string" ? hexToBytes(designatedPub.trim()) : designatedPub;
    if (!pointFrom33or65(publicKey)) return { status: "manual-invalid", inputIndex };
  }
  const input = tx.inputs[inputIndex];
  const outpoint = bip47InputOutpoint(input);
  const mask = bip47Mask(sharedSecretX(b, publicKey), outpoint); // The HMAC key is the outpoint; the message is x(S).
  const ownPub = secp256k1.getPublicKey(notificationPriv, true);
  const ownScript = p2pkhScript(ownPub);
  // A wrong key can still produce a valid-looking code; only this flag
  // distinguishes "meant for us" from garbage that happened to parse.
  const paysOurNotification = tx.outputs.some((output) => equalBytes(output.script, ownScript));
  const clear = bip47BlindPayload(payload, mask);
  let decoded = null;
  try { decoded = decodePaymentCodePayload(clear); } catch { /* wrong key: garbage payload */ }
  clear.fill(0);
  return {
    status: decoded ? "ok" : "undecodable",
    inputIndex,
    kind,
    publicKeyHex: bytesToHex(publicKey),
    designatedDisplayTxid: bytesToHex(input.txid),
    designatedVout: input.vout,
    paysOurNotification,
    code: decoded ? encodePaymentCode(decoded.publicKey, decoded.chainCode, decoded.features) : null,
    decoded,
  };
}

export { hexToBytes, bytesToHex, equalBytes };
